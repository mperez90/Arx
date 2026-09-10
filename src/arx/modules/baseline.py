"""Arx · baseline — aprendizaje de "lo normal" (comando `arx learn`).

Toma instantáneas del comportamiento del host y las funde en una línea base:
  · CONJUNTOS (procesos, puertos en escucha, servicios, usuarios conectados):
    se acumula lo visto → el conjunto "conocido", con frecuencia.
  · MEDIDORES (carga, memoria, disco, conexiones): min/max/media → rango normal.

Conservador: aprender > bloquear durante la ventana. Integridad de arranque: se
fija la huella de ficheros críticos (authorized_keys, sudoers, passwd, set SUID)
en el primer muestreo y se avisa si cambian mientras se aprende — para no aprender
a un intruso como "normal". `compare()` es la función que usa `guard` para detectar
desvíos contra esta base.
"""
from __future__ import annotations

import hashlib
import time
from datetime import datetime, timezone

from arx import config
from arx.modules import recon

# Severidad del desvío según qué conjunto introduce algo nuevo.
KIND_SEV = {
    "listen_ports": "high",
    "login_users": "high",
    "services": "med",
    "processes": "med",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _baseline_path():
    return config.state_dir() / "baseline.json"


# ── instantánea de comportamiento ────────────────────────────────────────────
def _processes() -> list[str]:
    for args in (["ps", "-eo", "comm="], ["ps", "-axo", "comm="], ["ps", "axo", "comm="]):
        out = recon._run(args)
        if out:
            return sorted({l.strip().rsplit("/", 1)[-1] for l in out.splitlines() if l.strip()})
    return []


def _login_users() -> list[str]:
    out = recon._run(["who"])
    if not out:
        return []
    users = set()
    for line in out.splitlines():
        f = line.split()
        if not f:
            continue
        src = ""
        if line.rstrip().endswith(")") and "(" in line:
            src = "@" + line[line.rfind("(") + 1 : line.rfind(")")]
        users.add(f[0] + src)
    return sorted(users)


def _gauges() -> dict:
    import os
    import shutil

    g: dict = {}
    try:
        g["load1"] = round(os.getloadavg()[0], 2)
    except (OSError, AttributeError):
        pass
    try:
        du = shutil.disk_usage("/")
        g["disk_used_pct"] = round(du.used / du.total * 100, 1)
    except OSError:
        pass
    mem = recon._read("/proc/meminfo")
    if mem:
        total = avail = None
        for line in mem.splitlines():
            if line.startswith("MemTotal"):
                total = int(line.split()[1])
            elif line.startswith("MemAvailable"):
                avail = int(line.split()[1])
        if total and avail is not None:
            g["mem_used_pct"] = round((total - avail) / total * 100, 1)
    est = recon._run(["ss", "-tanH", "state", "established"])
    if est is not None:
        g["conn_count"] = float(len([l for l in est.splitlines() if l.strip()]))
    return g


def snapshot() -> dict:
    ports = [f"{p['proto']} {p['local']}" for p in recon.collect_ports()]
    return {
        "at": _now(),
        "sets": {
            "processes": _processes(),
            "listen_ports": sorted(ports),
            "services": recon.collect_services() or [],
            "login_users": _login_users(),
        },
        "gauges": _gauges(),
    }


# ── integridad de arranque ───────────────────────────────────────────────────
def integrity_fingerprint() -> dict:
    fp: dict = {}
    for name, path in [
        ("authorized_keys_root", "/root/.ssh/authorized_keys"),
        ("sudoers", "/etc/sudoers"),
        ("passwd", "/etc/passwd"),
    ]:
        data = recon._read(path)
        if data is not None:
            fp[name] = hashlib.sha256(data.encode()).hexdigest()[:16]
    users = recon.collect_users()
    if users.get("suid_binaries") is not None:
        joined = "\n".join(sorted(users["suid_binaries"]))
        fp["suid_set"] = hashlib.sha256(joined.encode()).hexdigest()[:16]
    return fp


# ── modelo de la base ────────────────────────────────────────────────────────
def new_baseline() -> dict:
    return {
        "meta": {"created": _now(), "updated": _now(), "samples": 0, "sealed": False},
        "integrity": {},
        "integrity_alerts": [],
        "sets": {},
        "gauges": {},
    }


def fold(baseline: dict, snap: dict, check_integrity: bool = True) -> dict:
    baseline["meta"]["samples"] += 1
    baseline["meta"]["updated"] = _now()
    for key, observed in snap["sets"].items():
        d = baseline["sets"].setdefault(key, {})
        for item in observed:
            d[item] = d.get(item, 0) + 1
    for key, val in snap["gauges"].items():
        g = baseline["gauges"].setdefault(key, {"min": val, "max": val, "sum": 0.0, "n": 0})
        g["min"] = min(g["min"], val)
        g["max"] = max(g["max"], val)
        g["sum"] += val
        g["n"] += 1
    fp = integrity_fingerprint()
    if not baseline.get("integrity"):
        baseline["integrity"] = fp
    elif check_integrity and fp != baseline["integrity"]:
        changed = [k for k in set(fp) | set(baseline["integrity"]) if fp.get(k) != baseline["integrity"].get(k)]
        baseline.setdefault("integrity_alerts", []).append({"at": _now(), "changed": changed})
    return baseline


def _target_for(key: str, item: str) -> dict:
    """Objetivo estructurado del hallazgo, para que la respuesta pueda actuar sobre él."""
    if key == "listen_ports":  # "tcp 0.0.0.0:4444"
        try:
            proto, local = item.split(" ", 1)
            host, port = local.rsplit(":", 1)
            return {"proto": proto, "addr": host, "port": int(port)}
        except (ValueError, TypeError):
            return {}
    if key == "processes":
        return {"process": item}
    if key == "login_users":
        return {"user": item}
    return {}


def compare(baseline: dict, snap: dict) -> list[dict]:
    """Desvíos de una instantánea contra la base sellada. Lo usa `guard`."""
    anomalies: list[dict] = []
    sets = baseline.get("sets", {})
    for key, observed in snap["sets"].items():
        known = set(sets.get(key, {}))
        for item in observed:
            if item not in known:
                anomalies.append(
                    {
                        "sev": KIND_SEV.get(key, "med"),
                        "kind": key,
                        "detail": f"nuevo en {key}: {item}",
                        "why": f"no aparece en la línea base de {key} ({len(known)} conocidos)",
                        "target": _target_for(key, item),
                    }
                )
    gauges = baseline.get("gauges", {})
    for key, val in snap["gauges"].items():
        g = gauges.get(key)
        if g and g["n"] >= 3:
            span = max(g["max"] - g["min"], 1e-9)
            if val > g["max"] + span * 0.5:
                anomalies.append(
                    {
                        "sev": "low",
                        "kind": "gauge",
                        "detail": f"{key}={val:.1f} sobre el rango aprendido [{g['min']:.1f}, {g['max']:.1f}]",
                        "why": "valor fuera del comportamiento normal aprendido",
                    }
                )
    return anomalies


# ── persistencia ─────────────────────────────────────────────────────────────
def load() -> dict | None:
    import json

    try:
        return json.loads(_baseline_path().read_text())
    except (OSError, ValueError):
        return None


def save(baseline: dict) -> None:
    import json

    _baseline_path().write_text(json.dumps(baseline, indent=2, ensure_ascii=False))


# ── informe / estado ─────────────────────────────────────────────────────────
def summary(baseline: dict) -> None:
    m = baseline["meta"]
    print("\n▸ Línea base de Arx")
    print(f"  muestras       {m['samples']}  ·  {'SELLADA' if m.get('sealed') else 'aprendiendo'}")
    print(f"  creada         {m['created']}   actualizada {m['updated']}")
    for key, d in baseline.get("sets", {}).items():
        print(f"  {key:<14} {len(d)} conocidos")
    for key, g in baseline.get("gauges", {}).items():
        mean = g["sum"] / g["n"] if g["n"] else 0
        print(f"  {key:<14} rango [{g['min']:.1f}, {g['max']:.1f}]  media {mean:.1f}")
    alerts = baseline.get("integrity_alerts", [])
    if alerts:
        print(f"  ⚠ integridad   {len(alerts)} cambio(s) en ficheros críticos durante el aprendizaje:")
        for a in alerts[-3:]:
            print(f"      {a['at']}  →  {', '.join(a['changed'])}")
    else:
        print("  integridad     sin cambios en ficheros críticos ✓")
    print()


# ── entrada ──────────────────────────────────────────────────────────────────
def run(samples: int = 1, interval: int = 0, seal: bool = False, status: bool = False) -> int:
    if status:
        b = load()
        if not b:
            print("No hay línea base todavía. Ejecuta:  arx learn")
            return 0
        summary(b)
        return 0

    baseline = load() or new_baseline()

    if seal:
        if baseline["meta"]["samples"] == 0:
            print("No puedes sellar una base vacía. Ejecuta `arx learn` primero.")
            return 1
        baseline["meta"]["sealed"] = True
        save(baseline)
        print(f"✓ Línea base SELLADA con {baseline['meta']['samples']} muestras. Lista para `arx guard`.")
        return 0

    for i in range(max(1, samples)):
        fold(baseline, snapshot())
        if i < samples - 1 and interval > 0:
            time.sleep(interval)
    save(baseline)
    print(f"✓ {samples} muestra(s) integrada(s). Total acumulado: {baseline['meta']['samples']}.")
    summary(baseline)
    if not baseline["meta"]["sealed"]:
        print("Cuando el sistema haya mostrado su comportamiento normal, sella la base:  arx learn --seal\n")
    return 0
