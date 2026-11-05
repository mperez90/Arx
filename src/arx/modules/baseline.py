"""Arx · baseline — aprendizaje de "lo normal" (comando `arx learn`).

Toma instantáneas del comportamiento del host y las funde en una línea base:
  · CONJUNTOS (procesos, puertos en escucha, servicios, usuarios conectados):
    se acumula lo visto → el conjunto "conocido", con frecuencia.
  · MEDIDORES (carga, memoria, disco, conexiones): min/max/media → rango normal.

Conservador: aprender > bloquear durante la ventana. Integridad de arranque: se
fija la huella de ficheros críticos (authorized_keys, sudoers, passwd, cron, units de
systemd, ld.so.preload, set SUID) en el primer muestreo y se avisa si cambian mientras
se aprende — para no aprender a un intruso como "normal". `compare()` es la función que
usa `guard` para detectar desvíos contra esta base.

Identidades estables (para no inundar de falsos positivos):
  · ejecutables por RUTA real (/proc/<pid>/exe), no por el nombre corto de 15 caracteres
    que cualquier malware puede imitar ("sshd", "kworker");
  · puertos como "proto puerto exposición" ("tcp 22 all"): 0.0.0.0:22 y [::]:22 son lo
    mismo; los UDP del rango efímero (DHCP, NTP, mDNS) no se aprenden ni se vigilan.
"""
from __future__ import annotations

import glob
import hashlib
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from arx import config
from arx.i18n import tr
from arx.modules import recon

# Severidad del desvío según qué conjunto introduce algo nuevo.
KIND_SEV = {
    "listen_ports": "high",
    "login_users": "high",
    "services": "med",
    "executables": "med",
    "processes": "med",
}
# Ejecutar desde estas rutas es típico de malware descargado → severidad alta.
_SUSPECT_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/")
# Binarios del sistema (gestionados por paquetes): que un admin ejecute uno nuevo es lo normal.
# Se registran con severidad baja; lo que corre desde /opt, /home, /srv… queda en media.
_SYSTEM_DIRS = ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/usr/libexec/",
                "/lib/", "/usr/local/bin/", "/snap/")
FORMAT = 2  # v2: executables + puertos normalizados


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _baseline_path():
    return config.state_dir() / "baseline.json"


# ── instantánea de comportamiento ────────────────────────────────────────────
def _executables() -> list[str]:
    """Rutas de los binarios en ejecución. Linux: /proc/<pid>/exe (no falsificable por
    nombre). Sin /proc (macOS/dev): `ps -axo comm=`, que allí ya da la ruta."""
    proc = Path("/proc")
    if proc.is_dir():
        exes = set()
        for d in proc.iterdir():
            if not d.name.isdigit():
                continue
            try:
                exe = os.readlink(d / "exe")
            except OSError:
                continue  # hilo del kernel, proceso ya terminado o sin permiso
            exes.add(exe.removesuffix(" (deleted)"))
        if exes:
            return sorted(exes)
    out = recon._run(["ps", "-axo", "comm="]) or recon._run(["ps", "-eo", "comm="])
    return sorted({l.strip() for l in (out or "").splitlines() if l.strip()})


def _ephemeral_range() -> tuple[int, int]:
    raw = recon._read("/proc/sys/net/ipv4/ip_local_port_range")
    try:
        lo, hi = (int(x) for x in raw.split())
        return lo, hi
    except (AttributeError, ValueError):
        return 32768, 60999


def port_item(proto: str, local: str, exposed: str) -> str | None:
    """'tcp' '[::]:22' 'all' → 'tcp 22 all'. None si no aplica (UDP efímero, sin puerto)."""
    try:
        port = int(local.rsplit(":", 1)[1])
    except (IndexError, ValueError):
        return None
    proto = proto.lower()
    if proto.startswith("udp"):
        lo, hi = _ephemeral_range()
        if lo <= port <= hi:
            return None
        proto = "udp"
    else:
        proto = "tcp"
    return f"{proto} {port} {exposed}"


def _listen_ports() -> list[str]:
    items = {port_item(p["proto"], p["local"], p["exposed"]) for p in recon.collect_ports()}
    return sorted(i for i in items if i)


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
            # el primer paréntesis: el origen de tmux lleva otro dentro, `(tmux(451).%0)`
            origin = _login_origin(line[line.find("(") + 1 : line.rfind(")")])
            if origin is None:
                continue
            src = "@" + origin
        users.add(f[0] + src)
    return sorted(users)


def _login_origin(origin: str) -> str | None:
    """Lo estable del origen, nunca lo que cambia: mosh pone un pid. Una ventana de tmux o screen no
    es un acceso (None): es alguien que ya entró, y ese acceso se vio cuando ocurrió."""
    if origin.startswith("tmux(") or (origin.startswith(":") and ":S." in origin):
        return None
    if origin.startswith("mosh"):
        return "mosh"
    if origin.startswith(":"):
        return "local"
    return origin


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
    return {
        "at": _now(),
        "sets": {
            "executables": _executables(),
            "listen_ports": _listen_ports(),
            "services": recon.collect_services() or [],
            "login_users": _login_users(),
        },
        "gauges": _gauges(),
    }


# ── integridad de arranque ───────────────────────────────────────────────────
def _h(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogateescape")).hexdigest()[:16]


def _hash_files(paths: list[str]) -> str | None:
    """Huella conjunta de varios ficheros (ruta + contenido). None si no hay ninguno legible."""
    parts = [f"{p}\0{d}" for p in sorted(paths) if (d := recon._read(p)) is not None]
    return _h("\0\0".join(parts)) if parts else None


def suid_fingerprint() -> str | None:
    """Recorre el disco (find -perm -4000): CARO. `guard` lo hace cada hora, no cada barrido."""
    suid = recon.collect_users().get("suid_binaries")
    return _h("\n".join(sorted(suid))) if suid is not None else None


def integrity_paths() -> dict[str, list[str]]:
    """Clave de integridad → ficheros cubiertos que EXISTEN (respaldo y restauración)."""
    groups = {
        "authorized_keys_root": ["/root/.ssh/authorized_keys"],
        "sudoers": ["/etc/sudoers"],
        "passwd": ["/etc/passwd"],
        "ld_preload": ["/etc/ld.so.preload"],
        "authorized_keys_users": glob.glob("/home/*/.ssh/authorized_keys"),
        "sudoers_d": glob.glob("/etc/sudoers.d/*"),
        "cron": ["/etc/crontab", *glob.glob("/etc/cron.d/*"),
                 *glob.glob("/var/spool/cron/crontabs/*")],
        "systemd_units": glob.glob("/etc/systemd/system/*.service")
                         + glob.glob("/etc/systemd/system/*.timer"),
    }
    out: dict[str, list[str]] = {}
    for key, paths in groups.items():
        existing = [p for p in paths if os.path.isfile(p)]
        if existing:
            out[key] = existing
    return out


def integrity_fingerprint(include_suid: bool = True) -> dict:
    fp: dict = {}
    singles = {"authorized_keys_root", "sudoers", "passwd", "ld_preload"}
    for key, paths in integrity_paths().items():
        if key in singles:
            data = recon._read(paths[0])
            if data is not None:
                fp[key] = _h(data)
        else:
            v = _hash_files(paths)
            if v:
                fp[key] = v
    if include_suid:
        v = suid_fingerprint()
        if v:
            fp["suid_set"] = v
    return fp


# ── modelo de la base ────────────────────────────────────────────────────────
def new_baseline() -> dict:
    return {
        "meta": {"created": _now(), "updated": _now(), "samples": 0, "sealed": False, "format": FORMAT},
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
    if key == "listen_ports":  # "tcp 4444 all"
        try:
            proto, port, exposed = item.split(" ")
            return {"proto": proto, "port": int(port), "exposed": exposed}
        except (ValueError, TypeError):
            return {}
    if key == "executables":
        return {"exe": item}
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
        if key not in sets:
            continue  # la base no aprendió este conjunto (base antigua): no inundar de "nuevos"
        known = set(sets[key])
        for item in observed:
            if item not in known:
                sev = KIND_SEV.get(key, "med")
                why = tr("not in the {key} baseline ({n} known)", key=key, n=len(known))
                if key == "executables" and item.startswith(_SUSPECT_DIRS):
                    sev, why = "high", why + tr("; it also runs from a temporary directory")
                elif key == "executables" and item.startswith(_SYSTEM_DIRS):
                    sev = "low"
                anomalies.append(
                    {
                        "sev": sev,
                        "kind": key,
                        "detail": tr("new in {key}: {item}", key=key, item=item),
                        "why": why,
                        "target": _target_for(key, item),
                        "set": key,
                        "item": item,
                        # semilla histórica de la huella: no es texto, y no cambia con el idioma
                        "fp_key": f"{key}|nuevo en {key}: {item}",
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
                        "detail": tr("{key}={val:.1f} above the learned range [{min:.1f}, "
                                     "{max:.1f}]", key=key, val=val, min=g['min'], max=g['max']),
                        "why": tr("value outside the learned normal behavior"),
                        "fp_key": f"gauge|{key}",  # el valor cambia cada barrido; la amenaza no
                    }
                )
    return anomalies


# ── persistencia ─────────────────────────────────────────────────────────────
def _migrate(b: dict) -> dict:
    """Base v1 → v2: puertos 'tcp 0.0.0.0:22' → 'tcp 22 all'. Los ejecutables no se
    pueden deducir de los nombres cortos de v1: hay que re-aprender (guard lo avisa)."""
    if b.get("meta", {}).get("format", 1) >= FORMAT:
        return b
    old = b.get("sets", {}).get("listen_ports")
    if old is not None:
        new: dict = {}
        for item, n in old.items():
            try:
                proto, local = item.split(" ", 1)
            except ValueError:
                continue
            norm = port_item(proto, local, recon._classify_exposure(local))
            if norm:
                new[norm] = new.get(norm, 0) + n
        b["sets"]["listen_ports"] = new
    b["sets"].pop("processes", None)
    b["meta"]["format"] = FORMAT
    b["meta"]["migrated_from_v1"] = True
    return b


def load() -> dict | None:
    b = config.read_json(_baseline_path(), None)
    return _migrate(b) if isinstance(b, dict) and "meta" in b else None


def save(baseline: dict) -> None:
    config.write_json(_baseline_path(), baseline)


def accept(key: str, item: str) -> bool:
    """Incorpora a la base un cambio legítimo (p. ej. instalaste nginx → 'tcp 80 all')."""
    with config.locked("baseline"):
        b = load()
        if key == "integrity" and b:  # un cambio legítimo: la nueva huella y la nueva copia buena
            current = integrity_fingerprint().get(item)
            if current is None:
                return False
            b.setdefault("integrity", {})[item] = current
            b["meta"]["updated"] = _now()
            save(b)
            from arx.modules import response
            response.backup_critical({item: integrity_paths().get(item, [])})
            return True
        if key in ("uid0_accounts", "intel_allow") and b:  # jamás se aprenden solas: nacen al aceptar
            b.setdefault("sets", {}).setdefault(key, {})
        if not b or key not in b.get("sets", {}):
            return False
        b["sets"][key][item] = b["sets"][key].get(item, 0) + 1
        b["meta"]["updated"] = _now()
        save(b)
    return True


# ── informe / estado ─────────────────────────────────────────────────────────
def summary(baseline: dict) -> None:
    m = baseline["meta"]
    print(tr("\n▸ Arx baseline"))
    print(tr("  samples        {samples}  ·  {v}",
             samples=m['samples'], v='SELLADA' if m.get('sealed') else 'aprendiendo'))
    print(tr("  created        {created}   updated {updated}",
             created=m['created'], updated=m['updated']))
    for key, d in baseline.get("sets", {}).items():
        print(tr("  {key:<14} {n} known", key=key, n=len(d)))
    for key, g in baseline.get("gauges", {}).items():
        mean = g["sum"] / g["n"] if g["n"] else 0
        print(tr("  {key:<14} range [{min:.1f}, {max:.1f}]  mean {mean:.1f}",
                 key=key, min=g['min'], max=g['max'], mean=mean))
    alerts = baseline.get("integrity_alerts", [])
    if alerts:
        print(tr("  ⚠ integrity    {n} change(s) in critical files during learning:", n=len(alerts)))
        for a in alerts[-3:]:
            print(f"      {a['at']}  →  {', '.join(a['changed'])}")
    else:
        print(tr("  integrity      no changes in critical files ✓"))
    print()


# ── entrada ──────────────────────────────────────────────────────────────────
def run(samples: int = 1, interval: int = 0, seal: bool = False, status: bool = False) -> int:
    if status:
        b = load()
        if not b:
            print(tr("No baseline yet. Run:  arx learn"))
            return 0
        summary(b)
        return 0

    baseline = load() or new_baseline()

    if seal:
        if baseline["meta"]["samples"] == 0:
            print(tr("You cannot seal an empty baseline. Run `arx learn` first."))
            return 1
        baseline["meta"]["sealed"] = True
        # la huella dice QUE cambió el conjunto SUID, no cuál: sin la lista no se sabe qué hay de nuevo
        suid = recon.collect_users().get("suid_binaries")
        if suid is not None:
            baseline["sets"]["suid_binaries"] = {p: 1 for p in suid}
        save(baseline)
        # Respaldo de los ficheros críticos al sellar: sin copia buena no hay restauración.
        from arx.modules import response
        n = response.backup_critical(integrity_paths())
        # La pista de escaneo (nft scan4/6) nace con el sellado: debe estar activa
        # ANTES del primer ataque, no en la primera respuesta.
        tracked = response.ensure_nft_tracking()
        print(tr("✓ Baseline SEALED with {samples} samples. Ready for `arx guard`.",
                 samples=baseline['meta']['samples']))
        print(tr("✓ Backup of {n} critical file(s) in the vault (enables Tier 2 restore).", n=n))
        if tracked:
            print(tr("✓ nft scan trail active (inet arx: scan4/scan6 + block sets)."))
        return 0

    from arx.modules import sensors
    for i in range(max(1, samples)):
        snap = snapshot()
        # lo normal también son los accesos sin terminal que ya ocurrieron: scp, Ansible, túneles
        snap["sets"]["login_users"] = sorted(set(snap["sets"]["login_users"]) | sensors.accepted_logins())
        fold(baseline, snap)
        if i < samples - 1 and interval > 0:
            time.sleep(interval)
    save(baseline)
    print(tr("✓ {samples} sample(s) taken. Running total: {samples2}.",
             samples=samples, samples2=baseline['meta']['samples']))
    summary(baseline)
    if not baseline["meta"]["sealed"]:
        print(tr("Once the system has shown its normal behavior, seal the baseline:  arx learn "
                 "--seal\n"))
    return 0
