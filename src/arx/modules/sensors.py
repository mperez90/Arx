"""Arx · sensors — capa de sensores del sistema con degradación.

Detecta y usa lo que haya en el host, con fallback a los colectores base de `recon`:
  · osquery   — consultas SQL al estado del sistema (multiplataforma).
  · auditd    — eventos de syscalls/ficheros (Linux) con reglas PROPIAS de Arx (claves
                arx_ident / arx_canary), leídos de forma incremental con `--checkpoint`.
  · Falco     — comportamiento en kernel/eBPF (Linux); su JSONL se lee por offset.

INCREMENTAL: cada barrido entrega solo los eventos nuevos desde el anterior. El primer
barrido fija el punto de partida y no re-emite la historia (evita la inundación inicial).

Todo degrada: si un sensor no está, su colector devuelve [] y `guard` sigue con la
detección por anomalía de la baseline.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

from arx import config
from arx.modules import recon

FALCO_LOG = "/var/log/falco/events.json"
MAX_EVENTS = 20  # por sensor y barrido: una avalancha se resume, no se vuelca entera

_FALCO_SEV = {
    "Emergency": "crit", "Alert": "crit", "Critical": "crit", "Error": "high",
    "Warning": "med", "Notice": "low", "Informational": "info", "Debug": "info",
}

# Ficheros de identidad vigilados por auditd (escritura/atributos).
IDENT_WATCH = ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers", "/etc/sudoers.d",
               "/root/.ssh"]


def available() -> dict:
    return {
        "osquery": bool(shutil.which("osqueryi")),
        "auditd": bool(shutil.which("ausearch") and shutil.which("auditctl")),
        "falco": bool(shutil.which("falco")) or Path(FALCO_LOG).exists(),
    }


def osquery(sql: str, timeout: int = 10) -> list[dict] | None:
    if not shutil.which("osqueryi"):
        return None
    out = recon._run(["osqueryi", "--json", sql], timeout=timeout)
    if out is None:
        return None
    try:
        return json.loads(out)
    except ValueError:
        return None


# ── Falco (JSONL por offset) ─────────────────────────────────────────────────
def _cursor_path():
    return config.state_dir() / "sensor_cursors.json"


def _tail_new(path: str, name: str) -> tuple[list[str], bool]:
    """(Líneas añadidas a `path` desde la última lectura, hubo_truncado).

    Detecta rotación (cambio de inode: normal, logrotate) y TRUNCADO (mismo inode,
    tamaño menor: alguien vació el log — anti-forense clásico, ver lab L9).
    El primer barrido arranca al final y no re-emite la historia.
    """
    try:
        st = os.stat(path)
    except OSError:
        return [], False
    cursors = config.read_json(_cursor_path())
    cur = cursors.get(name)
    if cur is None:  # primera vez: arrancar al final, no re-emitir la historia
        cursors[name] = {"ino": st.st_ino, "off": st.st_size}
        config.write_json(_cursor_path(), cursors)
        return [], False
    tampered = cur.get("ino") == st.st_ino and st.st_size < cur.get("off", 0)
    off = cur.get("off", 0) if cur.get("ino") == st.st_ino and not tampered else 0
    try:
        with open(path, "rb") as f:
            f.seek(off)
            data = f.read(4 * 1024 * 1024)
    except OSError:
        return [], False
    # no partir una línea a medias: avanzar solo hasta el último salto de línea completo
    cut = data.rfind(b"\n") + 1
    cursors[name] = {"ino": st.st_ino, "off": off + cut}
    config.write_json(_cursor_path(), cursors)
    return data[:cut].decode("utf-8", "replace").splitlines(), tampered


def read_falco_events(path: str = FALCO_LOG) -> list[dict]:
    """Eventos Falco NUEVOS (requiere json_output=true en su config)."""
    events = []
    lines, _ = _tail_new(path, "falco")
    for line in lines[-MAX_EVENTS:]:
        try:
            e = json.loads(line)
        except ValueError:
            continue
        events.append(
            {
                "sev": _FALCO_SEV.get(e.get("priority", ""), "med"),
                "kind": "falco",
                "detail": f"Falco · {e.get('rule', '?')}: {e.get('output', '')}"[:400],
                "why": "regla de comportamiento de Falco disparada",
            }
        )
    return events


# ── auditd (reglas propias + checkpoint) ─────────────────────────────────────
def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def ensure_audit_rules(canary_paths: list[str] | None = None) -> bool:
    """Instala (idempotente) las reglas de Arx en auditd. Requiere root + auditctl."""
    if not (_is_root() and shutil.which("auditctl")):
        return False
    current = recon._run(["auditctl", "-l"]) or ""
    wanted = [(p, "wa", "arx_ident") for p in IDENT_WATCH if os.path.exists(p)]
    wanted += [(p, "rwa", "arx_canary") for p in (canary_paths or []) if os.path.exists(p)]
    for path, perm, key in wanted:
        if f"-w {path} " in current and f"-k {key}" in current:
            continue
        subprocess.run(["auditctl", "-w", path, "-p", perm, "-k", key],
                       capture_output=True, text=True, timeout=10)
    return True


def _ausearch_new(key: str) -> list[str]:
    """Eventos nuevos de una clave, en formato legible (`--format text`)."""
    if not shutil.which("ausearch"):
        return []
    ckpt = config.state_dir() / f"ausearch-{key}.ckpt"
    first = not ckpt.exists()
    args = ["ausearch", "-k", key, "--checkpoint", str(ckpt), "--format", "text"]
    if first:
        args += ["-ts", "recent"]
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return []
    if r.returncode in (10, 11, 12):  # checkpoint inválido (logs rotados): reiniciar
        ckpt.unlink(missing_ok=True)
        return []
    if first or r.returncode != 0:  # rc 1 = sin coincidencias
        return []
    return [l.strip() for l in r.stdout.splitlines() if l.strip()]


def read_auditd_events() -> list[dict]:
    events = []
    for line in _ausearch_new("arx_ident")[-MAX_EVENTS:]:
        events.append({"sev": "high", "kind": "auditd", "detail": f"auditd · identidad: {line}"[:400],
                       "why": "escritura/cambio de atributos en un fichero de identidad o privilegios"})
    for line in _ausearch_new("arx_canary")[-MAX_EVENTS:]:
        events.append({"sev": "high", "kind": "canary", "detail": f"señuelo accedido · {line}"[:400],
                       "why": "nadie legítimo abre un honeytoken: el acceso lo hizo el proceso indicado"})
    return events


def collect_events() -> list[dict]:
    """Todos los eventos NUEVOS de sensores disponibles, normalizados."""
    return read_falco_events() + read_auditd_events() + read_auth_log() + detect_port_scan()


# ── auth.log / secure: fuerza bruta SSH + anti-forense (cierra GAP L2) ───────
AUTH_LOGS = ["/var/log/auth.log", "/var/log/secure"]  # Debian/Ubuntu · RHEL/Fedora
AUTH_FAIL_RE = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from ([0-9a-fA-F.:]+)")
AUTH_WINDOW_S = 600     # 10 min de memoria
AUTH_THRESHOLD = 6      # fallos desde una misma IP dentro de la ventana

# ── escaneo de puertos por conexiones (procfs) — GAP L1 ──────────────────────
SCAN_WINDOW_S = 600
SCAN_THRESHOLD = 8      # puertos locales distintos tocados por una misma IP


def _window_path(name: str):
    return config.state_dir() / f"sensor-window-{name}.json"


def _prune(win: dict, now: float, ttl: int) -> dict:
    return {k: v for k, v in win.items() if now - v.get("t", 0) <= ttl}


def read_auth_log(now: float | None = None) -> list[dict]:
    """Ráfagas de fallos de autenticación (sshd) y truncado del log de autenticación.

    La ventana es por IP de origen: un atacante que prueba muchos usuarios desde la
    misma IP sigue contando. El usuario atacado NO se toca automáticamente (Tier 1
    bloquea la IP; la rotación de credenciales es Tier 2).
    """
    path = next((p for p in AUTH_LOGS if os.path.exists(p)), None)
    if path is None:
        return []
    now = now if now is not None else time.time()
    lines, tampered = _tail_new(path, "authlog")
    events: list[dict] = []
    if tampered:
        events.append({
            "sev": "high", "kind": "log_tamper",
            "detail": f"{path} fue truncado (mismo inode, tamaño menor)",
            "why": "vaciar el log de autenticación es anti-forense: alguien borra huellas",
        })
    win = _prune(config.read_json(_window_path("auth"), {}), now, AUTH_WINDOW_S)
    for line in lines:
        m = AUTH_FAIL_RE.search(line)
        if not m:
            continue
        user, ip = m.group(1), m.group(2)
        e = win.setdefault(ip, {"t": now, "fails": 0, "users": {}})
        e["t"], e["fails"] = now, e["fails"] + 1
        e["users"][user] = e["users"].get(user, 0) + 1
    fired = []
    for ip, e in win.items():
        if e["fails"] >= AUTH_THRESHOLD and not e.get("fired"):
            e["fired"] = True  # una alerta por IP y ventana; la dedup de response hace el resto
            user = max(e["users"], key=e["users"].get)
            fired.append({
                "sev": "high", "kind": "auth_bruteforce",
                "detail": f"{e['fails']} fallos de autenticación desde {ip} "
                          f"(usuario más probado: {user})",
                "why": "fuerza bruta contra el servicio de acceso remoto",
                "target": {"ip": ip, "user": user},
            })
    config.write_json(_window_path("auth"), win)
    return events + fired


def _scan_from_nft() -> dict[str, set[int]] | None:
    """ip → {puertos tocados} según los sets de pista del kernel (inet arx scan4/6).

    La regla `tcp flags & (syn|ack) == syn → add @scanN { saddr . dport }` registra
    CADA SYN entrante, incluso contra puertos cerrados (no hace falta que nazca un
    socket): es la pista fiable para -sS y la que no pierde carreras contra servicios
    que cierran rápido. La ventana la mantiene el propio set (timeout 10m).
    Devuelve None si nftables no está disponible (el llamador degrada a procfs).
    """
    if not shutil.which("nft"):
        return None
    hits: dict[str, set[int]] = {}
    found = False
    for setname in ("scan4", "scan6"):
        try:
            r = subprocess.run(["nft", "list", "set", "inet", "arx", setname],
                               capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if r.returncode != 0:
            continue  # la tabla aún no existe (primeros barridos): no es un error
        found = True
        for m in re.finditer(r"([0-9a-fA-F.:]+)\s*\.\s*(\d+)", r.stdout):
            hits.setdefault(m.group(1), set()).add(int(m.group(2)))
    return hits if found else None


def detect_port_scan(conns: list[dict] | None = None, now: float | None = None,
                     listen_ports: set[int] | None = None) -> list[dict]:
    """Una IP que toca muchos puertos locales distintos en poco tiempo = escaneo.

    Primario: la pista nft del kernel (`_scan_from_nft`) — ve SYNs aunque el puerto
    esté cerrado. Fallback (host sin nftables): ventana sobre /proc/net/tcp, que solo
    ve puertos que ACEPTARON conexión (límite honesto, lab/README).
    Nunca señala loopback ni las IPs propias del host.
    """
    now = now if now is not None else time.time()
    own = recon.local_ips()
    hits = _scan_from_nft()
    if hits is not None:
        events = []
        for ip, ports in sorted(hits.items()):
            if ip in own or len(ports) < SCAN_THRESHOLD:
                continue
            events.append({
                "sev": "high", "kind": "port_scan",
                "detail": f"escaneo desde {ip} (≥{SCAN_THRESHOLD} puertos en 10 min, pista kernel)",
                "why": "reconocimiento previo a un ataque: nadie legítimo toca tantos puertos",
                "target": {"ip": ip},
            })
        return events
    # ── fallback procfs: solo conexiones aceptadas a puertos en escucha ──
    # (las sesiones salientes tienen puerto local efímero y nunca cuentan)
    conns = recon.collect_connections() if conns is None else conns
    if listen_ports is None:
        listen_ports = set()
        for p in recon.collect_ports():
            try:
                listen_ports.add(int(str(p.get("local", "")).rsplit(":", 1)[-1]))
            except (ValueError, IndexError):
                continue
    win = _prune(config.read_json(_window_path("scan"), {}), now, SCAN_WINDOW_S)
    for c in conns:
        ip = c.get("remote_ip", "")
        if not ip or ip in own or c.get("local_port") not in listen_ports:
            continue
        e = win.setdefault(ip, {"t": now, "ports": []})
        e["t"] = now
        if c["local_port"] not in e["ports"]:
            e["ports"].append(c["local_port"])
    events = []
    for ip, e in win.items():
        if len(e["ports"]) >= SCAN_THRESHOLD and not e.get("fired"):
            e["fired"] = True
            events.append({
                "sev": "high", "kind": "port_scan",
                "detail": f"escaneo desde {ip} (≥{SCAN_THRESHOLD} puertos aceptados en 10 min)",
                "why": "reconocimiento previo a un ataque: nadie legítimo toca tantos puertos",
                "target": {"ip": ip},
            })
    config.write_json(_window_path("scan"), win)
    return events
