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
import shutil
import subprocess
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


def _tail_new(path: str, name: str) -> list[str]:
    """Líneas añadidas a `path` desde la última lectura. Detecta rotación (inode/tamaño)."""
    try:
        st = os.stat(path)
    except OSError:
        return []
    cursors = config.read_json(_cursor_path())
    cur = cursors.get(name)
    if cur is None:  # primera vez: arrancar al final, no re-emitir la historia
        cursors[name] = {"ino": st.st_ino, "off": st.st_size}
        config.write_json(_cursor_path(), cursors)
        return []
    off = cur.get("off", 0) if cur.get("ino") == st.st_ino and st.st_size >= cur.get("off", 0) else 0
    try:
        with open(path, "rb") as f:
            f.seek(off)
            data = f.read(4 * 1024 * 1024)
    except OSError:
        return []
    # no partir una línea a medias: avanzar solo hasta el último salto de línea completo
    cut = data.rfind(b"\n") + 1
    cursors[name] = {"ino": st.st_ino, "off": off + cut}
    config.write_json(_cursor_path(), cursors)
    return data[:cut].decode("utf-8", "replace").splitlines()


def read_falco_events(path: str = FALCO_LOG) -> list[dict]:
    """Eventos Falco NUEVOS (requiere json_output=true en su config)."""
    events = []
    for line in _tail_new(path, "falco")[-MAX_EVENTS:]:
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
    return read_falco_events() + read_auditd_events()
