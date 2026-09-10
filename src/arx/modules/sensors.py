"""Arx · sensors — capa de sensores del sistema con degradación.

Detecta y usa lo que haya en el host, con fallback a los colectores base de `recon`:
  · osquery   — consultas SQL al estado del sistema (multiplataforma).
  · auditd    — eventos de syscalls/ficheros (Linux); vía `ausearch`.
  · Falco     — comportamiento en kernel/eBPF (Linux); lee su salida JSON.

Todo degrada: si un sensor no está, su colector devuelve []/None y `guard` sigue con la
detección por anomalía de la baseline. Falco/auditd se activan de verdad en el host
Linux; aquí queda el ingestor real (parseo de sus formatos), no un simulacro.
"""
from __future__ import annotations

import json
import shutil

from arx.modules import recon

_FALCO_SEV = {
    "Emergency": "crit", "Alert": "crit", "Critical": "crit", "Error": "high",
    "Warning": "med", "Notice": "low", "Informational": "info", "Debug": "info",
}


def available() -> dict:
    return {
        "osquery": bool(shutil.which("osqueryi")),
        "auditd": bool(shutil.which("ausearch")),
        "falco": bool(shutil.which("falco")),
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


def read_falco_events(path: str = "/var/log/falco/events.json", limit: int = 50) -> list[dict]:
    """Lee eventos JSONL de Falco (requiere json_output=true en su config)."""
    data = recon._read(path)
    if not data:
        return []
    events = []
    for line in data.splitlines()[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except ValueError:
            continue
        events.append(
            {
                "sev": _FALCO_SEV.get(e.get("priority", ""), "med"),
                "kind": "falco",
                "detail": e.get("output", "evento Falco"),
                "why": "regla de comportamiento de Falco disparada",
            }
        )
    return events


def read_auditd_events() -> list[dict]:
    """Eventos recientes de auditd en ficheros sensibles (Linux, requiere reglas)."""
    if not shutil.which("ausearch"):
        return []
    events = []
    for target, why in [
        ("/etc/passwd", "cambio en /etc/passwd fuera de la gestión de usuarios"),
        ("/etc/sudoers", "cambio en /etc/sudoers → posible escalada de privilegios"),
    ]:
        out = recon._run(["ausearch", "-ts", "recent", "-f", target, "-i"], timeout=8)
        if out:
            events.append(
                {"sev": "high", "kind": "auditd",
                 "detail": f"auditd registró acceso de escritura reciente a {target}", "why": why}
            )
    return events


def collect_events() -> list[dict]:
    """Todos los eventos de sensores disponibles, normalizados."""
    return read_falco_events() + read_auditd_events()
