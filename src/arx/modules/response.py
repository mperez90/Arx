"""Arx · response — motor de respuesta por niveles.

Cada hallazgo recibe SIEMPRE atención Tier 0 (registro + evidencia + alerta). Además
se propone una remediación con su nivel:

  Tier 0  observar/registrar          — siempre, sin autorización
  Tier 1  auto, REVERSIBLE, auto-expira — se aplica si `--enforce` está activo
  Tier 2  humano + palabra             — nunca automático (irreversible/sensible)

"Voluntad de acero" = Tier 0/1 sin fatiga; lo irreversible es del humano.

Nota de honestidad: la EJECUCIÓN real de acciones de sistema (bloqueo de puerto,
SIGSTOP, revertir fichero) requiere Linux + root en el host destino. Aquí se decide
y se registra el plan; la ejecución se realiza en el host (marcada como tal), nunca
se finge hecha.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone

from arx import config

DEFAULT_TTL_MIN = 60  # los bloqueos Tier 1 auto-expiran (reversibles por doctrina)

# kind → (tier, acción de remediación, reversible, por qué ese nivel)
_PLAN: dict[str, tuple[int, str, bool, str]] = {
    "integrity": (2, "revertir el fichero crítico a copia buena conocida", True,
                  "alterar credenciales/ficheros del sistema es sensible → requiere tu palabra"),
    "listen_ports": (1, "bloquear el puerto en firewall (temporal, auto-expira)", True,
                     "bloquear un puerto es reversible y contiene exposición nueva"),
    "processes": (1, "suspender el proceso (SIGSTOP) para análisis", True,
                  "suspender es reversible (SIGCONT); no destruye evidencia"),
    "login_users": (2, "terminar la sesión y rotar credenciales", False,
                    "podría ser un admin legítimo → requiere tu palabra"),
    "canary": (1, "elevar el nivel de alerta y capturar el contexto del acceso al señuelo", True,
               "un señuelo tocado es señal fuerte de intruso; elevar y capturar es reversible"),
    "gauge": (0, "registrar y vigilar la tendencia", True, "señal débil; observar primero"),
}


def classify(finding: dict) -> dict:
    tier, action, reversible, why = _PLAN.get(
        finding.get("kind", ""), (0, "registrar y vigilar", True, "señal débil; observar primero")
    )
    return {"tier": tier, "action": action, "reversible": reversible, "why": why}


def _incidents_path():
    return config.state_dir() / "incidents.jsonl"


def record(entry: dict) -> None:
    entry = {"at": datetime.now(timezone.utc).isoformat(timespec="seconds"), **entry}
    with open(_incidents_path(), "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _is_linux_root() -> bool:
    return sys.platform.startswith("linux") and hasattr(os, "geteuid") and os.geteuid() == 0


# ── bloqueos activos con auto-expiración (Tier 1 reversible) ──────────────────
def _blocks_path():
    return config.state_dir() / "active_blocks.json"


def _load_blocks() -> list[dict]:
    try:
        return json.loads(_blocks_path().read_text())
    except (OSError, ValueError):
        return []


def _save_blocks(blocks: list[dict]) -> None:
    _blocks_path().write_text(json.dumps(blocks, indent=2, ensure_ascii=False))
    try:
        _blocks_path().chmod(0o600)
    except OSError:
        pass


def _parse_dt(s: str | None):
    try:
        return datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return None


def register_block(finding: dict, revert_cmd: str, ttl_min: int = DEFAULT_TTL_MIN, now=None) -> None:
    now = now or datetime.now(timezone.utc)
    blocks = _load_blocks()
    blocks.append(
        {
            "detail": finding.get("detail"),
            "revert": revert_cmd,
            "applied_at": now.isoformat(timespec="seconds"),
            "expires_at": (now + timedelta(minutes=ttl_min)).isoformat(timespec="seconds"),
        }
    )
    _save_blocks(blocks)


def expire_blocks(now=None) -> list[dict]:
    """Revierte los bloqueos Tier 1 vencidos. En Linux+root ejecuta el revert real."""
    now = now or datetime.now(timezone.utc)
    keep, expired = [], []
    for b in _load_blocks():
        exp = _parse_dt(b.get("expires_at"))
        if exp and exp <= now:
            if _is_linux_root() and b.get("revert"):
                try:
                    subprocess.run(b["revert"].split(), capture_output=True, text=True)
                except OSError:
                    pass  # la herramienta de revert ya no está; no romper el bucle de guardia
            record({"kind": "block_expired", "detail": b.get("detail"), "reverted": b.get("revert")})
            expired.append(b)
        else:
            keep.append(b)
    if expired:
        _save_blocks(keep)
    return expired


def _execute_tier1(finding: dict) -> tuple[str, str | None]:
    """Ejecuta una remediación Tier 1 reversible SOLO en Linux+root.

    Devuelve (status, comando_para_revertir). Fuera de Linux+root NO finge: informa que
    queda listo para ejecutar en el destino. Nunca hace nada irreversible.
    """
    if not _is_linux_root():
        return "listo para ejecutar en destino (requiere Linux + root)", None
    kind = finding.get("kind")
    target = finding.get("target") or {}
    if kind == "listen_ports" and target.get("port") and shutil.which("ufw"):
        proto, port = target.get("proto", "tcp"), target["port"]
        r = subprocess.run(["ufw", "deny", f"{port}/{proto}"], capture_output=True, text=True)
        if r.returncode == 0:
            revert = f"ufw delete deny {port}/{proto}"
            register_block(finding, revert)
            return f"puerto {port}/{proto} bloqueado en ufw (auto-expira en {DEFAULT_TTL_MIN} min)", revert
        return f"no se pudo bloquear el puerto ({r.stderr.strip()[:48]})", None
    if kind == "canary":
        return "nivel de alerta elevado y contexto capturado", None
    # p. ej. suspender un proceso por NOMBRE es inseguro (match erróneo) → se propone, no se auto-ejecuta
    return "propuesta (sin ejecutor automático seguro para este tipo)", None


def handle(finding: dict, enforce: bool = False, authorized: bool = False) -> dict:
    """Decide y registra la respuesta a un hallazgo. Devuelve el desenlace."""
    plan = classify(finding)
    tier = plan["tier"]
    outcome = {
        "sev": finding.get("sev"),
        "detail": finding.get("detail"),
        "tier": tier,
        "remediation": plan["action"],
        "reversible": plan["reversible"],
    }
    if tier == 0:
        outcome["status"] = "observado y registrado"
    elif tier == 1:
        if enforce:
            status, revert = _execute_tier1(finding)
            outcome["status"] = status
            if revert:
                outcome["revert"] = revert
        else:
            outcome["status"] = "propuesta auto — activa --enforce para aplicar"
    else:  # tier 2
        outcome["status"] = (
            "autorizada por palabra ✓" if authorized else "PENDIENTE — requiere tu palabra de autorización"
        )
    record({"kind": "incident", **outcome})
    return outcome
