"""Arx · response — motor de respuesta por niveles.

Cada hallazgo recibe SIEMPRE atención Tier 0 (registro + evidencia + alerta). Además
se propone una remediación con su nivel:

  Tier 0  observar/registrar          — siempre, sin autorización
  Tier 1  auto, REVERSIBLE, auto-expira — se aplica si `--enforce` está activo
  Tier 2  humano + palabra             — nunca automático (irreversible/sensible)

"Voluntad de acero" = Tier 0/1 sin fatiga; lo irreversible es del humano.

Salvaguardas contra el auto-daño (una defensa que tumba su propio servidor es peor que
ninguna):
  · Memoria por hallazgo (huella estable): lo ya visto no se re-ejecuta ni se re-registra
    cada barrido; solo cuenta lo NUEVO o lo que cambia de estado.
  · Intocables: el puerto SSH, PID 1, el propio Arx y lo que el operador marcó como
    fuera-de-límites nunca reciben una acción automática — solo se observan.
  · Un bloqueo que expira y cuyo hallazgo REAPARECE no se re-bloquea en bucle: escala a
    Tier 2 (lo decide el humano).
  · Freno de seguridad: más de MAX_TIER1_PER_HOUR acciones automáticas en una hora →
    Arx deja de actuar y solo observa (algo raro pasa, o es él quien se equivoca).

Nota de honestidad: la EJECUCIÓN real de acciones de sistema requiere Linux + root en el
host destino. Fuera de eso se decide y se registra el plan, nunca se finge hecho.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import signal
import subprocess
import sys
from datetime import datetime, timedelta, timezone

from arx import config

DEFAULT_TTL_MIN = 60  # los bloqueos Tier 1 auto-expiran (reversibles por doctrina)
MAX_TIER1_PER_HOUR = 5

# kind → (tier, acción de remediación, reversible, por qué ese nivel)
_PLAN: dict[str, tuple[int, str, bool, str]] = {
    "integrity": (2, "revertir el fichero crítico a copia buena conocida", True,
                  "alterar credenciales/ficheros del sistema es sensible → requiere tu palabra"),
    "listen_ports": (1, "bloquear el puerto en firewall (temporal, auto-expira)", True,
                     "bloquear un puerto es reversible y contiene exposición nueva"),
    "executables": (1, "suspender el proceso (SIGSTOP) para análisis", True,
                    "suspender es reversible (SIGCONT); no destruye evidencia"),
    "processes": (1, "suspender el proceso (SIGSTOP) para análisis", True,
                  "suspender es reversible (SIGCONT); no destruye evidencia"),
    "login_users": (2, "terminar la sesión y rotar credenciales", False,
                    "podría ser un admin legítimo → requiere tu palabra"),
    "canary": (1, "elevar el nivel de alerta y capturar el contexto del acceso al señuelo", True,
               "un señuelo tocado es señal fuerte de intruso; elevar y capturar es reversible"),
    "gauge": (0, "registrar y vigilar la tendencia", True, "señal débil; observar primero"),
}

# Procesos que jamás se suspenden automáticamente (dejarían el host inaccesible o a Arx ciego).
_PROTECTED_EXES = {"sshd", "systemd", "init", "dbus-daemon", "journald", "systemd-journald",
                   "auditd", "falco", "osqueryd", "python3", "arx"}


def classify(finding: dict) -> dict:
    tier, action, reversible, why = _PLAN.get(
        finding.get("kind", ""), (0, "registrar y vigilar", True, "señal débil; observar primero")
    )
    return {"tier": tier, "action": action, "reversible": reversible, "why": why}


def fingerprint(finding: dict) -> str:
    """Huella estable de un hallazgo: misma amenaza → misma huella entre barridos."""
    basis = finding.get("fp_key") or f"{finding.get('kind', '')}|{finding.get('detail', '')}"
    return hashlib.sha1(basis.encode()).hexdigest()[:10]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def _parse_dt(s: str | None):
    try:
        return datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return None


def _incidents_path():
    return config.state_dir() / "incidents.jsonl"


def record(entry: dict) -> None:
    import json

    entry = {"at": _iso(_now()), **entry}
    fd = os.open(_incidents_path(), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _is_linux_root() -> bool:
    return sys.platform.startswith("linux") and hasattr(os, "geteuid") and os.geteuid() == 0


# ── memoria de hallazgos (dedup + escalada) ──────────────────────────────────
def _findings_path():
    return config.state_dir() / "findings.json"


def load_findings() -> dict:
    return config.read_json(_findings_path())


def _save_findings(st: dict) -> None:
    config.write_json(_findings_path(), st)


# ── intocables ───────────────────────────────────────────────────────────────
def ssh_ports() -> set[int]:
    from arx.modules import recon

    ports = {int(p) for p in ((recon.collect_ssh() or {}).get("ports") or []) if str(p).isdigit()}
    return ports or {22}


def _out_of_bounds(cfg: dict) -> list[str]:
    raw = cfg.get("out_of_bounds") or ""
    if raw.strip() in ("", "(ninguno)"):
        return []
    return [t.strip() for t in re.split(r"[,\s]+", raw) if t.strip()]


def protected_reason(finding: dict, cfg: dict | None = None) -> str | None:
    """Por qué este objetivo NO admite acción automática (None = sí la admite)."""
    cfg = cfg if cfg is not None else config.load_config()
    kind, target = finding.get("kind"), finding.get("target") or {}
    oob = _out_of_bounds(cfg)
    if kind == "listen_ports" and target.get("port"):
        port = int(target["port"])
        if port in ssh_ports():
            return "puerto SSH: bloquearlo te dejaría fuera del servidor"
        if str(port) in oob:
            return "puerto marcado fuera-de-límites"
    if kind in ("executables", "processes"):
        name = str(target.get("exe") or target.get("process") or "")
        base = name.rsplit("/", 1)[-1]
        if base in _PROTECTED_EXES or name == sys.executable:
            return f"proceso crítico ({base})"
        if any(t and t in name for t in oob):
            return "proceso marcado fuera-de-límites"
    path = str(target.get("path") or target.get("file") or "")
    if path and any(path.startswith(t) for t in oob if t.startswith("/")):
        return "ruta marcada fuera-de-límites"
    return None


# ── bloqueos activos con auto-expiración (Tier 1 reversible) ──────────────────
def _blocks_path():
    return config.state_dir() / "active_blocks.json"


def _load_blocks() -> list[dict]:
    return config.read_json(_blocks_path(), [])


def _save_blocks(blocks: list[dict]) -> None:
    config.write_json(_blocks_path(), blocks)


def register_block(finding: dict, revert: dict, ttl_min: int = DEFAULT_TTL_MIN, now=None) -> None:
    now = now or _now()
    blocks = _load_blocks()
    blocks.append(
        {
            "fp": fingerprint(finding),
            "detail": finding.get("detail"),
            "revert": revert,
            "applied_at": _iso(now),
            "expires_at": _iso(now + timedelta(minutes=ttl_min)),
        }
    )
    _save_blocks(blocks)


_LEGACY_REVERT = re.compile(r"^ufw delete deny (\d{1,5})/(tcp|udp)$")


def _revert_argv(revert) -> list[str] | None:
    """Comando de reversión validado. Solo formas conocidas: nunca se ejecuta texto libre."""
    if isinstance(revert, dict) and revert.get("tool") == "ufw":
        port, proto = revert.get("port"), revert.get("proto")
        if isinstance(port, int) and 0 < port < 65536 and proto in ("tcp", "udp"):
            return ["ufw", "delete", "deny", f"{port}/{proto}"]
        return None
    if isinstance(revert, dict) and revert.get("tool") == "nft":
        port, proto = revert.get("port"), revert.get("proto")
        if isinstance(port, int) and 0 < port < 65536 and proto in ("tcp", "udp"):
            return ["nft", "delete", "element", "inet", "arx", f"block_{proto}",
                    f"{{ {port} }}"]
        return None
    if isinstance(revert, str):  # formato antiguo (texto): solo si encaja exactamente
        m = _LEGACY_REVERT.match(revert)
        if m:
            return ["ufw", "delete", "deny", f"{m.group(1)}/{m.group(2)}"]
    return None


def _pids_for_exe(exe: str) -> list[int]:
    """PIDs cuyo ejecutable REAL (readlink de /proc/<pid>/exe) es `exe`.

    Jamás se empareja por nombre de proceso: dos binarios distintos pueden llamarse
    igual y el nombre lo pone el propio programa.
    """
    out = []
    try:
        entries = os.listdir("/proc")
    except OSError:
        return out
    for name in entries:
        if not name.isdigit():
            continue
        try:
            if os.readlink(f"/proc/{name}/exe") == exe:
                out.append(int(name))
        except OSError:
            continue  # murió entre listado y lectura, o sin permiso
    return out


def _apply_revert(revert) -> str | None:
    """Ejecuta una reversión y la describe. Solo formas conocidas: nunca texto libre."""
    argv = _revert_argv(revert)
    if argv:
        try:
            subprocess.run(argv, capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired):
            pass  # la herramienta ya no está; no romper el bucle de guardia
        return " ".join(argv)
    if isinstance(revert, dict) and revert.get("tool") == "sigstop":
        pids, exe = revert.get("pids"), revert.get("exe")
        if not (isinstance(exe, str) and exe.startswith("/") and isinstance(pids, list)
                and all(isinstance(p, int) and p > 1 for p in pids)):
            return None
        done = 0
        for pid in pids:
            try:
                # anti reutilización de PID: solo SIGCONT si sigue siendo el mismo binario
                if os.readlink(f"/proc/{pid}/exe") == exe:
                    os.kill(pid, signal.SIGCONT)
                    done += 1
            except OSError:
                continue
        return f"SIGCONT a {done} proceso(s) de {exe}"
    return None


def expire_blocks(now=None) -> list[dict]:
    """Revierte los bloqueos Tier 1 vencidos. En Linux+root ejecuta el revert real."""
    now = now or _now()
    with config.locked():
        keep, expired = [], []
        for b in _load_blocks():
            exp = _parse_dt(b.get("expires_at"))
            if exp and exp <= now:
                done = _apply_revert(b.get("revert")) if _is_linux_root() else None
                record({"kind": "block_expired", "detail": b.get("detail"), "reverted": done})
                expired.append(b)
            else:
                keep.append(b)
        if expired:
            _save_blocks(keep)
            st = load_findings()
            for b in expired:  # si reaparece, ya no se re-bloquea: escala al humano
                if b.get("fp") in st:
                    st[b["fp"]]["blocked_before"] = True
            _save_findings(st)
    return expired


def _active_block(fp: str, now=None) -> dict | None:
    now = now or _now()
    for b in _load_blocks():
        exp = _parse_dt(b.get("expires_at"))
        if b.get("fp") == fp and exp and exp > now:
            return b
    return None


# ── freno de seguridad ───────────────────────────────────────────────────────
def _actions_path():
    return config.state_dir() / "tier1_actions.json"


def recent_actions(now=None) -> list[str]:
    now = now or _now()
    cutoff = now - timedelta(hours=1)
    return [t for t in config.read_json(_actions_path(), [])
            if (_parse_dt(t) or cutoff) > cutoff]


def breaker_tripped(now=None) -> bool:
    return len(recent_actions(now)) >= MAX_TIER1_PER_HOUR


def _note_action(now=None) -> None:
    now = now or _now()
    config.write_json(_actions_path(), recent_actions(now) + [_iso(now)])


# ── cola de acciones Tier 2 pendientes de autorización humana ─────────────────
def _pending_path():
    return config.state_dir() / "pending_tier2.json"


def _load_pending() -> list[dict]:
    return config.read_json(_pending_path(), [])


def _save_pending(pend: list[dict]) -> None:
    config.write_json(_pending_path(), pend)


def _add_pending(finding: dict, plan: dict) -> str:
    pid = fingerprint(finding)[:6]  # estable por amenaza → dedup natural
    pend = _load_pending()
    if not any(p["id"] == pid for p in pend):
        pend.append(
            {
                "id": pid,
                "sev": finding.get("sev"),
                "detail": finding.get("detail", ""),
                "remediation": plan["action"],
                "at": _iso(_now()),
            }
        )
        _save_pending(pend)
    return pid


def list_pending() -> list[dict]:
    return _load_pending()


def authorize_pending(pid: str) -> dict | None:
    """Quita el pendiente de la cola y lo registra como autorizado. Devuelve el item o None."""
    with config.locked():
        pend = _load_pending()
        item = next((p for p in pend if p["id"] == pid), None)
        if item is None:
            return None
        _save_pending([p for p in pend if p["id"] != pid])
    record({"kind": "tier2_authorized", "detail": item["detail"], "remediation": item["remediation"]})
    return item


def forget(fp: str) -> dict | None:
    """Olvida un hallazgo aceptado (y su pendiente Tier 2). Devuelve la entrada o None."""
    with config.locked():
        st = load_findings()
        entry = st.pop(fp, None)
        if entry is None:
            return None
        _save_findings(st)
        _save_pending([p for p in _load_pending() if p["id"] != fp[:6]])
    return entry


# ── ejecución Tier 1 ─────────────────────────────────────────────────────────
def _ufw_active() -> bool:
    try:
        r = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return False
    first = (r.stdout.splitlines() or [""])[0].lower()
    return r.returncode == 0 and "inactive" not in first and "inactivo" not in first


def _nft_available() -> bool:
    return shutil.which("nft") is not None


def _nft_setup() -> bool:
    """Tabla/set/cadena de Arx en nftables, idempotente (ignora 'ya existe')."""
    try:
        ruleset = subprocess.run(["nft", "list", "ruleset"], capture_output=True,
                                 text=True, timeout=15).stdout
    except (OSError, subprocess.TimeoutExpired):
        return False
    cmds = []
    if "table inet arx" not in ruleset:
        cmds.append(["nft", "add", "table", "inet", "arx"])
    if "block_tcp" not in ruleset:
        cmds += [["nft", "add", "set", "inet", "arx", "block_tcp",
                  "{", "type", "inet_service;", "flags", "timeout;", "}"],
                 ["nft", "add", "set", "inet", "arx", "block_udp",
                  "{", "type", "inet_service;", "flags", "timeout;", "}"]]
    if "chain input" not in ruleset.split("table inet arx")[-1]:
        cmds.append(["nft", "add", "chain", "inet", "arx", "input",
                     "{", "type", "filter", "hook", "input", "priority", "0;",
                     "policy", "accept;", "}"])
    if "tcp dport @block_tcp" not in ruleset:
        cmds += [["nft", "add", "rule", "inet", "arx", "input", "tcp", "dport",
                  "@block_tcp", "drop"],
                 ["nft", "add", "rule", "inet", "arx", "input", "udp", "dport",
                  "@block_udp", "drop"]]
    for argv in cmds:
        try:
            subprocess.run(argv, capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired):
            return False
    return True


def _execute_tier1(finding: dict) -> tuple[str, dict | None]:
    """Ejecuta una remediación Tier 1 reversible SOLO en Linux+root.

    Devuelve (status, revert). Fuera de Linux+root NO finge: informa que queda listo para
    ejecutar en el destino. Nunca hace nada irreversible.
    """
    if not _is_linux_root():
        return "listo para ejecutar en destino (requiere Linux + root)", None
    kind = finding.get("kind")
    target = finding.get("target") or {}
    if kind == "listen_ports" and target.get("port"):
        proto, port = target.get("proto", "tcp"), int(target["port"])
        if shutil.which("ufw") and _ufw_active():
            r = subprocess.run(["ufw", "deny", f"{port}/{proto}"],
                               capture_output=True, text=True, timeout=15)
            if r.returncode == 0:
                revert = {"tool": "ufw", "port": port, "proto": proto}
                register_block(finding, revert)
                return (f"puerto {port}/{proto} bloqueado en ufw "
                        f"(auto-expira en {DEFAULT_TTL_MIN} min)"), revert
            return f"no se pudo bloquear el puerto ({r.stderr.strip()[:48]})", None
        if _nft_available():
            # hosts sin ufw: nftables con timeout NATIVO (el set expira solo aunque Arx caiga)
            if not _nft_setup():
                return "nftables presente pero no se pudo preparar la tabla arx", None
            r = subprocess.run(["nft", "add", "element", "inet", "arx", f"block_{proto}",
                                f"{{ {port} timeout {DEFAULT_TTL_MIN}m }}"],
                               capture_output=True, text=True, timeout=15)
            if r.returncode == 0:
                revert = {"tool": "nft", "port": port, "proto": proto}
                register_block(finding, revert)
                return (f"puerto {port}/{proto} bloqueado en nftables "
                        f"(timeout nativo {DEFAULT_TTL_MIN} min + reversión de Arx)"), revert
            return f"nft falló al bloquear ({r.stderr.strip()[:48]})", None
        if shutil.which("ufw"):
            # `ufw deny` "funciona" con ufw apagado pero no filtra nada → no fingir contención
            return "ufw está INACTIVO: un bloqueo no tendría efecto (actívalo o decide tú)", None
        return "sin ufw ni nftables: no hay ejecutor seguro de bloqueo en este host", None
    if kind in ("executables", "processes"):
        exe = str(target.get("exe") or target.get("process") or "")
        if not exe.startswith("/"):
            # suspender por NOMBRE es inseguro (match erróneo) → se propone, no se auto-ejecuta
            return "sin ruta de ejecutable resuelta: no se suspende por nombre", None
        base = exe.rsplit("/", 1)[-1]
        if base in _PROTECTED_EXES:
            return f"proceso crítico ({base}): jamás se suspende", None
        pids = [p for p in _pids_for_exe(exe) if p > 1 and p != os.getpid()]
        if not pids:
            return "el proceso ya no está vivo: nada que suspender", None
        stopped = 0
        for pid in pids:
            try:
                os.kill(pid, signal.SIGSTOP)
                stopped += 1
            except OSError:
                continue
        if not stopped:
            return "no se pudo suspender (carrera o permisos)", None
        revert = {"tool": "sigstop", "exe": exe, "pids": pids}
        register_block(finding, revert)
        return (f"proceso suspendido ({stopped} pid) — SIGCONT automático al expirar "
                f"({DEFAULT_TTL_MIN} min)"), revert
    if kind == "canary":
        return "nivel de alerta elevado y contexto capturado", None
    return "propuesta (sin ejecutor automático seguro para este tipo)", None


def handle(finding: dict, enforce: bool = False, authorized: bool = False,
           cfg: dict | None = None, now=None) -> dict:
    """Decide y registra la respuesta a un hallazgo. Devuelve el desenlace.

    `outcome["new"]` es True solo la primera vez que se ve esta amenaza: es la señal que
    usan las alertas y el motor LLM para no repetirse cada barrido.
    """
    now = now or _now()
    plan = classify(finding)
    tier = plan["tier"]
    fp = fingerprint(finding)
    outcome = {
        "fp": fp,
        "sev": finding.get("sev"),
        "detail": finding.get("detail"),
        "tier": tier,
        "remediation": plan["action"],
        "reversible": plan["reversible"],
    }
    with config.locked():
        st = load_findings()
        entry = st.get(fp)
        outcome["new"] = entry is None
        entry = entry or {"first_seen": _iso(now), "seen": 0, "kind": finding.get("kind"),
                          "detail": finding.get("detail"), "set": finding.get("set"),
                          "item": finding.get("item")}
        entry["seen"] += 1
        entry["last_seen"] = _iso(now)

        reason = protected_reason(finding, cfg) if tier == 1 else None
        if tier == 0:
            status = "observado y registrado"
        elif tier == 1 and reason:
            outcome["tier"] = 0
            status = f"protegido ({reason}) — solo se observa"
        elif tier == 1 and entry.get("blocked_before"):
            outcome["tier"] = 2
            pid = _add_pending(finding, {"action": f"{plan['action']} — REAPARECIÓ tras expirar el bloqueo"})
            outcome["pending_id"] = pid
            status = f"reapareció tras expirar el bloqueo → decide tú: arx authorize {pid}  ·  o acepta: arx accept {fp}"
        elif tier == 1 and not enforce:
            status = "propuesta auto — activa --enforce para aplicar"
        elif tier == 1 and (blk := _active_block(fp, now)):
            status = f"ya contenido (bloqueo activo hasta {blk['expires_at'][11:16]} UTC)"
        elif tier == 1 and breaker_tripped(now):
            status = (f"FRENO DE SEGURIDAD: ya hubo {MAX_TIER1_PER_HOUR} acciones automáticas en la "
                      "última hora → solo observo")
        elif tier == 1:
            status, revert = _execute_tier1(finding)
            if revert:
                outcome["revert"] = revert
                _note_action(now)
        elif authorized:
            status = "autorizada por palabra ✓"
        else:  # tier 2
            pid = _add_pending(finding, plan)
            outcome["pending_id"] = pid
            status = f"PENDIENTE (id {pid}) — autoriza con: arx authorize {pid}"
        outcome["status"] = status

        changed = entry.get("status") != status
        entry["status"] = status
        st[fp] = entry
        _save_findings(st)
    if outcome["new"] or changed:  # registrar solo lo nuevo o lo que cambia, no cada barrido
        record({"kind": "incident", **outcome})
    return outcome
