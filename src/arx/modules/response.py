"""Arx · response — motor de respuesta por niveles.

Cada hallazgo recibe SIEMPRE atención Tier 0 (registro + evidencia + alerta). Además
se propone una remediación con su nivel:

  Tier 0  observar/registrar          — siempre, sin autorización
  Tier 1  auto, REVERSIBLE, auto-expira — se aplica si `--enforce` está activo
  Tier 2  humano + palabra             — nunca automático (irreversible/sensible)

"Voluntad de acero" = Tier 0/1 sin fatiga; lo irreversible es del humano, con UNA excepción
decidida por el dueño del producto: si el modelo confirma como amenaza una cuenta que la capa
determinista ya señaló, se bloquea y se cierran sus sesiones sin esperar (`apply_verdicts`). El
modelo lee datos que controla el atacante, así que nunca elige a quién: solo confirma, y lo
acotan salvaguardas por código. Un bloqueo de cuenta no caduca: lo levanta una persona.

Salvaguardas contra el auto-daño (una defensa que tumba su propio servidor es peor que
ninguna):
  · Memoria por hallazgo (huella estable): lo ya visto no se re-ejecuta ni se re-registra
    cada barrido; solo cuenta lo NUEVO o lo que cambia de estado.
  · Intocables: el puerto SSH, PID 1, el propio Arx y lo que el operador marcó como
    fuera-de-límites nunca reciben una acción automática — solo se observan.
  · Un bloqueo que expira y cuyo hallazgo REAPARECE no se re-bloquea en bucle: escala a
    Tier 2 (lo decide el humano).
  · Freno de seguridad: más de MAX_TIER1_PER_HOUR acciones automáticas en una hora →
    Arx deja de actuar y solo observa (algo raro pasa, o es él quien se equivoca). Los
    hallazgos críticos tienen un cupo aparte: agotar el freno a propósito no debe dejar sin
    respuesta a un reverse shell.

Nota de honestidad: la EJECUCIÓN real de acciones de sistema requiere Linux + root en el
host destino. Fuera de eso se decide y se registra el plan, nunca se finge hecho.
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

from arx import config
from arx.i18n import tr
from arx.modules import recon
from arx.redact import printable

DEFAULT_TTL_MIN = 60  # los bloqueos Tier 1 auto-expiran (reversibles por doctrina)
MAX_QUARANTINE_BYTES = 1024 * 1024 * 1024
MAX_TIER1_PER_HOUR = 5
CRIT_RESERVE = 3       # cupo extra, solo para hallazgos críticos
LLM_LOCK_MIN_CONFIDENCE = 70   # "sospecha considerable": por debajo, decide el humano
MAX_LLM_LOCKS_PER_HOUR = 2     # freno propio: el modelo puede estar siendo manipulado

# kind → (tier, acción de remediación, reversible, por qué ese nivel)
_PLAN: dict[str, tuple[int, str, bool, str]] = {
    "integrity": (2, tr("revert the critical file to a known good copy"), True,
                  tr("altering credentials or system files is sensitive → needs your word")),
    "listen_ports": (1, tr("block the port in the firewall (temporary, auto-expires)"), True,
                     tr("blocking a port is reversible and contains new exposure")),
    "executables": (1, tr("suspend the process (SIGSTOP) for analysis"), True,
                    tr("suspending is reversible (SIGCONT); it does not destroy evidence")),
    "processes": (1, tr("suspend the process (SIGSTOP) for analysis"), True,
                  tr("suspending is reversible (SIGCONT); it does not destroy evidence")),
    "login_users": (2, tr("lock all access for the account and close its sessions (it does not "
                          "unlock on its own)"), False,
                    tr("a new connected account may be a legitimate admin → needs your word or the "
                       "model confirming it as a threat; a closed session cannot be recovered, and "
                       "root and system accounts are never touched")),
    "suid_new": (2, tr("remove its SUID bit (chmod u-s); the file stays as evidence"), True,
                 tr("a new SUID gives root to whoever runs it, but it may come from a package → "
                    "needs your word")),
    "uid0_account": (2, tr("lock that account (password and SSH key); root is not affected"), True,
                     tr("it may be legitimate → needs your word; if it is, accept it with arx "
                        "accept")),
    "canary": (1, tr("raise the alert level and capture the context of the canary access"), True,
               tr("a touched canary is a strong sign of an intruder; raising and capturing is "
                  "reversible")),
    "intel_ip": (1, tr("block the IP in the firewall (temporary, auto-expires)"), True,
                 tr("it comes from a vaccine validated on this host: blocking it is reversible")),
    "port_scan": (1, tr("block the source IP in the firewall (temporary, auto-expires)"), True,
                  tr("cutting reconnaissance is reversible and touches nothing local")),
    "auth_bruteforce": (1, tr("block the source IP in the firewall (temporary, auto-expires)"), True,
                        tr("stops the brute force without touching the attacked account (that is "
                           "Tier 2)")),
    "reverse_shell": (1, tr("block the C2 channel in nftables and suspend the owning process "
                            "(auto-expires)"), True,
                      tr("both actions undo themselves on expiry: no evidence destroyed, no flow "
                         "lost")),
    "log_tamper": (0, tr("log and alert: someone is wiping traces"), True,
                   tr("wiping logs is a sign of an intruder INSIDE: observe and escalate, do not "
                      "act blindly")),
    "gauge": (0, tr("log and watch the trend"), True, tr("weak signal; observe first")),
    "egress_profile": (0, tr("cut in the kernel at its first packet; the service keeps running"), True,
                       tr("outside the behavior Arx observed for it; if it is legitimate, accept it")),
    "unexpected_exec": (1, tr("isolate that process: no network, and suspended if there are signs of harm"), True,
                        tr("a program its service never started: the service keeps running")),
    "self_tamper": (0, tr("log and alert outside the host"), True,
                    tr("someone changed Arx itself: it may be an attempt to blind it")),
    "update_check": (0, tr("log and alert"), True,
                     tr("an update many services load: checked first, cut only with an untrusted verdict")),
    "untrusted_update": (1, tr("confine the service: no outbound network, it keeps running (until you decide)"),
                         True, tr("a signed update below the minimum trust: cutting its network stops a backdoor "
                                  "from calling home without stopping the service")),
    "profile_extended": (0, tr("log and alert"), True, tr("Arx keeps observing while it has doubts")),
    "profile_doc": (0, tr("log and alert"), True, tr("the model compared what it did with its documentation")),
    "firewall_reset": (0, tr("log and alert: active containment was already put back"), True,
                       tr("it may be a legitimate reboot: your call")),
}

# Procesos que jamás se suspenden automáticamente (dejarían el host inaccesible o a Arx ciego).
_PROTECTED_EXES = {"sshd", "systemd", "init", "dbus-daemon", "journald", "systemd-journald",
                   "auditd", "falco", "osqueryd", "python3", "arx"}

_SSHD_EXES = ("sshd", "sshd-session")
_SSH_SESSION_RE = re.compile(r"sshd(?:-session)?: [^\s@]+@\S+")

# Nombre de cuenta válido (login POSIX). Clave de seguridad: un valor que empiece por "-"
# NO casa → imposible colar una opción a `usermod` por el nombre de la cuenta.
_USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


def classify(finding: dict) -> dict:
    kind = finding.get("kind")
    prov = finding.get("provenance")
    # Procedencia probada (decisión D): paquete de un repositorio firmado, intacto y, si atiende la
    # red, arrancado por su propio unit. Se avisa y no se toca.
    if prov and prov.get("verified") and kind in ("listen_ports", "executables", "processes"):
        return {"tier": 0, "action": tr("log and alert (verified package)"), "reversible": True,
                "why": prov.get("reason", "")}
    # Sin esa prueba y sin señales de daño (decisión E): sigue funcionando, pero sin salir a la red.
    # Así una puerta trasera no llama a casa, y tu programa no se para. Lo decide una persona.
    if kind in ("executables", "processes") and prov is not None and not finding.get("harm"):
        return {"tier": 1, "confine": True, "reversible": True,
                "action": tr("confine it: no outbound network, it keeps running (until you decide)"),
                "why": tr("unproven origin and no sign of harm: cutting its network stops a backdoor "
                          "from calling home without stopping your program")}
    # Desde fuera no se llega a un puerto solo en localhost: bloquearlo no protege nada y rompe
    # lo que lo use (una base de datos local, un panel detrás de un proxy).
    if finding.get("kind") == "listen_ports" and (finding.get("target") or {}).get("exposed") == "local":
        return {"tier": 0, "action": tr("log and watch (local-only port)"), "reversible": True,
                "why": tr("not exposed to the network: a block would contain nothing")}
    # Un binario de sistema no visto al aprender es lo normal (un admin, una actualización).
    # Suspenderlo congelaría TODOS sus procesos, incluida la shell del operador (B9).
    if kind in ("executables", "processes") and finding.get("sev") == "low" and prov is None:
        return {"tier": 0, "action": tr("log and watch (new system binary)"),
                "reversible": True, "why": tr("low-confidence signal: it does not justify "
                                              "suspending anything")}
    tier, action, reversible, why = _PLAN.get(
        finding.get("kind", ""), (0, tr("log and watch"), True, tr("weak signal; observe first"))
    )
    return {"tier": tier, "action": action, "reversible": reversible, "why": why}


def fingerprint(finding: dict) -> str:
    """Huella estable de un hallazgo: misma amenaza → misma huella entre barridos."""
    basis = finding.get("fp_key") or f"{finding.get('kind', '')}|{finding.get('detail', '')}"
    return hashlib.sha1(basis.encode("utf-8", "surrogateescape")).hexdigest()[:10]


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
    """Al registro de incidentes, nunca un secreto: claves de API, licencia, token del bot (DoD-9)."""
    import json

    from arx import redact
    entry = {"at": _iso(_now()), **{k: redact.scrub(v) if isinstance(v, str) else v for k, v in entry.items()}}
    fd = os.open(_incidents_path(), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8", errors="backslashreplace") as f:
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
    if raw.strip() in ("", "(none)", "(ninguno)"):
        return []
    return [t.strip() for t in re.split(r"[,\s]+", raw) if t.strip()]


def _never_block_ips() -> set[str]:
    """IPs que JAMÁS reciben un bloqueo automático.

    · Las propias del host (bloquear tu interfaz es un auto-daño absurdo).
    · Las del OPERADOR: una sesión SSH AUTENTICADA y PERSISTENTE (vista en ≥2 decisiones).
      Proteger "cualquiera conectado al 22" sería un interruptor de evasión: bastaba un
      `nc host 22` sin autenticar, que sshd mantiene vivo 2 minutos, para volverse intocable
      y seguir con la fuerza bruta (B29). Solo cuenta el proceso de una sesión ya abierta.
    """
    out = set(recon.local_ips())
    ssh = ssh_ports()
    current = {c["remote_ip"] for c in recon.connection_owners()
               if c.get("state") == "ESTABLISHED" and c.get("local_port") in ssh
               and (c.get("exe") or "").rsplit("/", 1)[-1] in _SSHD_EXES
               and isinstance(c.get("pid"), int) and _is_ssh_session(c["pid"])}
    path = config.state_dir() / "ssh-peers.json"
    peers = config.read_json(path, {})
    now = _now().timestamp()
    peers = {ip: p for ip, p in peers.items() if now - p.get("last", 0) < 900}
    for ip in current:
        p = peers.setdefault(ip, {"seen": 0, "last": now})
        p["seen"] += 1
        p["last"] = now
    config.write_json(path, peers)
    return out | {ip for ip, p in peers.items() if ip in current and p["seen"] >= 2}


def _proc_title(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return f.read(200).replace(b"\0", b" ").decode("utf-8", "replace")
    except OSError:
        return ""


def _is_ssh_session(pid: int) -> bool:
    """`sshd: ana@pts/0`, `sshd: ana@notty`: sshd solo se pone ese título tras autenticar. Antes
    es `sshd: [accepted]`, `sshd: unknown [net]` o `sshd: root [priv]`."""
    return _SSH_SESSION_RE.match(_proc_title(pid)) is not None


def protected_reason(finding: dict, cfg: dict | None = None) -> str | None:
    """Por qué este objetivo NO admite acción automática (None = sí la admite)."""
    cfg = cfg if cfg is not None else config.load_config()
    kind, target = finding.get("kind"), finding.get("target") or {}
    oob = _out_of_bounds(cfg)
    if kind == "listen_ports" and target.get("port"):
        port = int(target["port"])
        if port in ssh_ports():
            return tr("SSH port: blocking it would lock you out of the server")
        if str(port) in oob:
            return tr("port marked out-of-bounds")
    if kind in ("port_scan", "auth_bruteforce", "intel_ip") and target.get("ip"):
        ip = str(target["ip"])
        if ip in _never_block_ips():
            return tr("untouchable IP (the host's own or with an active operator session)")
        if ip in oob:
            return tr("IP marked out-of-bounds")
    if kind == "reverse_shell":
        ip = str(target.get("ip") or "")
        if ip and ip in _never_block_ips():
            return tr("the peer is untouchable (the host's own or an operator session)")
        if ip in oob:
            return tr("IP marked out-of-bounds")
        exe = str(target.get("exe") or "")
        base = exe.rsplit("/", 1)[-1]
        if base in _PROTECTED_EXES or exe == sys.executable:
            return tr("critical process ({base}): observed only", base=base)
    if kind == "unexpected_exec" and target.get("alert_only") and not target.get("stopped"):
        return str(target.get("alert_reason") or "") or \
            tr("sshd's configuration could not be read with certainty: alert only, nothing frozen")
    if kind == "untrusted_update":
        unit = str(target.get("unit") or "")
        if _PROTECTED_UNITS.match(unit) and not _SSH_UNIT_RE.match(unit):  # ssh: sin salida, con excepciones
            return tr("critical service ({unit}): it is not confined on its own", unit=unit)
        if target.get("alert_only"):
            return tr("updater, clock or container service ({unit}): alert only", unit=unit)
        if any(t and t in unit for t in oob):
            return tr("service marked out-of-bounds")
    if kind in ("executables", "processes"):
        name = str(target.get("exe") or target.get("process") or "")
        base = name.rsplit("/", 1)[-1]
        if base in _PROTECTED_EXES or name == sys.executable:
            return tr("critical process ({base})", base=base)
        if any(t and t in name for t in oob):
            return tr("process marked out-of-bounds")
    path = str(target.get("path") or target.get("file") or "")
    if path and any(path.startswith(t) for t in oob if t.startswith("/")):
        return tr("path marked out-of-bounds")
    return None


# ── bloqueos activos con auto-expiración (Tier 1 reversible) ──────────────────
def _blocks_path():
    return config.state_dir() / "active_blocks.json"


def _load_blocks() -> list[dict]:
    return config.read_json(_blocks_path(), [])


def _save_blocks(blocks: list[dict]) -> None:
    config.write_json(_blocks_path(), blocks)


def register_block(finding: dict, revert: dict, ttl_min: int | None = DEFAULT_TTL_MIN, now=None) -> None:
    now = now or _now()
    blocks = _load_blocks()
    blocks.append(
        {
            "fp": fingerprint(finding),
            "detail": finding.get("detail"),
            "revert": revert,
            **({"origin_of": finding["origin_of"]} if finding.get("origin_of") else {}),
            "applied_at": _iso(now),
            "expires_at": None if ttl_min is None else _iso(now + timedelta(minutes=ttl_min)),
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
    if isinstance(revert, dict) and revert.get("tool") == "nft_ip":
        try:
            fam = ipaddress.ip_address(str(revert.get("ip", ""))).version
        except ValueError:
            return None
        return ["nft", "delete", "element", "inet", "arx", f"block_ipv{fam}",
                f"{{ {revert['ip']} }}"]
    if isinstance(revert, dict) and revert.get("tool") == "ufw_ip":
        try:
            ipaddress.ip_address(str(revert.get("ip", "")))
        except ValueError:
            return None
        return ["ufw", "delete", "deny", "from", str(revert["ip"])]
    if isinstance(revert, dict) and revert.get("tool") == "nft_c2":
        port = revert.get("port")
        try:
            fam = ipaddress.ip_address(str(revert.get("ip", ""))).version
        except ValueError:
            return None
        if not (isinstance(port, int) and 0 < port < 65536):
            return None
        return ["nft", "delete", "element", "inet", "arx", f"c2_out{fam}",
                f"{{ {revert['ip']} . {port} }}"]
    if isinstance(revert, dict) and revert.get("tool") == "nft_tarpit":
        try:
            fam = ipaddress.ip_address(str(revert.get("ip", ""))).version
        except ValueError:
            return None
        return ["nft", "delete", "element", "inet", "arx", f"tarpit{fam}",
                f"{{ {revert['ip']} }}"]
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
            # un dropper que se borra a sí mismo sigue vivo con exe "ruta (deleted)"
            if os.readlink(f"/proc/{name}/exe").removesuffix(" (deleted)") == exe:
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
                if os.readlink(f"/proc/{pid}/exe").removesuffix(" (deleted)") == exe:
                    os.kill(pid, signal.SIGCONT)
                    done += 1
            except OSError:
                continue
        return tr("SIGCONT to {done} process(es) of {exe}", done=done, exe=exe)
    if isinstance(revert, dict) and revert.get("tool") == "confine":
        return _release_confinement(revert)
    if isinstance(revert, dict) and revert.get("tool") == "usermod":
        import pwd

        user, uid = revert.get("user"), revert.get("uid")
        expire = str(revert.get("expire") or "")
        if not (isinstance(user, str) and _USERNAME_RE.fullmatch(user) and isinstance(uid, int)
                and (expire == "" or expire.isdigit())):
            return None
        try:
            # anti recreación de cuenta: solo se desbloquea si sigue siendo el mismo uid
            if pwd.getpwnam(user).pw_uid != uid:
                return tr("account '{user}' was recreated with another uid: not unlocked",
                          user=user)
        except KeyError:
            return tr("account '{user}' no longer exists: nothing to unlock", user=user)
        # se restaura el estado PREVIO: una cuenta que el admin ya tenía bloqueada sigue así
        argv = ["usermod", "-e", expire, user]
        if not revert.get("was_locked"):
            argv.insert(1, "-U")
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired):
            return tr("could not restore account '{user}': usermod did not respond", user=user)
        if r.returncode != 0:
            return tr("could not restore account '{user}' ({v})",
                      user=user, v=r.stderr.strip()[:60])
        return tr("{argv} (previous account state restored)", argv=' '.join(argv))
    return None


def _is_account_lock(block: dict) -> bool:
    revert = block.get("revert")
    return isinstance(revert, dict) and revert.get("tool") == "usermod"


def _holds_until_human(block: dict) -> bool:
    """No caduca: lo levanta una persona, nunca el reloj. Un bloqueo de cuenta (`arx unlock`), y un
    confinamiento (`arx accept`): este no para el programa, así que no hay prisa por soltarlo.
    Se decide por el tipo y no por la fecha: la v0.0.2 registró los de cuenta con caducidad."""
    revert = block.get("revert")
    return _is_account_lock(block) or (isinstance(revert, dict) and revert.get("tool") == "confine")


def _until(block: dict) -> str:
    if _holds_until_human(block):
        return tr("until you decide")
    return tr("until {v} UTC", v=str(block.get('expires_at'))[11:16])


def expire_blocks(now=None) -> list[dict]:
    """Revierte los bloqueos Tier 1 vencidos. En Linux+root ejecuta el revert real."""
    now = now or _now()
    with config.locked():
        keep, expired = [], []
        for b in _load_blocks():
            exp = _parse_dt(b.get("expires_at"))
            if exp and exp <= now and not _holds_until_human(b):
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


def _lock_of(finding: dict) -> dict | None:
    """El bloqueo vigente de la cuenta de este hallazgo, aunque venga de otro origen."""
    if finding.get("kind") != "login_users":
        return None
    user = str((finding.get("target") or {}).get("user") or "").partition("@")[0]
    return next((b for b in _load_blocks() if _is_account_lock(b) and b["revert"].get("user") == user), None)


def _active_block(fp: str, now=None) -> dict | None:
    now = now or _now()
    for b in _load_blocks():
        exp = _parse_dt(b.get("expires_at"))
        if b.get("fp") == fp and (_holds_until_human(b) or (exp and exp > now)):
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


def breaker_tripped(now=None, sev: str | None = None) -> bool:
    limit = MAX_TIER1_PER_HOUR + (CRIT_RESERVE if sev == "crit" else 0)
    return len(recent_actions(now)) >= limit


def _note_action(now=None) -> None:
    now = now or _now()
    config.write_json(_actions_path(), recent_actions(now) + [_iso(now)])


# ── vault: respaldo de ficheros críticos y cuarentena ─────────────────────────
def _vault_dir():
    d = config.state_dir() / "vault"
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    return d


def _vault_manifest_path():
    return _vault_dir() / "manifest.json"


def backup_critical(paths: dict[str, list[str]]) -> int:
    """Copia los ficheros cubiertos por integridad al vault (0600, solo root).

    Sin copia buena conocida no hay restauración posible: se hace al sellar la base.
    Devuelve cuántos ficheros quedaron respaldados (nuevos o cambiados).
    """
    manifest = config.read_json(_vault_manifest_path(), {})
    n = 0
    for key, files in paths.items():
        for path in files:
            try:
                data = open(path, "rb").read()
                st = os.stat(path)
            except OSError:
                continue
            h = hashlib.sha256(data).hexdigest()
            entry = manifest.get(path)
            if entry and entry.get("sha256") == h:
                continue
            q = _vault_dir() / f"{hashlib.sha1(path.encode()).hexdigest()[:12]}.bak"
            fd = os.open(q, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            manifest[path] = {"key": key, "sha256": h, "mode": st.st_mode & 0o777,
                              "backed_at": _iso(_now())}
            n += 1
    config.write_json(_vault_manifest_path(), manifest)
    return n


def quarantine_file(path: str, source: str | None = None) -> str | None:
    """Mueve un fichero al vault en cuarentena (evidencia preservada). Devuelve su ruta.

    `source` es de dónde leerlo si ya no está en `path`: un dropper que se borró a sí mismo solo
    sigue en /proc/<pid>/exe. Lo que controla el atacante no debe colgar a Arx: un FIFO en la ruta
    bloquearía `open()` para siempre, y un fichero enorme llenaría el disco de evidencia.
    """
    try:
        fd = os.open(source or path, os.O_RDONLY | os.O_NONBLOCK)
    except OSError:
        return None
    digest = hashlib.sha256()
    q = _vault_dir() / (f"q-{_now().strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(2)}-"
                        f"{os.path.basename(path)[:100]}")
    with os.fdopen(fd, "rb") as src:
        st = os.fstat(src.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_QUARANTINE_BYTES:
            return None
        out = os.open(q, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(out, "wb") as dst:
            while chunk := src.read(1024 * 1024):
                digest.update(chunk)
                dst.write(chunk)
    manifest = config.read_json(_vault_manifest_path(), {})
    manifest[str(q)] = {"quarantined_from": path, "sha256": digest.hexdigest(),
                        "mode": st.st_mode & 0o777, "at": _iso(_now())}
    config.write_json(_vault_manifest_path(), manifest)
    try:
        os.unlink(path)  # el fichero hostil sale de su sitio
    except OSError:
        pass
    return str(q)


def list_quarantine() -> list[dict]:
    manifest = config.read_json(_vault_manifest_path(), {})
    return [{"id": os.path.basename(q), "origin": m.get("quarantined_from"), "sha256": m.get("sha256"),
             "at": m.get("at")} for q, m in manifest.items() if m.get("quarantined_from")]


def restore_quarantined(qid: str) -> str | None:
    """Devuelve un fichero de la cuarentena a su sitio (la palabra la verifica el llamador).

    Nunca pisa lo que haya ahora en esa ruta. None si no hay nada con ese id.
    """
    with config.locked():
        manifest = config.read_json(_vault_manifest_path(), {})
        q = next((k for k, m in manifest.items()
                  if os.path.basename(k) == qid and m.get("quarantined_from")), None)
        if q is None:
            return None
        meta = manifest[q]
        dest = meta["quarantined_from"]
        if os.path.lexists(dest):
            return tr("{dest} already exists: not overwritten. Move it first if you want this one "
                      "back", dest=printable(dest))
        try:
            with open(q, "rb") as src:
                out = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(out, "wb") as dst:
                    shutil.copyfileobj(src, dst)
            os.chmod(dest, int(meta.get("mode", 0o600)))
            os.unlink(q)
        except OSError as e:
            return tr("could not restore {dest} ({strerror})",
                      dest=printable(dest), strerror=e.strerror)
        del manifest[q]
        config.write_json(_vault_manifest_path(), manifest)
    done = tr("restored to {dest}", dest=printable(dest))
    record({"kind": "quarantine_restored", "detail": dest, "result": done})
    return done


def _kill_and_quarantine(finding: dict) -> str:
    """Termina un proceso y guarda su binario como evidencia. Lo autoriza un humano: es lo que
    queda cuando suspenderlo no bastó (reapareció). El fichero se recupera con `arx restore`."""
    from arx.modules import baseline  # perezoso: baseline importa response (gancho de sellado)

    target = finding.get("target") or {}
    exe = str(target.get("exe") or target.get("process") or "")
    if not exe.startswith("/"):
        return tr("no resolved executable path: nothing is killed by name")
    base = exe.rsplit("/", 1)[-1]
    if base in _PROTECTED_EXES or exe == sys.executable:
        return tr("critical process ({base}): never killed", base=base)
    pids = [p for p in _pids_for_exe(exe) if p > 1 and p != os.getpid()]
    parts = []
    if exe.startswith(baseline._SYSTEM_DIRS):
        parts.append(tr("lives in a system directory: the file is not touched"))
    else:
        # primero la evidencia: si se borró a sí mismo, al morir se pierde con él
        source = f"/proc/{pids[0]}/exe" if pids and not os.path.exists(exe) else None
        q = quarantine_file(exe, source=source)
        parts.append(tr("file quarantined (recover it with: arx restore {q})",
                        q=os.path.basename(q)) if q
                     else tr("the file could not be quarantined"))
    killed = 0
    for pid in pids:
        try:
            os.kill(pid, signal.SIGKILL)
            killed += 1
        except OSError:
            continue
    parts.insert(0, tr("{killed} process(es) terminated", killed=killed) if pids else tr("no process left alive"))
    return " · ".join(parts)


def _drop_suid(path: str) -> str:
    """Quita el bit SUID sin borrar nada: deja de dar root y sigue ahí como evidencia."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as e:
        return tr("could not open {path} ({strerror})", path=printable(path), strerror=e.strerror)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return tr("{path} is no longer a regular file: not touched", path=printable(path))
        os.fchmod(fd, stat.S_IMODE(st.st_mode) & ~0o6000)
    except OSError as e:
        return tr("could not change {path} ({strerror})", path=printable(path), strerror=e.strerror)
    finally:
        os.close(fd)
    return tr("SUID bit removed from {path}: it no longer gives privileges. If it was legitimate: "
              "chmod u+s", path=printable(path))


def _restore_from_vault(key: str, current_files: list[str] | None = None) -> str:
    """Restaura el estado sellado de una clave de integridad desde el vault.

    Dos casos, ambos con evidencia preservada:
      · fichero CON copia buena alterado o ausente → cuarentena de la versión hostil
        (si existe) + restauración del respaldo con su modo original;
      · fichero SIN copia buena presente ahora bajo la clave → no existía al sellar:
        es un intruso (persistencia plantada) → cuarentena directa, no hay nada que
        restaurar.

    Lo intacto no se toca: restaurar ficheros que no cambiaron sería ruido forense.
    `current_files` se puede inyectar en pruebas; por defecto se deriva de la clave.
    """
    if current_files is None:
        from arx.modules import baseline  # perezoso: baseline importa response (gancho de sellado)
        current_files = baseline.integrity_paths().get(key, [])
    manifest = config.read_json(_vault_manifest_path(), {})
    known = {p: m for p, m in manifest.items()
             if m.get("key") == key and not p.startswith(str(_vault_dir()))}
    restored, quarantined = [], []
    for path, meta in known.items():
        bak = _vault_dir() / f"{hashlib.sha1(path.encode()).hexdigest()[:12]}.bak"
        try:
            good = open(bak, "rb").read()
        except OSError:
            continue
        try:
            now = open(path, "rb").read()
        except OSError:
            now = None  # el fichero crítico fue BORRADO: también se restaura
        if now == good:
            continue  # intacto: no tocar
        if now is not None:
            q = quarantine_file(path)  # la versión hostil no se pierde: es evidencia
            if q:
                quarantined.append(q)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(good)
        os.chmod(path, int(meta.get("mode", 0o600)))
        restored.append(path)
    for path in sorted(set(current_files) - set(known)):
        q = quarantine_file(path)  # intruso: sin copia buena porque no existía al sellar
        if q:
            quarantined.append(q)
    if not restored and not quarantined:
        if not known:
            return tr("no backup in the vault for '{key}': manual restore needed", key=key)
        return tr("'{key}' already matches the sealed version: nothing to restore", key=key)
    return (tr("restored {n} file(s) of '{key}' from the vault; hostile versions quarantined: {n2}",
               n=len(restored), key=key, n2=len(quarantined)))


def _shadow_entry(user: str) -> list[str] | None:
    """Campos de la cuenta en /etc/shadow. None si no se puede leer."""
    try:
        with open("/etc/shadow", encoding="utf-8", errors="replace") as f:
            for line in f:
                fields = line.rstrip("\n").split(":")
                if fields[0] == user and len(fields) >= 8:
                    return fields
    except OSError:
        pass
    return None


def _shadow_state(user: str) -> tuple[bool, str] | None:
    """(contraseña ya bloqueada, caducidad en días) de /etc/shadow. None si no se puede leer."""
    fields = _shadow_entry(user)
    return None if fields is None else (fields[1].startswith("!"), fields[7])


def _can_log_in(user: str) -> bool:
    """¿Esta cuenta puede entrar hoy, con contraseña o con llave SSH?"""
    import pwd

    fields = _shadow_entry(user)
    if fields is None:
        return False
    if fields[7].isdigit() and int(fields[7]) <= int(time.time() // 86400):
        return False
    if fields[1] and fields[1][0] not in "!*":
        return True
    try:
        keys = os.path.join(pwd.getpwnam(user).pw_dir, ".ssh", "authorized_keys")
        return os.path.getsize(keys) > 0
    except (KeyError, OSError):
        return False


def _admin_accounts() -> set[str]:
    """Cuentas con administración: uid 0, grupos de admin y lo que conceda sudoers."""
    import grp
    import pwd

    every = pwd.getpwall()
    admins = {p.pw_name for p in every if p.pw_uid == 0}
    for group in ("sudo", "wheel", "admin"):
        try:
            g = grp.getgrnam(group)
        except KeyError:
            continue
        admins.update(g.gr_mem)
        admins.update(p.pw_name for p in every if p.pw_gid == g.gr_gid)
    if shutil.which("sudo"):
        for p in every:
            if p.pw_uid < 1000 or p.pw_name in admins or not _USERNAME_RE.fullmatch(p.pw_name):
                continue
            try:
                r = subprocess.run(["sudo", "-n", "-l", "-U", p.pw_name], capture_output=True, text=True,
                                   timeout=5, env={**os.environ, "LC_ALL": "C"})
            except (OSError, subprocess.TimeoutExpired):
                continue
            if "may run the following" in (r.stdout or ""):
                admins.add(p.pw_name)
    return admins


def _leaves_no_admin(user: str) -> bool:
    """¿Bloquear esta cuenta dejaría el servidor sin nadie que pueda administrarlo?

    Una defensa que te deja fuera de tu propio servidor es peor que ninguna: pase lo que pase,
    siempre queda otra puerta. Sin poder comprobarlo, se asume que no queda.
    """
    admins = _admin_accounts()
    return user in admins and not any(_can_log_in(a) for a in admins - {user})


def _lock_account(user: str, finding: dict, allow_uid0: bool = False) -> tuple[bool, str]:
    """Bloquea los accesos NUEVOS de una cuenta y devuelve (bloqueada, explicación).

    `usermod -L` solo bloquea la contraseña: una llave SSH sigue entrando (comprobado con
    UsePAM yes). Por eso se caduca también la cuenta (-e 1). Se guarda el estado previo para
    restaurarlo tal cual, y el bloqueo no caduca: decide una persona con `arx unlock`.

    Jamás root ni cuentas de sistema (uid < 1000) ni cuentas fuera-de-límites, ni la última
    con administración: bloquear una de esas dejaría el host sin acceso. `allow_uid0` es para
    un alias de root que un humano ha decidido bloquear: `usermod` lo hace por nombre.
    """
    import pwd

    if not _USERNAME_RE.fullmatch(user):
        return False, tr("invalid account name ({user}): not locked", user=user)
    try:
        uid = pwd.getpwnam(user).pw_uid
    except KeyError:
        return False, tr("account '{user}' no longer exists: nothing to lock", user=user)
    if user == "root" or (uid < 1000 and not (allow_uid0 and uid == 0)):
        return False, tr("system account ({user}, uid {uid}): never locked automatically",
                         user=user, uid=uid)
    if user in _out_of_bounds(config.load_config()):
        return False, tr("account '{user}' marked out-of-bounds: not locked", user=user)
    if not shutil.which("usermod"):
        return False, tr("no usermod on this host: no safe account-lock executor")
    if any(b for b in _load_blocks() if _is_account_lock(b) and b["revert"].get("user") == user):
        # bloquear otra vez guardaría "bloqueada" como estado previo y nunca se restauraría
        return True, tr("account '{user}' was already locked by Arx. Your call:  arx unlock {user}",
                        user=user)
    state = _shadow_state(user)
    if state is None:
        return False, tr("could not read the state of '{user}' in /etc/shadow: not locked",
                         user=user)
    if _leaves_no_admin(user):
        return False, (tr("'{user}' is the last admin account with access: locking it would lock "
                          "you out of the server. Not locked", user=user))
    was_locked, expire = state
    r = subprocess.run(["usermod", "-L", "-e", "1", user], capture_output=True, text=True, timeout=15)
    if r.returncode != 0:
        return False, tr("could not lock the account ({v})", v=r.stderr.strip()[:48])
    register_block(finding, {"tool": "usermod", "user": user, "uid": uid,
                             "was_locked": was_locked, "expire": expire}, ttl_min=None)
    return True, (tr("account '{user}' locked: no entry by password or SSH key. It does not unlock "
                     "on its own: your call with  arx unlock {user}", user=user))


def _proc_uid(pid: int) -> int | None:
    try:
        return os.stat(f"/proc/{pid}").st_uid
    except OSError:
        return None


def _is_zombie(pid: int) -> bool:
    """Un zombi ya murió: solo espera a que su padre lo recoja, y contarlo como vivo sería falso."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            return f.read().rpartition(b")")[2].split()[0] == b"Z"
    except (OSError, IndexError):
        return True  # ya no está


def _account_processes(uid: int) -> list[dict]:
    """Procesos de la cuenta: los suyos y los nacidos de su sesión (loginuid), como un `sudo -i`."""
    out = []
    try:
        entries = os.listdir("/proc")
    except OSError:
        return out
    for name in entries:
        if not name.isdigit():
            continue
        pid = int(name)
        try:
            with open(f"/proc/{name}/loginuid", encoding="ascii") as f:
                loginuid = int(f.read().strip() or -1)
        except (OSError, ValueError):
            loginuid = -1
        if (_proc_uid(pid) != uid and loginuid != uid) or _is_zombie(pid):
            continue
        try:
            with open(f"/proc/{name}/cmdline", "rb") as f:
                cmd = f.read(200).replace(b"\0", b" ").decode("utf-8", "backslashreplace").strip()
        except OSError:
            continue  # murió entre listado y lectura
        out.append({"pid": pid, "cmd": printable(cmd)})
    return out


def _close_sessions(uid: int) -> tuple[list[dict], list[int]]:
    """Cierra todo lo que corre bajo la cuenta. Devuelve (procesos cerrados, supervivientes).

    SIGSTOP antes de SIGKILL para que nada se reproduzca mientras se recorre la lista. Nunca
    con uid < 1000: compartirlo con root o con un servicio mataría lo que no toca.
    """
    if uid < 1000:
        return [], []
    spared = {1, os.getpid(), os.getppid()}
    closed: dict[int, dict] = {}
    for _ in range(3):
        procs = [p for p in _account_processes(uid) if p["pid"] not in spared]
        if not procs:
            break
        for sig in (signal.SIGSTOP, signal.SIGKILL):
            for p in procs:
                try:
                    os.kill(p["pid"], sig)
                except OSError:
                    continue
        closed.update({p["pid"]: p for p in procs})
        time.sleep(0.2)
    alive = [p["pid"] for p in _account_processes(uid) if p["pid"] not in spared]
    return [p for pid, p in closed.items() if pid not in alive], alive


def _block_origin(origin: str, user: str, cfg: dict | None) -> str | None:
    """También se cierra la IP de origen: con una credencial robada, el atacante probaría otra
    cuenta. Esto sí expira (una IP cambia de manos) y respeta a quien nunca se bloquea."""
    try:
        ipaddress.ip_address(origin)
    except ValueError:
        return None
    f = {"kind": "auth_bruteforce", "sev": "high", "target": {"ip": origin}, "origin_of": user,
         "fp_key": f"auth_bruteforce|origen de la cuenta bloqueada {user}: {origin}",
         "detail": tr("origin of locked account {user}: {origin}", user=user, origin=origin)}
    reason = protected_reason(f, cfg)
    if reason:
        return tr("its IP {origin} is not blocked: {reason}", origin=origin, reason=reason)
    status, revert = _execute_tier1(f, cfg)
    if revert:
        _note_action()
    return status


def _identity_summary(rep: dict) -> str:
    lines = [tr("Account '{user}': ", user=rep['user']) + (tr("ALL ACCESS CLOSED") if rep["locked"] else tr("no action taken")),
             tr("  Detected: {detail}", detail=rep['detail']), tr("  Decided by: {decided_by}",
                                                 decided_by=rep['decided_by'])]
    v = rep.get("verdict")
    if v:
        lines.append(tr("  Model verdict: {verdict} ({confidence}%). {reason}",
                        verdict=tr(v['verdict']), confidence=v['confidence'], reason=v['reason']))
    lines.append(f"  {rep['lock']}")
    if rep["locked"]:
        cmds = [p["cmd"] or f"pid {p['pid']}" for p in rep["closed"]]
        lines.append(tr("  Sessions and processes closed: {n}. A closed session cannot be "
                        "recovered.", n=len(cmds)))
        lines += [f"    · {c[:70]}" for c in cmds[:8]]
        if len(cmds) > 8:
            lines.append(tr("    · and {v} more (arx forensics)", v=len(cmds) - 8))
        if rep["survivors"]:
            lines.append(tr("  ⚠ STILL ALIVE: {v}. Check them by hand.", v=rep['survivors'][:8]))
        if rep.get("origin_block"):
            lines.append(f"  {rep['origin_block']}")
        lines.append(tr("  This does not cover what does not go through the account: API tokens, "
                        "keys stolen from other services, or persistence already installed as root."))
        lines.append(tr("  Your call:  arx unlock {user}   ·   if it was legitimate, then:  arx "
                        "accept", user=rep['user']))
    return "\n".join(lines)


def contain_identity(finding: dict, decided_by: str, verdict: dict | None = None,
                     cfg: dict | None = None) -> dict:
    """Cierra todo acceso de una cuenta: contraseña, llave SSH, sesiones abiertas e IP de origen.

    Si no se puede bloquear (root, última cuenta admin…) no se cierra nada: cortarle la sesión a
    alguien a quien no se puede impedir que vuelva solo avisa. El informe es para el dueño: debe
    bastarle para decidir sin abrir otra pantalla.
    """
    import pwd

    user, _, origin = str((finding.get("target") or {}).get("user") or "").partition("@")
    locked, lock_msg = _lock_account(user, finding)
    rep = {"user": user, "origin": origin, "locked": locked, "decided_by": decided_by,
           "verdict": verdict, "detail": finding.get("detail"), "lock": lock_msg,
           "closed": [], "survivors": [], "origin_block": None}
    if locked:
        rep["closed"], rep["survivors"] = _close_sessions(pwd.getpwnam(user).pw_uid)
        rep["origin_block"] = _block_origin(origin, user, cfg)
    rep["summary"] = _identity_summary(rep)
    record({"kind": "identity_contained" if locked else "identity_refused", "sev": finding.get("sev"),
            "detail": finding.get("detail"), "result": rep["summary"], "decided_by": decided_by,
            "verdict": verdict, "closed": rep["closed"], "survivors": rep["survivors"]})
    return rep


def has_live_session(user: str, origin: str = "") -> bool:
    """¿Existe de verdad una sesión de esta cuenta desde ese origen?

    Cualquier usuario local puede escribir en auth.log con `logger`, así que una línea no basta
    para cerrarle el paso a nadie. `who` (utmp) solo lo escribe root, y un proceso sshd de la
    cuenta conectado a ese origen no lo puede fabricar quien no sea ya esa cuenta.
    """
    import pwd

    from arx.modules import baseline  # perezoso: baseline importa response (gancho de sellado)

    if (f"{user}@{origin}" if origin else user) in baseline._login_users():
        return True
    try:
        uid = pwd.getpwnam(user).pw_uid
    except KeyError:
        return False
    return bool(origin) and any(
        c.get("remote_ip") == origin and c.get("state") == "ESTABLISHED"
        and (c.get("exe") or "").rsplit("/", 1)[-1] in _SSHD_EXES
        and isinstance(c.get("pid"), int) and _sshd_serves(c["pid"], user, uid)
        for c in recon.connection_owners())


def _sshd_serves(pid: int, user: str, uid: int) -> bool:
    """El sshd de la sesión corre como la cuenta. Su monitor `[priv]`, que nace antes, corre como
    root y es lo único que hay al principio: solo root puede tener un proceso así con ese título."""
    owner = _proc_uid(pid)
    if owner == uid:
        return True
    if owner != 0:
        return False
    return re.match(rf"sshd(?:-session)?: {re.escape(user)} \[priv\]", _proc_title(pid)) is not None


def _llm_locks_path():
    return config.state_dir() / "llm_locks.json"


def _recent_llm_locks(now: datetime) -> list[str]:
    cutoff = now - timedelta(hours=1)
    return [t for t in config.read_json(_llm_locks_path(), []) if (_parse_dt(t) or cutoff) > cutoff]


def _verdict_refusal(user: str, origin: str, entry: dict | None, enforce: bool,
                     cfg: dict, now: datetime) -> str | None:
    """Por qué NO se actúa sobre un veredicto del modelo. Todo esto lo decide el código."""
    if not enforce:
        return tr("observe mode: with --enforce its access would have been closed")
    if cfg.get("llm_identity_actions") is False:
        return tr("disabled in the configuration (llm_identity_actions)")
    if (entry or {}).get("human_cleared"):
        return tr("you already unlocked it: the model does not overrule you")
    if not has_live_session(user, origin):
        return tr("no verifiable live session from that origin (auth.log can be forged)")
    if len(_recent_llm_locks(now)) >= MAX_LLM_LOCKS_PER_HOUR:
        return tr("it already locked {MAX_LLM_LOCKS_PER_HOUR} accounts in an hour: it may be "
                  "manipulated", MAX_LLM_LOCKS_PER_HOUR=MAX_LLM_LOCKS_PER_HOUR)
    return None


def apply_verdicts(pairs: list[tuple[dict, dict]], verdicts: list[dict], enforce: bool = False,
                   cfg: dict | None = None, now=None) -> list[dict]:
    """Aplica los veredictos del modelo sobre cuentas señaladas. Devuelve un informe por cada una.

    El modelo lee datos que un atacante puede escribir, así que nunca elige a quién: solo cuenta
    su veredicto sobre un hallazgo `login_users` de este lote, que ya señaló la capa determinista.
    Sin modelo, o por debajo del umbral, sigue siendo Tier 2 y decide el humano.
    """
    cfg = cfg if cfg is not None else {}
    now = now or _now()
    threshold = int(cfg.get("llm_lock_min_confidence", LLM_LOCK_MIN_CONFIDENCE))
    by_fp = {o.get("fp"): f for f, o in pairs}
    reports = []
    with config.locked():
        for v in verdicts:
            finding = by_fp.get(v["id"])
            if not finding or finding.get("kind") != "login_users":
                continue
            if v["verdict"] not in ("threat", "suspicion") or v["confidence"] < threshold:
                continue
            st = load_findings()
            item = str((finding.get("target") or {}).get("user") or "")
            user, _, origin = item.partition("@")
            refusal = _verdict_refusal(user, origin, st.get(v["id"]), enforce, cfg, now)
            decided = tr("the model, without waiting for your word (--enforce allows it)")
            if refusal:
                rep = {"user": user, "origin": origin, "locked": False, "decided_by": decided,
                       "verdict": v, "detail": finding.get("detail"), "lock": refusal,
                       "closed": [], "survivors": [], "origin_block": None}
                rep["summary"] = _identity_summary(rep) + tr("\n  Still waiting on you:  arx "
                                                             "authorize {v}", v=v['id'][:6])
                record({"kind": "identity_refused", "sev": finding.get("sev"), "detail": finding.get("detail"),
                        "result": rep["summary"], "verdict": v})
                reports.append(rep)
                continue
            rep = contain_identity(finding, decided, v, cfg)
            if rep["locked"]:
                config.write_json(_llm_locks_path(), _recent_llm_locks(now) + [_iso(now)])
                _save_pending([p for p in _load_pending() if p["id"] != v["id"][:6]])
                if v["id"] in st:
                    st[v["id"]]["status"] = tr("locked by model verdict → your call: arx unlock "
                                               "{user}", user=user)
                    _save_findings(st)
            reports.append(rep)
    return reports


def locked_accounts() -> list[dict]:
    """Cuentas que Arx mantiene bloqueadas a la espera de que una persona decida."""
    return [{"user": b["revert"].get("user"), "since": b.get("applied_at"), "detail": b.get("detail")}
            for b in _load_blocks() if _is_account_lock(b)]


def revert_failed(done: str | None) -> bool:
    """¿El revert dice que no pudo? Todo mensaje de ese fallo empieza por este texto."""
    return bool(done) and done.startswith(tr("could not"))


def unlock_account(user: str) -> str | None:
    """Levanta un bloqueo de cuenta (la palabra la verifica el llamador). None si no había.

    Es la decisión de una persona, y manda: el modelo no vuelve a bloquear esa cuenta por el
    mismo hallazgo, ni se vuelve a pedir autorización para ello.
    """
    with config.locked():
        blocks = _load_blocks()
        mine = [b for b in blocks if _is_account_lock(b) and b["revert"].get("user") == user]
        if not mine:
            return None
        done = _apply_revert(mine[0]["revert"]) if _is_linux_root() else tr("ready to run on the target")
        if revert_failed(done):
            return done  # sigue bloqueada: no se finge
        # su IP de origen tampoco debe seguir cerrada una hora más
        origin = [b for b in blocks if b.get("origin_of") == user]
        for b in origin:
            if _is_linux_root():
                _apply_revert(b.get("revert"))
        _save_blocks([b for b in blocks if b not in mine and b not in origin])
        st = load_findings()
        for e in st.values():
            if e.get("kind") == "login_users" and str(e.get("item", "")).partition("@")[0] == user:
                e["human_cleared"] = True
        _save_findings(st)
        _save_pending([p for p in _load_pending() if not (
            p.get("kind") == "login_users"
            and str((p.get("target") or {}).get("user", "")).partition("@")[0] == user)])
    record({"kind": "identity_unlocked", "detail": tr("account '{user}' unlocked by human decision",
                                                      user=user),
            "result": done})
    return done


def _execute_tier2(finding: dict) -> str:
    """Ejecuta una remediación Tier 2 ya autorizada por el humano. Nunca antes."""
    kind, target = finding.get("kind"), finding.get("target") or {}
    if not _is_linux_root():
        return tr("ready to run on the target (requires Linux + root)")
    if kind == "integrity" and target.get("file"):
        return _restore_from_vault(str(target["file"]))
    if kind == "login_users" and target.get("user"):
        return contain_identity(finding, tr("you, with your authorization word"))["summary"]
    if kind in ("listen_ports", "port_scan", "auth_bruteforce", "reverse_shell", "intel_ip"):
        # reapareció tras expirar y decidiste tú: la misma contención, otra hora
        cfg = config.load_config()
        reason = protected_reason(finding, cfg)
        return tr("protected ({reason}): no action taken", reason=reason) if reason else _execute_tier1(finding, cfg)[0]
    if kind in ("executables", "processes"):
        return _kill_and_quarantine(finding)
    if kind == "suid_new" and target.get("path"):
        return _drop_suid(str(target["path"]))
    if kind == "uid0_account" and target.get("user"):
        locked, msg = _lock_account(str(target["user"]), finding, allow_uid0=True)
        # comparte uid con root: cerrar por uid mataría todo lo de root
        return msg + (tr(". Its open sessions are NOT closed: they share a uid with root. Find "
                         "them with `who` and close them by hand") if locked else "")
    return tr("plan logged: no Tier 2 executor yet for this type")


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
                "kind": finding.get("kind"),
                "detail": finding.get("detail", ""),
                "target": finding.get("target"),  # el ejecutor Tier 2 lo necesita
                "fp_key": finding.get("fp_key"),  # sin ella, lo contenido no se reconocería después
                "remediation": plan["action"],
                "at": _iso(_now()),
            }
        )
        _save_pending(pend)
    return pid


def list_pending() -> list[dict]:
    return _load_pending()


def authorize_pending(pid: str) -> dict | None:
    """Quita el pendiente de la cola, lo registra como autorizado y lo EJECUTA.

    La autorización la verifica el llamador (CLI pide la palabra; Telegram pedirá TOTP).
    La ejecución es siempre reversible o restauradora, y queda auditada.
    """
    with config.locked():
        pend = _load_pending()
        item = next((p for p in pend if p["id"] == pid), None)
        if item is None:
            return None
        _save_pending([p for p in pend if p["id"] != pid])
    record({"kind": "tier2_authorized", "detail": item["detail"], "remediation": item["remediation"]})
    finding = {"kind": item.get("kind"), "target": item.get("target"), "fp_key": item.get("fp_key"),
               "detail": item.get("detail"), "sev": item.get("sev")}
    item["executed"] = _execute_tier2(finding)
    record({"kind": "tier2_executed", "detail": item["detail"], "result": item["executed"]})
    return item


def accept(fp: str) -> str | None:
    """Incorpora a la base un cambio legítimo y levanta lo que lo contenía. Devuelve qué pasó, o
    None si no hay un hallazgo aceptable con ese id. La autorización, si hace falta, es del llamador."""
    from arx.modules import baseline, vaccines  # perezoso: ambos importan este módulo

    from arx.modules import profile

    e = load_findings().get(fp)
    if not e or not e.get("set"):
        return None
    from arx.modules import trust
    accepted = (profile.accept(e["item"]) if e["set"] == "egress_profile"
                else profile.accept_exec(e["item"]) if e["set"] == "unexpected_exec"
                else trust.accept(e["item"]) if e["set"] == "untrusted_update"
                else baseline.accept(e["set"], e["item"]))
    if not accepted:
        return tr("Could not update the baseline (does it exist and contain that set?).")
    contained = _active_block(fp)
    forget(fp)
    if e["set"] == "untrusted_update":  # el preventivo y el veredicto de esa versión: los dos se levantan
        for other, oe in list(load_findings().items()):
            if oe.get("set") == "untrusted_update" and oe.get("item") == e["item"]:
                contained = _active_block(other) or contained
                forget(other)
    record({"kind": "accepted", "detail": e.get("detail")})
    out = [tr("✓ Accepted as normal: {item}", item=e['item']) + (tr("  ·  its block has been lifted") if contained else "")]
    if e.get("vaccine") and vaccines.note_false_positive(e["vaccine"]):  # a la tercera se retira sola
        out.append(tr("⚠ Vaccine {vaccine} removed: you have refuted it several times.",
                      vaccine=e['vaccine']))
    if str(e["item"]).partition("@")[0] in {a["user"] for a in locked_accounts()}:
        out.append(tr("⚠ That account stays locked: accepting does not unlock it. Use:  arx unlock"))
    return "\n".join(out)


def forget(fp: str) -> dict | None:
    """Olvida un hallazgo aceptado, su pendiente Tier 2 y lo que lo contenía: si dices que es
    normal, tu servicio no puede seguir caído una hora más. Devuelve la entrada o None.
    Un bloqueo de cuenta no se levanta por aquí: eso es `arx unlock`, con tu palabra."""
    with config.locked():
        st = load_findings()
        entry = st.pop(fp, None)
        if entry is None:
            return None
        _save_findings(st)
        _save_pending([p for p in _load_pending() if p["id"] != fp[:6]])
        blocks = _load_blocks()
        lifted = [b for b in blocks if b.get("fp") == fp and not _is_account_lock(b)]
        for b in lifted:
            if _is_linux_root():
                _apply_revert(b.get("revert"))
        if lifted:
            _save_blocks([b for b in blocks if b not in lifted])
    return entry


# ── ejecución Tier 1 ─────────────────────────────────────────────────────────
def _ufw_active() -> bool:
    try:
        r = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return False
    first = (r.stdout.splitlines() or [""])[0].lower()
    return r.returncode == 0 and "inactive" not in first and "inactivo" not in first


def _ufw_has_port_rule(port: int) -> bool:
    """¿El admin ya tiene una regla en ufw para este puerto? (`ufw show added`)"""
    try:
        r = subprocess.run(["ufw", "show", "added"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return True  # sin poder comprobarlo, no se arriesga a pisar nada
    return re.search(rf"(?:^|\s){port}(?:/\w+)?(?:\s|$)", r.stdout or "", re.M) is not None


def _nft_available() -> bool:
    return shutil.which("nft") is not None


def ensure_nft_tracking() -> bool:
    """Instala la tabla/sets/reglas de Arx — incluida la PISTA de escaneo — aunque aún
    no haya nada que bloquear. La pista debe existir ANTES del primer escaneo, no en
    la primera respuesta. Idempotente; sin nft o sin root: False silencioso."""
    if not (_is_linux_root() and _nft_available()):
        return False
    return _nft_setup()


_NFT_ELEMENT = {"nft": lambda r: (f"block_{r.get('proto')}", str(r.get("port"))),
                "nft_ip": lambda r: (f"block_ipv{ipaddress.ip_address(str(r.get('ip'))).version}", str(r.get("ip"))),
                "nft_c2": lambda r: (f"c2_out{ipaddress.ip_address(str(r.get('ip'))).version}",
                                     f"{r.get('ip')} . {r.get('port')}"),
                "nft_tarpit": lambda r: (f"tarpit{ipaddress.ip_address(str(r.get('ip'))).version}", str(r.get("ip")))}


def _nft_has(name: str, element: str) -> bool:
    try:
        return subprocess.run(["nft", "get", "element", "inet", "arx", name, f"{{ {element} }}"],
                              capture_output=True, text=True, timeout=15).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return True  # sin saberlo, no se anuncia que desapareció


def restore_kernel_blocks(now=None) -> dict | None:
    """Repone la contención que ya no está en el kernel: un reinicio o `systemctl restart nftables`
    (su configuración empieza con `flush ruleset`) la borran sin avisar, y seguir diciendo
    "contenido" sería falso. Devuelve un hallazgo para que el dueño lo sepa, o None.

    Se comprueba elemento a elemento: lo que sigue ahí no se toca, porque re-añadirlo en cada
    barrido alargaría lo que debe expirar.
    """
    if not (_is_linux_root() and _nft_available()):
        return None
    if any(isinstance(b.get("revert"), dict) and b["revert"].get("tool") == "confine"
           for b in _load_blocks()) and _nft_setup_confine() and (n := _restore_confinements()):
        record({"kind": "confinement_restored", "detail": tr("{n} confinement(s) put back", n=n)})
    now = now or _now()
    active = [(b, exp) for b in _load_blocks() if (exp := _parse_dt(b.get("expires_at"))) and exp > now
              and isinstance(b.get("revert"), dict) and b["revert"].get("tool") in _NFT_ELEMENT]
    if not active or not _nft_setup():
        return None
    missing, restored = 0, 0
    for b, exp in active:
        try:
            name, element = _NFT_ELEMENT[b["revert"]["tool"]](b["revert"])
        except ValueError:
            continue
        if _nft_has(name, element):
            continue
        missing += 1
        minutes = max(1, int((exp - now).total_seconds() // 60) + 1)
        try:
            r = subprocess.run(["nft", "add", "element", "inet", "arx", name,
                                f"{{ {element} timeout {minutes}m }}"],
                               capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired):
            continue
        restored += r.returncode == 0
    if not missing:
        return None
    return {"sev": "high", "kind": "firewall_reset",
            "fp_key": f"firewall_reset|el firewall se vació (reinicio o flush): {restored} de {missing} bloqueos repuestos",
            "detail": tr("the firewall was emptied (reboot or flush): {restored} of {missing} "
                         "blocks put back", restored=restored, missing=missing),
            "why": tr("a reboot explains it; if you did not reboot, someone with root deleted "
                      "Arx's rules")}


def _nft_chain(listing: str, name: str) -> str:
    """Cuerpo de una cadena en la salida de `nft list table`."""
    m = re.search(rf"chain {name} \{{(.*?)\n\s*\}}", listing, re.S)
    return m.group(1) if m else ""


def _nft_setup() -> bool:
    """Tabla/set/cadena de Arx en nftables, idempotente (ignora 'ya existe').

    Solo mira SU tabla: mirando todo el firewall, la `chain input` de otra tabla (la que trae la
    configuración por defecto de Debian y Ubuntu) parecía la suya y Arx quedaba sin reglas (B22).
    """
    try:
        r = subprocess.run(["nft", "list", "table", "inet", "arx"], capture_output=True,
                           text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return False
    ruleset = (r.stdout or "") if r.returncode == 0 else ""
    cmds = []
    if "table inet arx" not in ruleset:
        cmds.append(["nft", "add", "table", "inet", "arx"])
    if "block_tcp" not in ruleset:
        cmds += [["nft", "add", "set", "inet", "arx", "block_tcp",
                  "{", "type", "inet_service;", "flags", "timeout;", "}"],
                 ["nft", "add", "set", "inet", "arx", "block_udp",
                  "{", "type", "inet_service;", "flags", "timeout;", "}"]]
    if "block_ipv4" not in ruleset:
        cmds += [["nft", "add", "set", "inet", "arx", "block_ipv4",
                  "{", "type", "ipv4_addr;", "flags", "timeout;", "}"],
                 ["nft", "add", "set", "inet", "arx", "block_ipv6",
                  "{", "type", "ipv6_addr;", "flags", "timeout;", "}"]]
    # Parejas (origen, puerto) de cada SYN entrante: la PISTA de escaneo la guarda el
    # kernel (incluso contra puertos cerrados, donde no nace socket). La lee
    # sensors.detect_port_scan.
    if "scan4" not in ruleset:
        cmds += [["nft", "add", "set", "inet", "arx", "scan4",
                  "{", "type", "ipv4_addr", ".", "inet_service;", "flags", "timeout;",
                  "timeout", "10m;", "}"],
                 ["nft", "add", "set", "inet", "arx", "scan6",
                  "{", "type", "ipv6_addr", ".", "inet_service;", "flags", "timeout;",
                  "timeout", "10m;", "}"]]
    # Canal de un reverse shell (destino . puerto). Se corta con DROP en ambos sentidos, no
    # con RST ni `ss -K`: al expirar el flujo se reanuda por retransmisión TCP (reversible
    # de verdad) y no depende de que el kernel traiga INET_DIAG_DESTROY.
    if "c2_out4" not in ruleset:
        cmds += [["nft", "add", "set", "inet", "arx", "c2_out4",
                  "{", "type", "ipv4_addr", ".", "inet_service;", "flags", "timeout;", "}"],
                 ["nft", "add", "set", "inet", "arx", "c2_out6",
                  "{", "type", "ipv6_addr", ".", "inet_service;", "flags", "timeout;", "}"]]
    if "chain input" not in ruleset:
        cmds.append(["nft", "add", "chain", "inet", "arx", "input",
                     "{", "type", "filter", "hook", "input", "priority", "0;",
                     "policy", "accept;", "}"])
    # Un puerto publicado por Docker llega por FORWARD, no por INPUT: sin esto, una IP "bloqueada"
    # seguiría entrando en los contenedores del host.
    if "chain forward" not in ruleset:
        cmds.append(["nft", "add", "chain", "inet", "arx", "forward",
                     "{", "type", "filter", "hook", "forward", "priority", "0;",
                     "policy", "accept;", "}"])
    if "chain output" not in ruleset:
        cmds.append(["nft", "add", "chain", "inet", "arx", "output",
                     "{", "type", "filter", "hook", "output", "priority", "0;",
                     "policy", "accept;", "}"])
    if "@c2_out4" not in ruleset:
        cmds += [["nft", "add", "rule", "inet", "arx", "output", "ip", "daddr", ".", "tcp",
                  "dport", "@c2_out4", "drop"],
                 ["nft", "add", "rule", "inet", "arx", "output", "ip6", "daddr", ".", "tcp",
                  "dport", "@c2_out6", "drop"],
                 ["nft", "add", "rule", "inet", "arx", "input", "ip", "saddr", ".", "tcp",
                  "sport", "@c2_out4", "drop"],
                 ["nft", "add", "rule", "inet", "arx", "input", "ip6", "saddr", ".", "tcp",
                  "sport", "@c2_out6", "drop"]]
    if "tcp dport @block_tcp" not in ruleset:
        cmds += [["nft", "add", "rule", "inet", "arx", "input", "tcp", "dport",
                  "@block_tcp", "drop"],
                 ["nft", "add", "rule", "inet", "arx", "input", "udp", "dport",
                  "@block_udp", "drop"]]
    if "ip saddr @block_ipv4" not in _nft_chain(ruleset, "input"):
        cmds += [["nft", "add", "rule", "inet", "arx", "input", "ip", "saddr",
                  "@block_ipv4", "drop"],
                 ["nft", "add", "rule", "inet", "arx", "input", "ip6", "saddr",
                  "@block_ipv6", "drop"]]
    if "ip saddr @block_ipv4" not in _nft_chain(ruleset, "forward"):
        cmds += [["nft", "add", "rule", "inet", "arx", "forward", "ip", "saddr",
                  "@block_ipv4", "drop"],
                 ["nft", "add", "rule", "inet", "arx", "forward", "ip6", "saddr",
                  "@block_ipv6", "drop"]]
    if "@scan4" not in ruleset:
        cmds += [["nft", "add", "rule", "inet", "arx", "input", "tcp", "flags", "&",
                  "(", "syn", "|", "ack", ")", "==", "syn", "add", "@scan4",
                  "{", "ip", "saddr", ".", "tcp", "dport", "}"],
                 ["nft", "add", "rule", "inet", "arx", "input", "tcp", "flags", "&",
                  "(", "syn", "|", "ack", ")", "==", "syn", "add", "@scan6",
                  "{", "ip6", "saddr", ".", "tcp", "dport", "}"]]
    # TARPIT / estrangulamiento (Core): la IP hostil entra en tarpit4/6 y DOS reglas la
    # limitan POR ORIGEN con meters dinámicos per-IP — pocas conexiones nuevas/s y poco
    # caudal/s. No es un tarpit clásico de RETENCIÓN de conexión (eso exige userspace y es
    # la vía Pro/Business del honeypot); es rate-limiting agresivo que ahoga a un escáner
    # (medido: 4061 → 2,1 conexiones/s), reversible y con timeout nativo.
    if "tarpit4" not in ruleset:
        cmds += [["nft", "add", "set", "inet", "arx", "tarpit4",
                  "{", "type", "ipv4_addr;", "flags", "timeout;", "}"],
                 ["nft", "add", "set", "inet", "arx", "tarpit6",
                  "{", "type", "ipv6_addr;", "flags", "timeout;", "}"]]
    if "@tarpit4" not in ruleset:
        cmds += [  # conexiones NUEVAS por IP: ~2/s (ráfaga 2) → el escaneo/fuerza bruta se arrastra
            ["nft", "add", "rule", "inet", "arx", "input", "ct", "state", "new", "ip",
             "saddr", "@tarpit4", "meter", "arx_tpn4", "{", "ip", "saddr", "limit", "rate",
             "over", "2/second", "burst", "2", "packets", "}", "drop"],
            ["nft", "add", "rule", "inet", "arx", "input", "ct", "state", "new", "ip6",
             "saddr", "@tarpit6", "meter", "arx_tpn6", "{", "ip6", "saddr", "limit", "rate",
             "over", "2/second", "burst", "2", "packets", "}", "drop"],
            # caudal por IP: ~50 paquetes/s → throughput ahogado sin cortar del todo
            ["nft", "add", "rule", "inet", "arx", "input", "ip", "saddr", "@tarpit4",
             "meter", "arx_tpp4", "{", "ip", "saddr", "limit", "rate", "over", "50/second",
             "}", "drop"],
            ["nft", "add", "rule", "inet", "arx", "input", "ip6", "saddr", "@tarpit6",
             "meter", "arx_tpp6", "{", "ip6", "saddr", "limit", "rate", "over", "50/second",
             "}", "drop"]]
    for argv in cmds:
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired):
            return False
        if r.returncode != 0:  # sin su regla, meter algo en un set no contiene nada
            return False
    return True


# ── confinamiento (decisión E): el programa sigue, pero no sale a la red ──────
# Se mide en el kernel por cgroup v2: un servicio con todos sus procesos, o un proceso suelto que se
# adopta en un scope propio (sus hijos lo heredan). Probado en kernel real (Lima, Ubuntu 24.04):
#  · las respuestas a quien le habla siguen saliendo (`ct direction original` solo corta lo que él
#    inicia), y el resto del host no se entera;
#  · al reiniciar un servicio, systemd crea un cgroup nuevo y una regla con la ruta deja de casar en
#    silencio. Con systemd ≥ 254, `NFTSet=` mete el cgroup nuevo en el set en cada arranque; antes,
#    cada barrido lo repone (hueco: hasta el siguiente barrido);
#  · un slice con guion se anida (`arx-x.slice` cuelga de `arx.slice`): por eso `arxconfine.slice`;
#  · tras un reinicio, el servicio confinado salió una vez a la red antes del primer barrido de Arx.
#    Por eso `NFTSet=` es persistente (no `--runtime`) y `arx-firewall.service` crea la tabla antes de
#    que haya red: systemd mete al servicio en el set desde su primer arranque.
# Sin DNS tampoco: por el resolutor local se puede sacar información.
# Un nivel por profundidad: en un contenedor que comparte el árbol del host, los servicios cuelgan más hondo
_CONFINE_SETS = {n: f"confined{n}" for n in range(2, 7)}
_CONFINE_SLICE = "arxconfine.slice"
_SYSTEMD_DIR = "/etc/systemd/system"
_CONFINE_DROPIN = "90-arx-confine.conf"
_CGROUP_PATH_RE = re.compile(r"^[A-Za-z0-9@_.:\\-]{1,200}(?:/[A-Za-z0-9@_.:\\-]{1,200}){1,5}$")
_PROTECTED_UNITS = re.compile(r"^(?:ssh|sshd|dbus|dbus-broker|arx|polkit|systemd-[\w-]+|"
                              r"getty@[\w-]*|serial-getty@[\w-]*)\.service$")


def _systemd_nftset() -> bool:
    """¿systemd ≥ 254? Desde ahí repone el cgroup de un servicio en el set al reiniciarlo."""
    out = recon._run(["systemctl", "--version"]) or ""
    m = re.match(r"systemd (\d+)", out)
    return bool(m) and int(m.group(1)) >= 254


def _pin_confinement(name: str, path: str, set_name: str) -> None:
    """Que el confinamiento de un servicio sobreviva a sus reinicios y a los de la máquina.

    systemd ≥ 254: `NFTSet=`. Antes (Ubuntu 22.04, Debian 12): un drop-in con `ExecStartPre`. systemd
    crea el cgroup antes de `ExecStartPre`, así que el set lo tiene antes de que arranque el programa
    (probado en Ubuntu 22.04 real). El `-` hace que un fallo de nft no impida arrancar el servicio."""
    if _systemd_nftset():
        subprocess.run(["systemctl", "set-property", name, f"NFTSet=cgroup:inet:arx:{set_name}"],
                       capture_output=True, timeout=15)
        return
    d = os.path.join(_SYSTEMD_DIR, f"{name}.d")
    try:
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, _CONFINE_DROPIN), "w", encoding="utf-8") as f:
            f.write("# Arx: confined without outbound network until you decide (arx accept).\n"
                    f"[Service]\nExecStartPre=-{shutil.which('nft') or '/usr/sbin/nft'} add element inet "
                    f"arx {set_name} '{{ \"{path}\" }}'\n")
    except OSError:
        return
    subprocess.run(["systemctl", "daemon-reload"], capture_output=True, timeout=30)


def _unpin_confinement(name: str) -> None:
    if _systemd_nftset():
        subprocess.run(["systemctl", "set-property", name, "NFTSet="], capture_output=True, timeout=15)
        return
    try:
        os.unlink(os.path.join(_SYSTEMD_DIR, f"{name}.d", _CONFINE_DROPIN))
    except OSError:
        return
    subprocess.run(["systemctl", "daemon-reload"], capture_output=True, timeout=30)


# ── ssh: sin red de salida, salvo lo que necesita para autenticar (A#1) ─────────
_SSH_UNIT_RE = re.compile(r"^sshd?\.service$")
_ALLOW_DROPIN = "91-arx-confallow.conf"
_AUTH_FILES = {  # (fichero, regex de la línea, puerto por defecto, protocolos)
    "/etc/krb5.conf": (r"^\s*(?:kdc|master_kdc)\s*=\s*(\S+)", 88, ("udp", "tcp")),
    "/etc/ldap/ldap.conf": (r"^\s*URI\s+(.+)$", 389, ("tcp",)),
    "/etc/ldap.conf": (r"^\s*uri\s+(.+)$", 389, ("tcp",)),
    "/etc/nslcd.conf": (r"^\s*uri\s+(.+)$", 389, ("tcp",)),
    "/etc/sssd/sssd.conf": (r"^\s*ldap_(?:backup_)?uri\s*=\s*(.+)$", 389, ("tcp",)),
    "/etc/pam_radius_auth.conf": (r"^\s*([^#\s]+)\s+\S+", 1812, ("udp",)),
    "/etc/raddb/server": (r"^\s*([^#\s]+)\s+\S+", 1812, ("udp",)),
}


def _resolve(host: str) -> list[str]:
    import concurrent.futures
    import socket
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    try:  # getaddrinfo no tiene límite de tiempo: que un DNS lento no frene la contención
        infos = pool.submit(socket.getaddrinfo, host, None).result(timeout=3)
    except Exception:
        return []
    finally:
        pool.shutdown(wait=False)
    return sorted({i[4][0] for i in infos})


def _read_text(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read(65536)
    except OSError:
        return ""


def auth_backends(read=_read_text, resolve=None) -> list[tuple[str, str, int]]:
    """(protocolo, IP, puerto) que sshd necesita para seguir autenticando: DNS y los servidores de
    Kerberos, LDAP o RADIUS de la configuración. Con sssd o nslcd los usa su propio servicio, no sshd:
    sobran, pero no cuestan nada."""
    out, resolve = set(), resolve or _resolve
    resolv = read("/etc/resolv.conf")
    for ip in re.findall(r"^\s*nameserver\s+(\S+)", resolv, re.M) + ["127.0.0.53"]:
        out |= {("udp", ip, 53), ("tcp", ip, 53)}
    for path, (pattern, default, protos) in _AUTH_FILES.items():
        for value in re.findall(pattern, read(path), re.M | re.I):
            for item in value.split():
                m = re.match(r"^(?:(ldaps?)://)?\[?([A-Za-z0-9.:_-]+?)\]?(?::(\d+))?/?$", item.strip(",;"))
                if not m:
                    continue
                port = int(m.group(3)) if m.group(3) else (636 if m.group(1) == "ldaps" else default)
                for ip in resolve(m.group(2)):
                    out |= {(p, ip, port) for p in protos}
    return sorted(x for x in out if 0 < x[2] < 65536)


_SSH_TEMPLATES = ("sshd", "ssh")
_UNIT_DIRS = ("/etc/systemd/system", "/run/systemd/generator", "/run/systemd/generator.late", "/usr/lib/systemd/system",
              "/lib/systemd/system")


def _ssh_templates() -> list[str]:
    """Las plantillas de sshd por conexión de este host (socket con Accept=yes; el generador de ssh de systemd)."""
    return [t for t in _SSH_TEMPLATES if os.path.isdir(f"/sys/fs/cgroup/system.slice/system-{t}.slice")
            or any(os.path.exists(os.path.join(d, f"{t}@.service")) for d in _UNIT_DIRS)]


def _confine_ssh_instances(allow: list) -> list[dict]:
    """Las conexiones por instancia (sshd@….service) viven en su slice, fuera de ssh.service: el slice entero
    queda sin salida salvo las excepciones. Lo recarga cada instancia al arrancar (ExecStartPre), así que
    vale aunque el slice desaparezca y vuelva, en cualquier versión de systemd."""
    done = []
    nft = shutil.which("nft") or "/usr/sbin/nft"
    for t in _ssh_templates():
        path, set_name = f"system.slice/system-{t}.slice", _CONFINE_SETS[2]
        if allow and not _ensure_allow_sets(2):
            continue
        lines = [f"ExecStartPre=-{nft} add element inet arx {name} '{{ {elements} }}'"
                 for name, elements in _allow_elements(path, allow).items()]
        lines.append(f"ExecStartPre=-{nft} add element inet arx {set_name} '{{ \"{path}\" }}'")
        d = os.path.join(_SYSTEMD_DIR, f"{t}@.service.d")
        try:
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, _ALLOW_DROPIN), "w", encoding="utf-8") as f:
                f.write("# Arx: connections without outbound network, except what they need to authenticate.\n"
                        "[Service]\n" + "\n".join(lines) + "\n")
        except OSError:
            continue
        for name, elements in _allow_elements(path, allow).items():  # ya, si el slice existe
            subprocess.run(["nft", "add", "element", "inet", "arx", name, f"{{ {elements} }}"], capture_output=True,
                           text=True, timeout=15)
        _nft_cgroup("add", set_name, path)
        done.append({"template": t, "path": path, "set": set_name, "allow": allow})
    if done:
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True, timeout=30)
    return done


def _release_ssh_instances(entries) -> list[str]:
    done = []
    for e in entries if isinstance(entries, list) else []:
        t = e.get("template") if isinstance(e, dict) else None
        if t not in _SSH_TEMPLATES:
            continue
        path = f"system.slice/system-{t}.slice"
        _nft_cgroup("delete", _CONFINE_SETS[2], path)
        for name, elements in _allow_elements(path, _valid_allow(e.get("allow"))).items():
            subprocess.run(["nft", "delete", "element", "inet", "arx", name, f"{{ {elements} }}"], capture_output=True,
                           text=True, timeout=15)
        try:
            os.unlink(os.path.join(_SYSTEMD_DIR, f"{t}@.service.d", _ALLOW_DROPIN))
        except OSError:
            pass
        done.append(f"{t}@")
    if done:
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True, timeout=30)
    return done


def _valid_allow(items) -> list:
    """Solo formas conocidas, venga de donde venga el estado: nunca texto libre a nft."""
    out = []
    for item in items if isinstance(items, list) else []:
        try:
            proto, ip, port = item
            ipaddress.ip_address(str(ip))
            if proto in ("tcp", "udp") and isinstance(port, int) and 0 < port < 65536:
                out.append((proto, str(ip), port))
        except (TypeError, ValueError):
            continue
    return out


def _allow_set(level: int, fam: int) -> str:
    return f"confallow{level}v{fam}"


def _ensure_allow_sets(level: int) -> bool:
    """Sets de excepciones y su regla, ANTES del corte (se inserta al principio de la cadena)."""
    try:
        listing = subprocess.run(["nft", "list", "table", "inet", "arx"], capture_output=True, text=True,
                                 timeout=15).stdout or ""
    except (OSError, subprocess.TimeoutExpired):
        return False
    for fam, addr in ((4, "ip"), (6, "ip6")):
        name = _allow_set(level, fam)
        cmds = []
        if f"set {name} " not in listing:
            cmds.append(["nft", "add", "set", "inet", "arx", name, "{", "typeof", "socket", "cgroupv2", "level",
                         str(level), ".", "meta", "l4proto", ".", addr, "daddr", ".", "th", "dport;", "}"])
        if f"@{name}" not in _nft_chain(listing, "output"):
            cmds.append(["nft", "insert", "rule", "inet", "arx", "output", "ct", "direction", "original", "socket",
                         "cgroupv2", "level", str(level), ".", "meta", "l4proto", ".", addr, "daddr", ".", "th",
                         "dport", f"@{name}", "accept"])
        for argv in cmds:
            try:
                if subprocess.run(argv, capture_output=True, text=True, timeout=15).returncode != 0:
                    return False
            except (OSError, subprocess.TimeoutExpired):
                return False
    return True


def _allow_elements(path: str, allow: list) -> dict[str, str]:
    """{set: elementos nft} para las excepciones de un cgroup."""
    level = path.count("/") + 1
    by_set: dict[str, list[str]] = {}
    for proto, ip, port in allow:
        fam = ipaddress.ip_address(ip).version
        by_set.setdefault(_allow_set(level, fam), []).append(f'"{path}" . {proto} . {ip} . {int(port)}')
    return {name: ", ".join(items) for name, items in by_set.items()}


def _pin_allow(unit: str, path: str, allow: list) -> bool:
    """Carga las excepciones ahora y en cada arranque del servicio (su cgroup cambia al reiniciar)."""
    if not allow or not _ensure_allow_sets(path.count("/") + 1):
        return False
    nft = shutil.which("nft") or "/usr/sbin/nft"
    lines = []
    for name, elements in _allow_elements(path, allow).items():
        subprocess.run(["nft", "add", "element", "inet", "arx", name, f"{{ {elements} }}"], capture_output=True,
                       text=True, timeout=15)
        lines.append(f"ExecStartPre=-{nft} add element inet arx {name} '{{ {elements} }}'")
    d = os.path.join(_SYSTEMD_DIR, f"{unit}.d")
    try:
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, _ALLOW_DROPIN), "w", encoding="utf-8") as f:
            f.write("# Arx: what this service needs to keep authenticating while confined.\n[Service]\n"
                    + "\n".join(lines) + "\n")
    except OSError:
        return False
    subprocess.run(["systemctl", "daemon-reload"], capture_output=True, timeout=30)
    return True


def _unpin_allow(unit: str, path: str, allow: list) -> None:
    for name, elements in _allow_elements(path, allow).items():
        subprocess.run(["nft", "delete", "element", "inet", "arx", name, f"{{ {elements} }}"], capture_output=True,
                       text=True, timeout=15)
    try:
        os.unlink(os.path.join(_SYSTEMD_DIR, f"{unit}.d", _ALLOW_DROPIN))
    except OSError:
        return
    subprocess.run(["systemctl", "daemon-reload"], capture_output=True, timeout=30)


_SYSTEMD_CONTROL_DIR = "/etc/systemd/system.control"  # donde `systemctl set-property` deja NFTSet=


def _pinned_units() -> list[str]:
    """Servicios atados a un set de confinamiento de Arx, se sepa o no por qué (un estado perdido)."""
    found = set()
    for base, fname in ((_SYSTEMD_CONTROL_DIR, None), (_SYSTEMD_DIR, _CONFINE_DROPIN)):
        try:
            dirs = [d for d in os.listdir(base) if d.endswith(".service.d")]
        except OSError:
            continue
        for d in dirs:
            names = [fname] if fname else [n for n in os.listdir(os.path.join(base, d)) if n.endswith(".conf")]
            for n in names:
                try:
                    with open(os.path.join(base, d, n), encoding="utf-8", errors="replace") as f:
                        text = f.read(4096)
                except OSError:
                    continue
                if re.search(r"NFTSet=cgroup:inet:arx:confined\d|inet arx confined\d", text):
                    found.add(d[:-2])
    return sorted(u for u in found if re.match(r"^[A-Za-z0-9@_.:\\-]{1,200}\.service$", u))


def release_all_confinements() -> int:
    """Al desinstalar Arx: lo que confinó vuelve a tener red (lo decide quien lo desinstala) y ningún
    servicio queda atado a un set que ya nadie gestiona, ni que una reinstalación volvería a cerrar."""
    n = 0
    with config.locked():
        keep = []
        for b in _load_blocks():
            revert = b.get("revert")
            if isinstance(revert, dict) and revert.get("tool") == "confine":
                _release_confinement(revert)
                n += 1
            else:
                keep.append(b)
        _save_blocks(keep)
    for unit in _pinned_units():  # huérfanos: un estado borrado no puede dejar servicios sin red para siempre
        _unpin_confinement(unit)
        n += 1
    try:
        leftovers = [d for d in os.listdir(_SYSTEMD_DIR) if os.path.exists(os.path.join(_SYSTEMD_DIR, d, _ALLOW_DROPIN))]
    except OSError:
        leftovers = []
    for d in leftovers:
        os.unlink(os.path.join(_SYSTEMD_DIR, d, _ALLOW_DROPIN))
    if leftovers:
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True, timeout=30)
    return n


def _nft_setup_confine() -> bool:
    """Sets y reglas del confinamiento. Aparte de _nft_setup: un kernel o un nft sin `socket
    cgroupv2` no debe dejar al host sin el resto de la contención."""
    if not _nft_setup():
        return False
    try:
        r = subprocess.run(["nft", "list", "table", "inet", "arx"], capture_output=True, text=True,
                           timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return False
    listing = r.stdout or ""
    cmds = []
    for level, name in _CONFINE_SETS.items():
        if f"set {name} " not in listing:
            cmds.append(["nft", "add", "set", "inet", "arx", name,
                         "{", "typeof", "socket", "cgroupv2", "level", f"{level};", "}"])
        if f"@{name}" not in _nft_chain(listing, "output"):
            cmds += [["nft", "add", "rule", "inet", "arx", "output", "meta", "oifname", "!=", "lo",
                      "ct", "direction", "original", "socket", "cgroupv2", "level", str(level),
                      f"@{name}", "drop"],
                     ["nft", "add", "rule", "inet", "arx", "output", "ct", "direction", "original",
                      "socket", "cgroupv2", "level", str(level), f"@{name}", "meta", "l4proto",
                      "{", "tcp,", "udp", "}", "th", "dport", "53", "drop"]]
    for argv in cmds:
        try:
            if subprocess.run(argv, capture_output=True, text=True, timeout=15).returncode != 0:
                return False
        except (OSError, subprocess.TimeoutExpired):
            return False
    return True


def _can_confine() -> bool:
    return (_is_linux_root() and _nft_available() and bool(shutil.which("busctl"))
            and os.path.exists("/sys/fs/cgroup/cgroup.controllers") and _nft_setup_confine())


def _cgroup_of(pid: int) -> str | None:
    try:
        for line in open(f"/proc/{pid}/cgroup", encoding="utf-8"):
            if line.startswith("0::"):
                return line.strip()[3:].strip("/")
    except OSError:
        return None
    return None


def _nft_cgroup(action: str, set_name: str, path: str) -> bool:
    if set_name not in _CONFINE_SETS.values() or not _CGROUP_PATH_RE.match(path) or ".." in path:
        return False
    try:
        return subprocess.run(["nft", action, "element", "inet", "arx", set_name, f'{{ "{path}" }}'],
                              capture_output=True, text=True, timeout=15).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _confine_pid(pid: int) -> dict | None:
    """Confina el servicio de `pid`, o a `pid` en un scope propio. Lo hecho, o None."""
    from arx.modules import provenance  # perezoso: provenance importa este módulo

    unit = provenance.unit_of(pid)
    if unit:
        path, name = unit
        set_name = _CONFINE_SETS.get(path.count("/") + 1)
        if not set_name or _PROTECTED_UNITS.match(name) or not provenance._UNIT_RE.match(name):
            return None
        if not _nft_cgroup("add", set_name, path):
            return None
        _pin_confinement(name, path, set_name)
        return {"unit": name, "path": path, "set": set_name}
    return _adopt_into_scope(pid)


def _adopt_into_scope(pid: int, also: list[int] | None = None) -> dict | None:
    """Mueve el proceso (y `also`, su familia) a un scope propio y lo deja sin red: solo ellos, no su servicio."""
    scope = f"arxconfine-{pid}.scope"
    pids = [pid] + [p for p in also or [] if isinstance(p, int) and p > 1 and p != pid]
    try:
        r = subprocess.run(["busctl", "call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
                            "org.freedesktop.systemd1.Manager", "StartTransientUnit",
                            "ssa(sv)a(sa(sv))", scope, "fail", "2", "PIDs", "au", str(len(pids)), *map(str, pids),
                            "Slice", "s", _CONFINE_SLICE, "0"],
                           capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return None
    from arx.modules import provenance as prov
    root = prov.system_root()
    path = f"{root}/{_CONFINE_SLICE}/{scope}" if root else f"{_CONFINE_SLICE}/{scope}"
    set_name = _CONFINE_SETS.get(path.count("/") + 1)
    if not set_name:
        return None
    for _ in range(20):  # systemd mueve el proceso en segundo plano
        if _cgroup_of(pid) == path:
            break
        time.sleep(0.1)
    else:
        return None
    if r.returncode != 0 or not _nft_cgroup("add", set_name, path):
        return None
    return {"scope": scope, "path": path, "set": set_name, "pid": pid}


def _already_confined(pid: int, revert: dict) -> bool:
    cg = _cgroup_of(pid) or ""
    return f"{_CONFINE_SLICE}/" in f"/{cg}" or any(
        cg == u.get("path") or cg.startswith(str(u.get("path")) + "/") for u in revert.get("units") or [])


def boot_restore() -> str:
    """Al arrancar, antes de que haya red: lo contenido vuelve al kernel (`arx service restore`)."""
    if not (_is_linux_root() and _nft_available()):
        return tr("requires Linux + root with nftables")
    if not _nft_setup():
        return tr("nftables present but the arx table could not be prepared")
    can_confine = _nft_setup_confine()  # el set debe existir cuando systemd arranque a los confinados
    reset = restore_kernel_blocks()
    confined = _restore_confinements() if can_confine else 0
    msg = tr("containment back in the kernel: {blocks} · confinements: {confined}",
             blocks=(reset or {}).get("detail") or tr("nothing was missing"), confined=confined)
    record({"kind": "boot_restore", "detail": msg})
    return msg


def _confine(exe: str, pids: list[int], finding: dict) -> tuple[str, dict | None, list[int]]:
    """Confina lo que puede. Devuelve (estado, revert, pids que NO se pudieron confinar)."""
    revert = {"tool": "confine", "exe": exe, "units": [], "scopes": []}
    left = []
    for pid in pids:
        if _already_confined(pid, revert):
            continue
        done = _confine_pid(pid)
        if done:
            revert["units" if "unit" in done else "scopes"].append(done)
        else:
            left.append(pid)
    if not (revert["units"] or revert["scopes"]):
        return "", None, left
    register_block(finding, revert, ttl_min=None)
    what = [u["unit"] for u in revert["units"]] + [f"pid {s['pid']}" for s in revert["scopes"]]
    return (tr("confined without outbound network: {what}. It keeps running; it does not expire, "
               "you decide", what=", ".join(what))), revert, left


def _release_confinement(revert: dict) -> str:
    done = []
    for u in revert.get("units") or []:
        name = str(u.get("unit", ""))
        if not re.match(r"^[A-Za-z0-9@_.:\\-]{1,200}\.service$", name):
            continue
        _nft_cgroup("delete", str(u.get("set")), str(u.get("path", "")))
        _unpin_confinement(name)
        if isinstance(u.get("allow"), list):
            _unpin_allow(name, str(u.get("path", "")), _valid_allow(u["allow"]))
        done.append(name)
    for sc in revert.get("scopes") or []:
        _nft_cgroup("delete", str(sc.get("set")), str(sc.get("path", "")))
        done.append(f"pid {sc.get('pid')}")
    done += _release_ssh_instances(revert.get("templates"))
    for path in revert.get("frozen_cgroups") or []:  # primero descongelar el scope, luego SIGCONT
        if isinstance(path, str):
            _freeze_cgroup(path, False)
    exe = revert.get("exe")
    exes = revert.get("stopped_exes") if isinstance(revert.get("stopped_exes"), dict) else {}
    for pid in revert.get("stopped") or []:
        try:  # anti reutilización de PID: solo si sigue siendo el mismo programa
            mine = exes.get(str(pid), exe)  # cada miembro de la familia, con su propio programa
            if isinstance(pid, int) and pid > 1 and isinstance(mine, str) and \
                    os.readlink(f"/proc/{pid}/exe").removesuffix(" (deleted)") == mine:
                os.kill(pid, signal.SIGCONT)
                done.append(f"pid {pid}")
        except OSError:
            continue
    return tr("network restored to: {what}", what=", ".join(done) or "—")


def _extend_containment(blk: dict) -> int:
    """Un proceso nuevo del mismo programa (cron, un reinicio) no se escapa de lo ya decidido."""
    revert = blk.get("revert") if isinstance(blk.get("revert"), dict) else {}
    exe, tool = revert.get("exe"), revert.get("tool")
    if tool not in ("sigstop", "confine") or not isinstance(exe, str) or revert.get("pid_only") \
            or not _is_linux_root():
        return 0
    pids = [p for p in _pids_for_exe(exe) if p > 1 and p != os.getpid()]
    new = []
    if tool == "sigstop":
        for pid in pids:
            if pid in (revert.get("pids") or []):
                continue
            try:
                os.kill(pid, signal.SIGSTOP)
                new.append(pid)
            except OSError:
                continue
        revert["pids"] = list(revert.get("pids") or []) + new
    else:
        for pid in pids:
            if _already_confined(pid, revert) or pid in (revert.get("stopped") or []):
                continue
            done = _confine_pid(pid)
            if done:
                revert["units" if "unit" in done else "scopes"].append(done)
                new.append(pid)
                continue
            try:  # no se pudo confinar: suspendido hasta que decidas, nunca libre y con red
                os.kill(pid, signal.SIGSTOP)
            except OSError:
                continue
            revert["stopped"] = list(revert.get("stopped") or []) + [pid]
            new.append(pid)
    if new:
        _save_blocks([{**b, "revert": revert} if b.get("fp") == blk.get("fp") else b
                      for b in _load_blocks()])
        record({"kind": "containment_extended", "detail": blk.get("detail"), "result": new})
    return len(new)


def _restore_confinements() -> int:
    """Tras un reinicio o un `flush`, los confinamientos vuelven: no caducan."""
    restored = 0
    for b in _load_blocks():
        revert = b.get("revert")
        if not (isinstance(revert, dict) and revert.get("tool") == "confine"):
            continue
        for entry in (revert.get("units") or []) + (revert.get("scopes") or []):
            path, set_name = str(entry.get("path", "")), str(entry.get("set", ""))
            if not os.path.isdir(f"/sys/fs/cgroup/{path}"):
                continue  # el servicio está parado o el proceso ya no existe
            try:
                there = subprocess.run(["nft", "get", "element", "inet", "arx", set_name,
                                        f'{{ "{path}" }}'], capture_output=True, timeout=15).returncode == 0
            except (OSError, subprocess.TimeoutExpired):
                continue
            if not there and _nft_cgroup("add", set_name, path):
                restored += 1
                if entry.get("unit"):
                    _pin_confinement(str(entry["unit"]), path, set_name)
                if entry.get("unit") and isinstance(entry.get("allow"), list):
                    _pin_allow(str(entry["unit"]), path, _valid_allow(entry["allow"]))
        for e in revert.get("templates") or []:  # las conexiones por instancia: el slice, si ya existe
            if isinstance(e, dict) and e.get("template") in _SSH_TEMPLATES and os.path.isdir(
                    f"/sys/fs/cgroup/system.slice/system-{e['template']}.slice"):
                path = f"system.slice/system-{e['template']}.slice"
                for name, elements in _allow_elements(path, _valid_allow(e.get("allow"))).items():
                    subprocess.run(["nft", "add", "element", "inet", "arx", name, f"{{ {elements} }}"],
                                   capture_output=True, text=True, timeout=15)
                if _nft_cgroup("add", _CONFINE_SETS[2], path):
                    restored += 1
    return restored


def _confine_unit(unit: str, cgroup: str, finding: dict) -> tuple[str, dict | None]:
    """Confina un servicio entero por su cgroup: lo que arranque dentro, también un intérprete compartido
    (sh, python), queda sin red, y solo eso. Si no está corriendo, `NFTSet=` lo confina al arrancar."""
    from arx.modules import provenance  # perezoso: provenance importa este módulo
    if not (provenance._UNIT_RE.match(unit) and _CGROUP_PATH_RE.match(cgroup)
            and cgroup.rsplit("/", 1)[-1] == unit):
        return tr("invalid service: nothing confined"), None
    set_name = _CONFINE_SETS.get(cgroup.count("/") + 1)
    if not set_name or not _can_confine():
        return tr("confinement is not possible on this host: decide yourself (arx accept, or stop {unit})",
                  unit=unit), None
    entry = {"unit": unit, "path": cgroup, "set": set_name}
    if _SSH_UNIT_RE.match(unit):  # sin salida, pero con DNS y sus servidores de autenticación; la entrada, intacta
        entry["allow"] = [list(x) for x in auth_backends()]
        if not _pin_allow(unit, cgroup, _valid_allow(entry["allow"])):
            return tr("could not prepare what {unit} needs to keep authenticating: not confined", unit=unit), None
    _nft_cgroup("add", set_name, cgroup)
    _pin_confinement(unit, cgroup, set_name)
    revert = {"tool": "confine", "exe": None, "units": [entry], "scopes": []}
    what = unit
    if _SSH_UNIT_RE.match(unit):  # y las conexiones por instancia, si las hay
        revert["templates"] = _confine_ssh_instances(_valid_allow(entry["allow"]))
        what += "".join(f", {t['template']}@" for t in revert["templates"])
    register_block(finding, revert, ttl_min=None)
    return tr("confined without outbound network: {what}. It keeps running; it does not expire, "
              "you decide", what=what), revert


def _freeze_cgroup(path: str, on: bool) -> bool:
    """cgroup.freeze del scope de Arx: lo que hay dentro, y lo que se cree después, queda congelado; a
    diferencia de SIGSTOP, otro proceso no lo puede deshacer con un SIGCONT."""
    if not (_CGROUP_PATH_RE.match(path) and ".." not in path and f"{_CONFINE_SLICE}/" in f"{path}/"):
        return False
    try:
        with open(f"/sys/fs/cgroup/{path}/cgroup.freeze", "w") as f:
            f.write("1" if on else "0")
        return True
    except OSError:
        return False


def _contained_pids(fp: str) -> set:
    pids = set()
    for b in _load_blocks():
        revert = b.get("revert") if b.get("fp") == fp and isinstance(b.get("revert"), dict) else {}
        pids |= set(revert.get("stopped") or []) | {sc.get("pid") for sc in revert.get("scopes") or []}
    return pids


def _contain_process(target: dict, finding: dict) -> tuple[str, dict | None]:
    """Un proceso concreto (pid + inicio + ejecutable): a un scope sin red y, con señales de daño, congelado.
    Nunca «todos los de ese programa»: /bin/sh es de todos."""
    from arx.modules import execwatch  # perezoso
    pid, start, exe = target.get("pid"), target.get("start"), str(target.get("exe") or "")
    if not (isinstance(pid, int) and pid > 1 and pid != os.getpid() and isinstance(start, int) and exe.startswith("/")):
        return tr("invalid process: nothing contained"), None
    if not execwatch.same_process(pid, exe, start):
        return tr("the process is no longer alive: nothing to suspend"), None
    if "arx.service" in (_cgroup_of(pid) or ""):
        return tr("critical process ({base})", base="arx"), None
    stopped = bool(target.get("stopped"))
    family = [m for m in target.get("family") or [] if isinstance(m, dict) and isinstance(m.get("pid"), int)
              and execwatch.same_process(m["pid"], str(m.get("exe") or ""), m.get("start"))]
    if finding.get("harm") and not stopped:
        try:
            os.kill(pid, signal.SIGSTOP)
            stopped = True
        except OSError:
            pass
        family += execwatch.freeze_family(pid)  # lo que ya lanzó, también
    given = target.get("scope") if isinstance(target.get("scope"), dict) else None
    if given and _CGROUP_PATH_RE.match(str(given.get("path", ""))) and _cgroup_of(pid) == given.get("path"):
        scope = {k: given[k] for k in ("scope", "path", "set", "pid") if k in given}  # ya lo hizo el vigilante
        frozen = bool(target.get("scope_frozen")) or (stopped and _freeze_cgroup(scope["path"], True))
    else:
        scope = _adopt_into_scope(pid, [m["pid"] for m in family]) if _can_confine() else None
        frozen = bool(scope and stopped and _freeze_cgroup(scope["path"], True))  # ni un SIGCONT ajeno lo despierta
    if not scope and not stopped:  # lo que no se puede aislar se congela: nunca libre y con red
        try:
            os.kill(pid, signal.SIGSTOP)
            stopped = True
        except OSError:
            return tr("could not suspend (race or permissions)"), None
    revert = {"tool": "confine", "exe": exe, "pid_only": True, "units": [], "scopes": [scope] if scope else [],
              "stopped": ([pid] + [m["pid"] for m in family]) if stopped else [],
              "stopped_exes": {str(m["pid"]): m["exe"] for m in family},
              "frozen_cgroups": [scope["path"]] if frozen else []}
    register_block(finding, revert, ttl_min=None)
    parts = [tr("pid {pid} ({exe}) without network", pid=pid, exe=exe)] if scope else []
    if stopped:
        parts.append(tr("pid {pid} suspended", pid=pid))
    return " · ".join(parts) + tr(" · it does not expire, you decide"), revert


def _execute_tier1(finding: dict, cfg: dict | None = None) -> tuple[str, dict | None]:
    """Ejecuta una remediación Tier 1 reversible SOLO en Linux+root.

    Devuelve (status, revert). Fuera de Linux+root NO finge: informa que queda listo para
    ejecutar en el destino. Nunca hace nada irreversible. `cfg["ip_response"]` elige la
    respuesta a escaneo/fuerza bruta: "block" (por defecto) o "tarpit" (estrangular).
    """
    if not _is_linux_root():
        return tr("ready to run on the target (requires Linux + root)"), None
    kind = finding.get("kind")
    target = finding.get("target") or {}
    if kind == "listen_ports" and target.get("port"):
        proto, port = target.get("proto", "tcp"), int(target["port"])
        if _nft_available():
            # nftables también con ufw activo: un DROP en su propia tabla manda sea cual sea el
            # orden de las reglas de ufw, no toca las del admin y expira solo aunque Arx caiga.
            if not _nft_setup():
                return tr("nftables present but the arx table could not be prepared"), None
            r = subprocess.run(["nft", "add", "element", "inet", "arx", f"block_{proto}",
                                f"{{ {port} timeout {DEFAULT_TTL_MIN}m }}"],
                               capture_output=True, text=True, timeout=15)
            if r.returncode == 0:
                revert = {"tool": "nft", "port": port, "proto": proto}
                register_block(finding, revert)
                return (tr("port {port}/{proto} blocked in nftables (native timeout "
                           "{DEFAULT_TTL_MIN} min + Arx revert)",
                           port=port, proto=proto, DEFAULT_TTL_MIN=DEFAULT_TTL_MIN)), revert
            return tr("nft failed to block ({v})", v=r.stderr.strip()[:48]), None
        if shutil.which("ufw") and _ufw_active():
            # `ufw deny` sobre un puerto con regla la SOBRESCRIBE, y al revertir la borraría
            if _ufw_has_port_rule(port):
                return (tr("ufw already has a rule for port {port}: not touched (blocking would "
                           "destroy it). Install nftables to cut it without touching your rules",
                           port=port)), None
            r = subprocess.run(["ufw", "prepend", "deny", f"{port}/{proto}"],
                               capture_output=True, text=True, timeout=15)
            if r.returncode == 0:
                revert = {"tool": "ufw", "port": port, "proto": proto}
                register_block(finding, revert)
                return (tr("port {port}/{proto} blocked in ufw (auto-expires in {DEFAULT_TTL_MIN} "
                           "min)", port=port, proto=proto, DEFAULT_TTL_MIN=DEFAULT_TTL_MIN)), revert
            return tr("could not block the port ({v})", v=r.stderr.strip()[:48]), None
        if shutil.which("ufw"):
            # `ufw deny` "funciona" con ufw apagado pero no filtra nada → no fingir contención
            return tr("ufw is INACTIVE: a block would have no effect (enable it or decide yourself)"), None
        return tr("no ufw or nftables: no safe block executor on this host"), None
    if kind == "untrusted_update":
        return _confine_unit(str(target.get("unit") or ""), str(target.get("cgroup") or ""), finding)
    if kind == "unexpected_exec":
        return _contain_process(target, finding)
    if kind in ("executables", "processes"):
        exe = str(target.get("exe") or target.get("process") or "")
        if not exe.startswith("/"):
            # suspender por NOMBRE es inseguro (match erróneo) → se propone, no se auto-ejecuta
            return tr("no resolved executable path: nothing is suspended by name"), None
        base = exe.rsplit("/", 1)[-1]
        if base in _PROTECTED_EXES:
            return tr("critical process ({base}): never suspended", base=base), None
        pids = [p for p in _pids_for_exe(exe) if p > 1 and p != os.getpid()]
        if not pids:
            return tr("the process is no longer alive: nothing to suspend"), None
        fallback, confined_status = "", ""
        if finding.get("provenance") is not None and not finding.get("harm"):
            if _can_confine():
                confined_status, revert, pids = _confine(exe, pids, finding)
                if not pids:
                    return confined_status, revert
            # Sin confinamiento real (sin cgroup v2 + nftables + systemd, o un proceso que no se pudo
            # mover: medido en el kernel de GitHub, dentro de un contenedor), lo seguro es suspender.
            # Nunca queda libre y con red.
            fallback = tr(" (confinement is not possible on this host: suspended instead)")
        stopped = 0
        for pid in pids:
            try:
                os.kill(pid, signal.SIGSTOP)
                stopped += 1
            except OSError:
                continue
        if not stopped:
            return tr("could not suspend (race or permissions)"), None
        revert = {"tool": "sigstop", "exe": exe, "pids": pids}
        register_block(finding, revert)
        return ((f"{confined_status} · " if confined_status else "")
                + tr("process suspended ({stopped} pid): automatic SIGCONT on expiry "
                     "({DEFAULT_TTL_MIN} min)", stopped=stopped, DEFAULT_TTL_MIN=DEFAULT_TTL_MIN)
                + fallback), revert
    if kind == "canary":
        return tr("alert level raised and context captured"), None
    if kind in ("port_scan", "auth_bruteforce", "intel_ip") and target.get("ip"):
        ip = str(target["ip"])
        try:
            fam = ipaddress.ip_address(ip).version
        except ValueError:
            return tr("invalid IP ({ip}): not blocked", ip=ip), None
        # Política de respuesta (Core): "tarpit" estrangula per-IP en vez de bloquear. Solo a
        # escaneos: 2 conexiones/s apenas frenan una fuerza bruta SSH (medido: de 56 a 34
        # contraseñas en 20 s), así que esa se sigue bloqueando.
        # Necesita nftables (ufw no limita por IP de origen); sin nft, se informa y se
        # cae a bloqueo honesto en vez de fingir un estrangulamiento que no existe.
        if kind == "port_scan" and (cfg or {}).get("ip_response") == "tarpit":
            if _nft_available():
                if not _nft_setup():
                    return tr("nftables present but the arx table could not be prepared"), None
                r = subprocess.run(["nft", "add", "element", "inet", "arx", f"tarpit{fam}",
                                    f"{{ {ip} timeout {DEFAULT_TTL_MIN}m }}"],
                                   capture_output=True, text=True, timeout=15)
                if r.returncode == 0:
                    revert = {"tool": "nft_tarpit", "ip": ip}
                    register_block(finding, revert)
                    return (tr("IP {ip} THROTTLED in nftables (per-IP rate limit ~2 conn/s and ~50 "
                               "pkt/s; auto-expires in {DEFAULT_TTL_MIN} min)",
                               ip=ip, DEFAULT_TTL_MIN=DEFAULT_TTL_MIN)), revert
                return tr("nft failed to throttle the IP ({v})", v=r.stderr.strip()[:48]), None
            # sin nft no hay tarpit posible → se sigue por la rama de bloqueo (honesto)
        if _nft_available():
            if not _nft_setup():
                return tr("nftables present but the arx table could not be prepared"), None
            r = subprocess.run(["nft", "add", "element", "inet", "arx", f"block_ipv{fam}",
                                f"{{ {ip} timeout {DEFAULT_TTL_MIN}m }}"],
                               capture_output=True, text=True, timeout=15)
            if r.returncode == 0:
                revert = {"tool": "nft_ip", "ip": ip}
                register_block(finding, revert)
                return (tr("IP {ip} blocked in nftables (native timeout {DEFAULT_TTL_MIN} min + "
                           "Arx revert)", ip=ip, DEFAULT_TTL_MIN=DEFAULT_TTL_MIN)), revert
            return tr("nft failed to block the IP ({v})", v=r.stderr.strip()[:48]), None
        if shutil.which("ufw") and _ufw_active():
            # prepend: ufw aplica la primera regla que casa, y un `deny` añadido al final queda
            # detrás de tu `allow 22/tcp`: la IP "bloqueada" seguiría llegando al SSH.
            r = subprocess.run(["ufw", "prepend", "deny", "from", ip],
                               capture_output=True, text=True, timeout=15)
            if r.returncode == 0:
                revert = {"tool": "ufw_ip", "ip": ip}
                register_block(finding, revert)
                return (tr("IP {ip} blocked in ufw, for new connections only: those already open "
                           "stay up (install nftables to cut them). Auto-expires in "
                           "{DEFAULT_TTL_MIN} min", ip=ip, DEFAULT_TTL_MIN=DEFAULT_TTL_MIN)), revert
            return tr("could not block the IP ({v})", v=r.stderr.strip()[:48]), None
        if shutil.which("ufw"):
            return tr("ufw is INACTIVE: a block would have no effect (enable it or decide yourself)"), None
        return tr("no ufw or nftables: no safe block executor on this host"), None
    if kind == "reverse_shell" and target.get("ip"):
        ip = str(target["ip"])
        try:
            fam = ipaddress.ip_address(ip).version
        except ValueError:
            return tr("invalid IP ({ip}): no action taken", ip=ip), None
        port, exe = target.get("port"), str(target.get("exe") or "")
        actions, reverts = [], []
        # 1) cortar el canal: el rc de `nft add element` es fiable; el de `ss -K` no lo es
        #    (devuelve 0 sin cortar nada si el kernel no trae INET_DIAG_DESTROY).
        if isinstance(port, int) and 0 < port < 65536 and _nft_available() and _nft_setup():
            r = subprocess.run(["nft", "add", "element", "inet", "arx", f"c2_out{fam}",
                                f"{{ {ip} . {port} timeout {DEFAULT_TTL_MIN}m }}"],
                               capture_output=True, text=True, timeout=15)
            if r.returncode == 0:
                reverts.append({"tool": "nft_c2", "ip": ip, "port": port})
                actions.append(tr("C2 channel cut in nftables ({ip}:{port})", ip=ip, port=port))
        if not reverts:
            actions.append(tr("the C2 channel IS STILL OPEN (no usable nftables)"))
        # 2) suspender SOLO el proceso dueño; anti reutilización de PID: solo si
        #    /proc/<pid>/exe sigue siendo el mismo binario (nunca se suspende por nombre).
        stopped = []
        if exe.startswith("/"):
            for pid in target.get("pids") or []:
                if not (isinstance(pid, int) and pid > 1 and pid != os.getpid()):
                    continue
                try:
                    if os.readlink(f"/proc/{pid}/exe").removesuffix(" (deleted)") == exe:
                        os.kill(pid, signal.SIGSTOP)
                        stopped.append(pid)
                except OSError:
                    continue
        if stopped:
            reverts.append({"tool": "sigstop", "exe": exe, "pids": stopped})
            actions.append(tr("owning process suspended ({n} pid)", n=len(stopped)))
        else:
            actions.append(tr("no live process to suspend"))
        if not reverts:
            return " · ".join(actions), None
        for revert in reverts:
            register_block(finding, revert)
        return " · ".join(actions) + tr(": undoes itself in {DEFAULT_TTL_MIN} min",
                                         DEFAULT_TTL_MIN=DEFAULT_TTL_MIN), reverts[0]
    return tr("proposal (no safe automatic executor for this type)"), None


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
        "finding_kind": finding.get("kind"),
        # el porqué viaja con el incidente: quien lee una alerta tiene que poder decidir con él
        "why": finding.get("why"),
    }
    with config.locked():
        st = load_findings()
        entry = st.get(fp)
        outcome["new"] = entry is None
        entry = entry or {"first_seen": _iso(now), "seen": 0, "kind": finding.get("kind"),
                          "detail": finding.get("detail"), "set": finding.get("set"),
                          "item": finding.get("item"), "vaccine": finding.get("vaccine"),
                          "ip": (finding.get("target") or {}).get("ip")}
        entry["seen"] += 1
        entry["last_seen"] = _iso(now)

        reason = protected_reason(finding, cfg) if tier == 1 else None
        if tier == 0:
            status = tr("observed and logged")
        elif tier == 1 and reason:
            outcome["tier"] = 0
            status = tr("protected ({reason}): observed only", reason=reason)
        elif tier == 1 and (blk := _active_block(fp, now)):
            status = tr("already contained (active block {blk})", blk=_until(blk))
            if enforce and (n := _extend_containment(blk)):
                status += tr(" · and {n} new process(es) of the same program", n=n)
            pid = (finding.get("target") or {}).get("pid")
            if enforce and finding.get("kind") == "unexpected_exec" and \
                    pid not in _contained_pids(fp):  # otro proceso del mismo hijo: también, bajo el mismo aviso
                more, revert = _contain_process(finding.get("target") or {}, finding)
                if revert:
                    status += f" · {more}"
        elif tier == 1 and entry.get("blocked_before"):
            outcome["tier"] = 2
            pid = _add_pending(finding, {"action": tr("{action}: REAPPEARED after the block expired",
                                                      action=plan['action'])})
            outcome["pending_id"] = pid
            status = tr("reappeared after the block expired → your call: arx authorize {pid}  ·  "
                        "or accept: arx accept {fp}", pid=pid, fp=fp)
        elif tier == 1 and not enforce:
            status = tr("automatic proposal: enable --enforce to apply")
        elif tier == 1 and breaker_tripped(now, finding.get("sev")) and not (finding.get("target") or {}).get("stopped"):
            # lo que el vigilante ya congeló se registra igual: si no, quedaría congelado sin forma de soltarlo
            status = (tr("SAFETY BRAKE: already {MAX_TIER1_PER_HOUR} automatic actions in the last "
                         "hour → observing only", MAX_TIER1_PER_HOUR=MAX_TIER1_PER_HOUR))
        elif tier == 1:
            status, revert = _execute_tier1(finding, cfg)
            if revert:
                outcome["revert"] = revert
                _note_action(now)
                if finding.get("set"):  # lo primero que quiere saber quien acaba de instalar algo
                    status += tr(" · if legitimate:  arx accept {fp}", fp=fp)
        elif tier == 2 and (blk := _active_block(fp, now) or _lock_of(finding)):
            status = tr("already authorized and active {blk}", blk=_until(blk))
        elif tier == 2 and entry.get("human_cleared"):
            status = tr("you unlocked it: observed only (make it normal with: arx accept {fp})",
                        fp=fp)
        elif authorized:
            status = tr("authorized by word ✓")
        else:  # tier 2
            pid = _add_pending(finding, plan)
            outcome["pending_id"] = pid
            status = tr("PENDING (id {pid}): authorize with: arx authorize {pid}", pid=pid)
        outcome["status"] = status

        changed = entry.get("status") != status
        entry["status"] = status
        st[fp] = entry
        _save_findings(st)
    if outcome["new"] or changed:  # registrar solo lo nuevo o lo que cambia, no cada barrido
        record({"kind": "incident", **outcome})
    return outcome
