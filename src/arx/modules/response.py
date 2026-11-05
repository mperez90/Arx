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
    "integrity": (2, "revertir el fichero crítico a copia buena conocida", True,
                  "alterar credenciales/ficheros del sistema es sensible → requiere tu palabra"),
    "listen_ports": (1, "bloquear el puerto en firewall (temporal, auto-expira)", True,
                     "bloquear un puerto es reversible y contiene exposición nueva"),
    "executables": (1, "suspender el proceso (SIGSTOP) para análisis", True,
                    "suspender es reversible (SIGCONT); no destruye evidencia"),
    "processes": (1, "suspender el proceso (SIGSTOP) para análisis", True,
                  "suspender es reversible (SIGCONT); no destruye evidencia"),
    "login_users": (2, "bloquear todos los accesos de la cuenta y cerrar sus sesiones (no se desbloquea sola)", False,
                    "una cuenta nueva conectada puede ser un admin legítimo → requiere tu palabra o "
                    "que el modelo la confirme como amenaza; una sesión cerrada no se puede "
                    "recuperar y jamás se toca root ni cuentas de sistema"),
    "suid_new": (2, "quitarle el bit SUID (chmod u-s); el fichero se queda como evidencia", True,
                 "un SUID nuevo da root a quien lo ejecute, pero puede venir de un paquete → requiere tu palabra"),
    "uid0_account": (2, "bloquear esa cuenta (contraseña y llave SSH); no afecta a root", True,
                     "puede ser legítima → requiere tu palabra; si lo es, acéptala con arx accept"),
    "canary": (1, "elevar el nivel de alerta y capturar el contexto del acceso al señuelo", True,
               "un señuelo tocado es señal fuerte de intruso; elevar y capturar es reversible"),
    "port_scan": (1, "bloquear la IP de origen en el firewall (temporal, auto-expira)", True,
                  "cortar el reconocimiento es reversible y no toca nada local"),
    "auth_bruteforce": (1, "bloquear la IP de origen en el firewall (temporal, auto-expira)", True,
                        "corta la fuerza bruta sin tocar la cuenta atacada (eso es Tier 2)"),
    "reverse_shell": (1, "bloquear el canal C2 en nftables y suspender el proceso dueño (auto-expira)", True,
                      "ambas acciones se deshacen al expirar: ni se destruye evidencia ni se pierde el flujo"),
    "log_tamper": (0, "registrar y alertar — alguien está borrando huellas", True,
                   "borrar logs es señal de intruso DENTRO: observar y escalar, no actuar a ciegas"),
    "gauge": (0, "registrar y vigilar la tendencia", True, "señal débil; observar primero"),
    "firewall_reset": (0, "registrar y alertar: la contención activa ya se repuso", True,
                       "puede ser un reinicio legítimo: lo decides tú"),
}

# Procesos que jamás se suspenden automáticamente (dejarían el host inaccesible o a Arx ciego).
_PROTECTED_EXES = {"sshd", "systemd", "init", "dbus-daemon", "journald", "systemd-journald",
                   "auditd", "falco", "osqueryd", "python3", "arx"}

# Nombre de cuenta válido (login POSIX). Clave de seguridad: un valor que empiece por "-"
# NO casa → imposible colar una opción a `usermod` por el nombre de la cuenta.
_USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


def classify(finding: dict) -> dict:
    # Un binario de sistema no visto al aprender es lo normal (un admin, una actualización).
    # Suspenderlo congelaría TODOS sus procesos, incluida la shell del operador (B9).
    if finding.get("kind") in ("executables", "processes") and finding.get("sev") == "low":
        return {"tier": 0, "action": "registrar y vigilar (binario de sistema nuevo)",
                "reversible": True, "why": "señal de baja confianza: no justifica suspender nada"}
    tier, action, reversible, why = _PLAN.get(
        finding.get("kind", ""), (0, "registrar y vigilar", True, "señal débil; observar primero")
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
    import json

    entry = {"at": _iso(_now()), **entry}
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
    if raw.strip() in ("", "(ninguno)"):
        return []
    return [t.strip() for t in re.split(r"[,\s]+", raw) if t.strip()]


def _never_block_ips() -> set[str]:
    """IPs que JAMÁS reciben un bloqueo automático.

    · Las propias del host (bloquear tu interfaz es un auto-daño absurdo).
    · Las del OPERADOR: una sesión SSH ESTABLECIDA y PERSISTENTE (vista en ≥2
      decisiones). Un atacante a mitad de fuerza bruta también tiene sockets
      ESTABLISHED efímeros hacia sshd: proteger "cualquiera conectado al 22" sería
      un interruptor de evasión — el atacante solo tendría que mantener una conexión
      abierta para volverse intocable.
    """
    out = set(recon.local_ips())
    ssh = ssh_ports()
    current = {c["remote_ip"] for c in recon.collect_connections()
               if c.get("state") == "ESTABLISHED" and c.get("local_port") in ssh}
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
    if kind in ("port_scan", "auth_bruteforce") and target.get("ip"):
        ip = str(target["ip"])
        if ip in _never_block_ips():
            return "IP intocable (propia del host o con sesión de operador activa)"
        if ip in oob:
            return "IP marcada fuera-de-límites"
    if kind == "reverse_shell":
        ip = str(target.get("ip") or "")
        if ip and ip in _never_block_ips():
            return "la contraparte es intocable (propia del host o sesión de operador)"
        if ip in oob:
            return "IP marcada fuera-de-límites"
        exe = str(target.get("exe") or "")
        base = exe.rsplit("/", 1)[-1]
        if base in _PROTECTED_EXES or exe == sys.executable:
            return f"proceso crítico ({base}): solo se observa"
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


def register_block(finding: dict, revert: dict, ttl_min: int | None = DEFAULT_TTL_MIN, now=None) -> None:
    now = now or _now()
    blocks = _load_blocks()
    blocks.append(
        {
            "fp": fingerprint(finding),
            "detail": finding.get("detail"),
            "revert": revert,
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
        return f"SIGCONT a {done} proceso(s) de {exe}"
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
                return f"cuenta '{user}' recreada con otro uid: no se desbloquea"
        except KeyError:
            return f"cuenta '{user}' ya no existe: nada que desbloquear"
        # se restaura el estado PREVIO: una cuenta que el admin ya tenía bloqueada sigue así
        argv = ["usermod", "-e", expire, user]
        if not revert.get("was_locked"):
            argv.insert(1, "-U")
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired):
            return f"no se pudo restaurar la cuenta '{user}': usermod no respondió"
        if r.returncode != 0:
            return f"no se pudo restaurar la cuenta '{user}' ({r.stderr.strip()[:60]})"
        return f"{' '.join(argv)} (estado previo de la cuenta restaurado)"
    return None


def _holds_until_human(block: dict) -> bool:
    """Un bloqueo de cuenta no caduca: lo levanta una persona (`arx unlock`), nunca el reloj.
    Se decide por el tipo y no por la fecha: la v0.0.2 los registró con caducidad."""
    revert = block.get("revert")
    return isinstance(revert, dict) and revert.get("tool") == "usermod"


def _until(block: dict) -> str:
    if _holds_until_human(block):
        return "hasta que lo decidas"
    return f"hasta {str(block.get('expires_at'))[11:16]} UTC"


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
    return next((b for b in _load_blocks() if _holds_until_human(b) and b["revert"].get("user") == user), None)


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
            return f"ya existe {printable(dest)}: no se pisa. Muévelo antes si quieres recuperar este"
        try:
            with open(q, "rb") as src:
                out = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(out, "wb") as dst:
                    shutil.copyfileobj(src, dst)
            os.chmod(dest, int(meta.get("mode", 0o600)))
            os.unlink(q)
        except OSError as e:
            return f"no se pudo restaurar {printable(dest)} ({e.strerror})"
        del manifest[q]
        config.write_json(_vault_manifest_path(), manifest)
    done = f"restaurado en {printable(dest)}"
    record({"kind": "quarantine_restored", "detail": dest, "result": done})
    return done


def _kill_and_quarantine(finding: dict) -> str:
    """Termina un proceso y guarda su binario como evidencia. Lo autoriza un humano: es lo que
    queda cuando suspenderlo no bastó (reapareció). El fichero se recupera con `arx restore`."""
    from arx.modules import baseline  # perezoso: baseline importa response (gancho de sellado)

    target = finding.get("target") or {}
    exe = str(target.get("exe") or target.get("process") or "")
    if not exe.startswith("/"):
        return "sin ruta de ejecutable resuelta: no se mata por nombre"
    base = exe.rsplit("/", 1)[-1]
    if base in _PROTECTED_EXES or exe == sys.executable:
        return f"proceso crítico ({base}): jamás se mata"
    pids = [p for p in _pids_for_exe(exe) if p > 1 and p != os.getpid()]
    parts = []
    if exe.startswith(baseline._SYSTEM_DIRS):
        parts.append("vive en un directorio del sistema: el fichero no se toca")
    else:
        # primero la evidencia: si se borró a sí mismo, al morir se pierde con él
        source = f"/proc/{pids[0]}/exe" if pids and not os.path.exists(exe) else None
        q = quarantine_file(exe, source=source)
        parts.append(f"fichero en cuarentena (recupéralo con: arx restore {os.path.basename(q)})" if q
                     else "el fichero no se pudo poner en cuarentena")
    killed = 0
    for pid in pids:
        try:
            os.kill(pid, signal.SIGKILL)
            killed += 1
        except OSError:
            continue
    parts.insert(0, f"{killed} proceso(s) terminado(s)" if pids else "no quedaba ningún proceso vivo")
    return " · ".join(parts)


def _drop_suid(path: str) -> str:
    """Quita el bit SUID sin borrar nada: deja de dar root y sigue ahí como evidencia."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as e:
        return f"no se pudo abrir {printable(path)} ({e.strerror})"
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return f"{printable(path)} ya no es un fichero normal: no se toca"
        os.fchmod(fd, stat.S_IMODE(st.st_mode) & ~0o6000)
    except OSError as e:
        return f"no se pudo cambiar {printable(path)} ({e.strerror})"
    finally:
        os.close(fd)
    return f"bit SUID retirado de {printable(path)}: ya no da privilegios. Si era legítimo: chmod u+s"


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
            return f"sin respaldo en el vault para '{key}' — restauración manual necesaria"
        return f"'{key}' ya coincide con el sellado — nada que restaurar"
    return (f"restaurado {len(restored)} fichero(s) de '{key}' desde el vault; "
            f"versiones hostiles en cuarentena: {len(quarantined)}")


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
        return False, f"nombre de cuenta inválido ({user}): no se bloquea"
    try:
        uid = pwd.getpwnam(user).pw_uid
    except KeyError:
        return False, f"la cuenta '{user}' ya no existe: nada que bloquear"
    if user == "root" or (uid < 1000 and not (allow_uid0 and uid == 0)):
        return False, f"cuenta de sistema ({user}, uid {uid}): jamás se bloquea automáticamente"
    if user in _out_of_bounds(config.load_config()):
        return False, f"cuenta '{user}' marcada fuera-de-límites: no se bloquea"
    if not shutil.which("usermod"):
        return False, "sin usermod en este host: no hay ejecutor seguro de bloqueo de cuenta"
    if any(b for b in _load_blocks() if _holds_until_human(b) and b["revert"].get("user") == user):
        # bloquear otra vez guardaría "bloqueada" como estado previo y nunca se restauraría
        return True, f"la cuenta '{user}' ya estaba bloqueada por Arx. Decide tú:  arx unlock {user}"
    state = _shadow_state(user)
    if state is None:
        return False, f"no pude leer el estado de '{user}' en /etc/shadow: no se bloquea"
    if _leaves_no_admin(user):
        return False, (f"'{user}' es la última cuenta de administración con acceso: bloquearla te "
                       "dejaría fuera del servidor. No se bloquea")
    was_locked, expire = state
    r = subprocess.run(["usermod", "-L", "-e", "1", user], capture_output=True, text=True, timeout=15)
    if r.returncode != 0:
        return False, f"no se pudo bloquear la cuenta ({r.stderr.strip()[:48]})"
    register_block(finding, {"tool": "usermod", "user": user, "uid": uid,
                             "was_locked": was_locked, "expire": expire}, ttl_min=None)
    return True, (f"cuenta '{user}' bloqueada: no entra ni con contraseña ni con llave SSH. No se "
                  f"desbloquea sola: decide tú con  arx unlock {user}")


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
    f = {"kind": "auth_bruteforce", "sev": "high", "target": {"ip": origin},
         "detail": f"origen de la cuenta bloqueada {user}: {origin}"}
    reason = protected_reason(f, cfg)
    if reason:
        return f"su IP {origin} no se bloquea: {reason}"
    status, revert = _execute_tier1(f, cfg)
    if revert:
        _note_action()
    return status


def _identity_summary(rep: dict) -> str:
    lines = [f"Cuenta '{rep['user']}': " + ("TODOS SUS ACCESOS CERRADOS" if rep["locked"] else "no se actuó"),
             f"  Detectado: {rep['detail']}", f"  Decidió: {rep['decided_by']}"]
    v = rep.get("verdict")
    if v:
        lines.append(f"  Veredicto del modelo: {v['veredicto']} ({v['confianza']}%). {v['razon']}")
    lines.append(f"  {rep['lock']}")
    if rep["locked"]:
        cmds = [p["cmd"] or f"pid {p['pid']}" for p in rep["closed"]]
        lines.append(f"  Sesiones y procesos cerrados: {len(cmds)}. Una sesión cerrada no se puede recuperar.")
        lines += [f"    · {c[:70]}" for c in cmds[:8]]
        if len(cmds) > 8:
            lines.append(f"    · y {len(cmds) - 8} más (arx forensics)")
        if rep["survivors"]:
            lines.append(f"  ⚠ SIGUEN VIVOS: {rep['survivors'][:8]}. Revísalos a mano.")
        if rep.get("origin_block"):
            lines.append(f"  {rep['origin_block']}")
        lines.append("  No cubre lo que no pasa por la cuenta: tokens de API, claves robadas de "
                     "otros servicios o persistencia ya instalada como root.")
        lines.append(f"  Decide tú:  arx unlock {rep['user']}   ·   si era legítima, después:  arx accept")
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
        and (c.get("exe") or "").rsplit("/", 1)[-1] in ("sshd", "sshd-session")
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
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            title = f.read(200).decode("utf-8", "replace")
    except OSError:
        return False
    return re.match(rf"sshd(?:-session)?: {re.escape(user)} \[priv\]", title) is not None


def _llm_locks_path():
    return config.state_dir() / "llm_locks.json"


def _recent_llm_locks(now: datetime) -> list[str]:
    cutoff = now - timedelta(hours=1)
    return [t for t in config.read_json(_llm_locks_path(), []) if (_parse_dt(t) or cutoff) > cutoff]


def _verdict_refusal(user: str, origin: str, entry: dict | None, enforce: bool,
                     cfg: dict, now: datetime) -> str | None:
    """Por qué NO se actúa sobre un veredicto del modelo. Todo esto lo decide el código."""
    if not enforce:
        return "modo observar: con --enforce se habrían cerrado sus accesos"
    if cfg.get("llm_identity_actions") is False:
        return "desactivado en la configuración (llm_identity_actions)"
    if (entry or {}).get("human_cleared"):
        return "ya la desbloqueaste tú: el modelo no te lleva la contraria"
    if not has_live_session(user, origin):
        return "sin sesión viva comprobable desde ese origen (auth.log se puede falsificar)"
    if len(_recent_llm_locks(now)) >= MAX_LLM_LOCKS_PER_HOUR:
        return f"ya bloqueó {MAX_LLM_LOCKS_PER_HOUR} cuentas en una hora: puede estar manipulado"
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
            if v["veredicto"] not in ("amenaza", "sospecha") or v["confianza"] < threshold:
                continue
            st = load_findings()
            item = str((finding.get("target") or {}).get("user") or "")
            user, _, origin = item.partition("@")
            refusal = _verdict_refusal(user, origin, st.get(v["id"]), enforce, cfg, now)
            decided = "el modelo, sin esperar tu palabra (lo permite --enforce)"
            if refusal:
                rep = {"user": user, "origin": origin, "locked": False, "decided_by": decided,
                       "verdict": v, "detail": finding.get("detail"), "lock": refusal,
                       "closed": [], "survivors": [], "origin_block": None}
                rep["summary"] = _identity_summary(rep) + f"\n  Sigue pendiente de ti:  arx authorize {v['id'][:6]}"
                record({"kind": "identity_refused", "sev": finding.get("sev"), "detail": finding.get("detail"),
                        "result": rep["summary"], "verdict": v})
                reports.append(rep)
                continue
            rep = contain_identity(finding, decided, v, cfg)
            if rep["locked"]:
                config.write_json(_llm_locks_path(), _recent_llm_locks(now) + [_iso(now)])
                _save_pending([p for p in _load_pending() if p["id"] != v["id"][:6]])
                if v["id"] in st:
                    st[v["id"]]["status"] = f"bloqueada por veredicto del modelo → decide tú: arx unlock {user}"
                    _save_findings(st)
            reports.append(rep)
    return reports


def locked_accounts() -> list[dict]:
    """Cuentas que Arx mantiene bloqueadas a la espera de que una persona decida."""
    return [{"user": b["revert"].get("user"), "since": b.get("applied_at"), "detail": b.get("detail")}
            for b in _load_blocks() if _holds_until_human(b)]


def unlock_account(user: str) -> str | None:
    """Levanta un bloqueo de cuenta (la palabra la verifica el llamador). None si no había.

    Es la decisión de una persona, y manda: el modelo no vuelve a bloquear esa cuenta por el
    mismo hallazgo, ni se vuelve a pedir autorización para ello.
    """
    with config.locked():
        blocks = _load_blocks()
        mine = [b for b in blocks if _holds_until_human(b) and b["revert"].get("user") == user]
        if not mine:
            return None
        done = _apply_revert(mine[0]["revert"]) if _is_linux_root() else "listo para ejecutar en destino"
        if done and done.startswith("no se pudo"):
            return done  # sigue bloqueada: no se finge
        # su IP de origen tampoco debe seguir cerrada una hora más
        origin = [b for b in blocks if str(b.get("detail", "")).startswith(f"origen de la cuenta bloqueada {user}:")]
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
    record({"kind": "identity_unlocked", "detail": f"cuenta '{user}' desbloqueada por decisión humana",
            "result": done})
    return done


def _execute_tier2(finding: dict) -> str:
    """Ejecuta una remediación Tier 2 ya autorizada por el humano. Nunca antes."""
    kind, target = finding.get("kind"), finding.get("target") or {}
    if not _is_linux_root():
        return "listo para ejecutar en destino (requiere Linux + root)"
    if kind == "integrity" and target.get("file"):
        return _restore_from_vault(str(target["file"]))
    if kind == "login_users" and target.get("user"):
        return contain_identity(finding, "tú, con tu palabra de autorización")["summary"]
    if kind in ("listen_ports", "port_scan", "auth_bruteforce", "reverse_shell"):
        # reapareció tras expirar y decidiste tú: la misma contención, otra hora
        cfg = config.load_config()
        reason = protected_reason(finding, cfg)
        return f"protegido ({reason}): no se actúa" if reason else _execute_tier1(finding, cfg)[0]
    if kind in ("executables", "processes"):
        return _kill_and_quarantine(finding)
    if kind == "suid_new" and target.get("path"):
        return _drop_suid(str(target["path"]))
    if kind == "uid0_account" and target.get("user"):
        locked, msg = _lock_account(str(target["user"]), finding, allow_uid0=True)
        # comparte uid con root: cerrar por uid mataría todo lo de root
        return msg + (". Sus sesiones abiertas NO se cierran: comparten uid con root. Búscalas con "
                      "`who` y ciérralas a mano" if locked else "")
    return "plan registrado — aún sin ejecutor Tier 2 para este tipo"


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
            "detail": f"el firewall se vació (reinicio o flush): {restored} de {missing} bloqueos repuestos",
            "why": "un reinicio lo explica; si no reiniciaste, alguien con root borró las reglas de Arx"}


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


def _execute_tier1(finding: dict, cfg: dict | None = None) -> tuple[str, dict | None]:
    """Ejecuta una remediación Tier 1 reversible SOLO en Linux+root.

    Devuelve (status, revert). Fuera de Linux+root NO finge: informa que queda listo para
    ejecutar en el destino. Nunca hace nada irreversible. `cfg["ip_response"]` elige la
    respuesta a escaneo/fuerza bruta: "block" (por defecto) o "tarpit" (estrangular).
    """
    if not _is_linux_root():
        return "listo para ejecutar en destino (requiere Linux + root)", None
    kind = finding.get("kind")
    target = finding.get("target") or {}
    if kind == "listen_ports" and target.get("port"):
        proto, port = target.get("proto", "tcp"), int(target["port"])
        if _nft_available():
            # nftables también con ufw activo: un DROP en su propia tabla manda sea cual sea el
            # orden de las reglas de ufw, no toca las del admin y expira solo aunque Arx caiga.
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
        if shutil.which("ufw") and _ufw_active():
            # `ufw deny` sobre un puerto con regla la SOBRESCRIBE, y al revertir la borraría
            if _ufw_has_port_rule(port):
                return (f"ufw ya tiene una regla para el puerto {port}: no se toca (bloquear la "
                        "destruiría). Instala nftables para cortar sin tocar tus reglas"), None
            r = subprocess.run(["ufw", "prepend", "deny", f"{port}/{proto}"],
                               capture_output=True, text=True, timeout=15)
            if r.returncode == 0:
                revert = {"tool": "ufw", "port": port, "proto": proto}
                register_block(finding, revert)
                return (f"puerto {port}/{proto} bloqueado en ufw "
                        f"(auto-expira en {DEFAULT_TTL_MIN} min)"), revert
            return f"no se pudo bloquear el puerto ({r.stderr.strip()[:48]})", None
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
    if kind in ("port_scan", "auth_bruteforce") and target.get("ip"):
        ip = str(target["ip"])
        try:
            fam = ipaddress.ip_address(ip).version
        except ValueError:
            return f"IP inválida ({ip}): no se bloquea", None
        # Política de respuesta (Core): "tarpit" estrangula per-IP en vez de bloquear. Solo a
        # escaneos: 2 conexiones/s apenas frenan una fuerza bruta SSH (medido: de 56 a 34
        # contraseñas en 20 s), así que esa se sigue bloqueando.
        # Necesita nftables (ufw no limita por IP de origen); sin nft, se informa y se
        # cae a bloqueo honesto en vez de fingir un estrangulamiento que no existe.
        if kind == "port_scan" and (cfg or {}).get("ip_response") == "tarpit":
            if _nft_available():
                if not _nft_setup():
                    return "nftables presente pero no se pudo preparar la tabla arx", None
                r = subprocess.run(["nft", "add", "element", "inet", "arx", f"tarpit{fam}",
                                    f"{{ {ip} timeout {DEFAULT_TTL_MIN}m }}"],
                                   capture_output=True, text=True, timeout=15)
                if r.returncode == 0:
                    revert = {"tool": "nft_tarpit", "ip": ip}
                    register_block(finding, revert)
                    return (f"IP {ip} ESTRANGULADA en nftables (rate-limit per-IP ~2 conx/s "
                            f"y ~50 paq/s; auto-expira en {DEFAULT_TTL_MIN} min)"), revert
                return f"nft falló al estrangular la IP ({r.stderr.strip()[:48]})", None
            # sin nft no hay tarpit posible → se sigue por la rama de bloqueo (honesto)
        if _nft_available():
            if not _nft_setup():
                return "nftables presente pero no se pudo preparar la tabla arx", None
            r = subprocess.run(["nft", "add", "element", "inet", "arx", f"block_ipv{fam}",
                                f"{{ {ip} timeout {DEFAULT_TTL_MIN}m }}"],
                               capture_output=True, text=True, timeout=15)
            if r.returncode == 0:
                revert = {"tool": "nft_ip", "ip": ip}
                register_block(finding, revert)
                return (f"IP {ip} bloqueada en nftables "
                        f"(timeout nativo {DEFAULT_TTL_MIN} min + reversión de Arx)"), revert
            return f"nft falló al bloquear la IP ({r.stderr.strip()[:48]})", None
        if shutil.which("ufw") and _ufw_active():
            # prepend: ufw aplica la primera regla que casa, y un `deny` añadido al final queda
            # detrás de tu `allow 22/tcp`: la IP "bloqueada" seguiría llegando al SSH.
            r = subprocess.run(["ufw", "prepend", "deny", "from", ip],
                               capture_output=True, text=True, timeout=15)
            if r.returncode == 0:
                revert = {"tool": "ufw_ip", "ip": ip}
                register_block(finding, revert)
                return (f"IP {ip} bloqueada en ufw, solo para conexiones nuevas: las ya abiertas "
                        f"siguen (instala nftables para cortarlas). Auto-expira en {DEFAULT_TTL_MIN} min"), revert
            return f"no se pudo bloquear la IP ({r.stderr.strip()[:48]})", None
        if shutil.which("ufw"):
            return "ufw está INACTIVO: un bloqueo no tendría efecto (actívalo o decide tú)", None
        return "sin ufw ni nftables: no hay ejecutor seguro de bloqueo en este host", None
    if kind == "reverse_shell" and target.get("ip"):
        ip = str(target["ip"])
        try:
            fam = ipaddress.ip_address(ip).version
        except ValueError:
            return f"IP inválida ({ip}): no se actúa", None
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
                actions.append(f"canal C2 cortado en nftables ({ip}:{port})")
        if not reverts:
            actions.append("el canal C2 SIGUE ABIERTO (sin nftables utilizable)")
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
            actions.append(f"proceso dueño suspendido ({len(stopped)} pid)")
        else:
            actions.append("sin proceso vivo que suspender")
        if not reverts:
            return " · ".join(actions), None
        for revert in reverts:
            register_block(finding, revert)
        return " · ".join(actions) + f" — se deshace solo en {DEFAULT_TTL_MIN} min", reverts[0]
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
        "finding_kind": finding.get("kind"),
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
        elif tier == 1 and (blk := _active_block(fp, now)):
            status = f"ya contenido (bloqueo activo {_until(blk)})"
        elif tier == 1 and entry.get("blocked_before"):
            outcome["tier"] = 2
            pid = _add_pending(finding, {"action": f"{plan['action']} — REAPARECIÓ tras expirar el bloqueo"})
            outcome["pending_id"] = pid
            status = f"reapareció tras expirar el bloqueo → decide tú: arx authorize {pid}  ·  o acepta: arx accept {fp}"
        elif tier == 1 and not enforce:
            status = "propuesta auto — activa --enforce para aplicar"
        elif tier == 1 and breaker_tripped(now, finding.get("sev")):
            status = (f"FRENO DE SEGURIDAD: ya hubo {MAX_TIER1_PER_HOUR} acciones automáticas en la "
                      "última hora → solo observo")
        elif tier == 1:
            status, revert = _execute_tier1(finding, cfg)
            if revert:
                outcome["revert"] = revert
                _note_action(now)
        elif tier == 2 and (blk := _active_block(fp, now) or _lock_of(finding)):
            status = f"ya autorizado y activo {_until(blk)}"
        elif tier == 2 and entry.get("human_cleared"):
            status = f"la desbloqueaste tú: solo se observa (hazla normal con: arx accept {fp})"
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
