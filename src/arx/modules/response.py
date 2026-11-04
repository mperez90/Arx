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
import ipaddress
import os
import re
import shutil
import signal
import subprocess
import sys
from datetime import datetime, timedelta, timezone

from arx import config
from arx.modules import recon

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
    "login_users": (2, "bloquear la cuenta (usermod -L, reversible, auto-expira)", True,
                    "una cuenta nueva conectada puede ser un admin legítimo → requiere tu "
                    "palabra; el bloqueo se deshace solo y jamás toca root ni cuentas de sistema"),
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
                if os.readlink(f"/proc/{pid}/exe").removesuffix(" (deleted)") == exe:
                    os.kill(pid, signal.SIGCONT)
                    done += 1
            except OSError:
                continue
        return f"SIGCONT a {done} proceso(s) de {exe}"
    if isinstance(revert, dict) and revert.get("tool") == "usermod":
        import pwd

        user, uid = revert.get("user"), revert.get("uid")
        if not (isinstance(user, str) and _USERNAME_RE.match(user) and isinstance(uid, int)):
            return None
        try:
            # anti recreación de cuenta: solo se desbloquea si sigue siendo el mismo uid
            if pwd.getpwnam(user).pw_uid != uid:
                return f"cuenta '{user}' recreada con otro uid: no se desbloquea"
        except KeyError:
            return f"cuenta '{user}' ya no existe: nada que desbloquear"
        try:
            subprocess.run(["usermod", "-U", user], capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired):
            pass
        return f"usermod -U {user} (cuenta desbloqueada)"
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


def quarantine_file(path: str) -> str | None:
    """Mueve un fichero al vault en cuarentena (evidencia preservada). Devuelve su ruta."""
    try:
        data = open(path, "rb").read()
        st = os.stat(path)
    except OSError:
        return None
    q = _vault_dir() / f"q-{_now().strftime('%Y%m%d%H%M%S')}-{os.path.basename(path)}"
    fd = os.open(q, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    manifest = config.read_json(_vault_manifest_path(), {})
    manifest[str(q)] = {"quarantined_from": path, "sha256": hashlib.sha256(data).hexdigest(),
                        "mode": st.st_mode & 0o777, "at": _iso(_now())}
    config.write_json(_vault_manifest_path(), manifest)
    try:
        os.unlink(path)  # el fichero hostil sale de su sitio
    except OSError:
        pass
    return str(q)


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


def _lock_account(user: str, finding: dict) -> str:
    """Bloquea una cuenta (usermod -L), reversible y auto-expirable.

    Jamás root ni cuentas de sistema (uid < 1000) ni cuentas fuera-de-límites: bloquear
    una de esas dejaría el host sin acceso. El desbloqueo al expirar solo ocurre si sigue
    siendo la MISMA cuenta (mismo uid), análogo al anti reutilización de PID del SIGSTOP:
    si alguien recreó el usuario con otro uid entre medias, no se toca.
    """
    import pwd

    if not _USERNAME_RE.match(user):
        return f"nombre de cuenta inválido ({user}): no se bloquea"
    try:
        uid = pwd.getpwnam(user).pw_uid
    except KeyError:
        return f"la cuenta '{user}' ya no existe: nada que bloquear"
    if user == "root" or uid < 1000:
        return f"cuenta de sistema ({user}, uid {uid}): jamás se bloquea automáticamente"
    if user in _out_of_bounds(config.load_config()):
        return f"cuenta '{user}' marcada fuera-de-límites: no se bloquea"
    if not shutil.which("usermod"):
        return "sin usermod en este host: no hay ejecutor seguro de bloqueo de cuenta"
    r = subprocess.run(["usermod", "-L", user], capture_output=True, text=True, timeout=15)
    if r.returncode != 0:
        return f"no se pudo bloquear la cuenta ({r.stderr.strip()[:48]})"
    register_block(finding, {"tool": "usermod", "user": user, "uid": uid})
    return (f"cuenta '{user}' bloqueada (usermod -L) — se desbloquea sola en "
            f"{DEFAULT_TTL_MIN} min si sigue siendo la misma cuenta (uid {uid})")


def _execute_tier2(finding: dict) -> str:
    """Ejecuta una remediación Tier 2 ya autorizada por el humano. Nunca antes."""
    kind, target = finding.get("kind"), finding.get("target") or {}
    if not _is_linux_root():
        return "listo para ejecutar en destino (requiere Linux + root)"
    if kind == "integrity" and target.get("file"):
        return _restore_from_vault(str(target["file"]))
    if kind == "login_users" and target.get("user"):
        # el item de baseline es "usuario@origen": la cuenta es la parte antes de la @
        return _lock_account(str(target["user"]).split("@")[0], finding)
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
    finding = {"kind": item.get("kind"), "target": item.get("target"),
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


def _nft_available() -> bool:
    return shutil.which("nft") is not None


def ensure_nft_tracking() -> bool:
    """Instala la tabla/sets/reglas de Arx — incluida la PISTA de escaneo — aunque aún
    no haya nada que bloquear. La pista debe existir ANTES del primer escaneo, no en
    la primera respuesta. Idempotente; sin nft o sin root: False silencioso."""
    if not (_is_linux_root() and _nft_available()):
        return False
    return _nft_setup()


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
    if "chain input" not in ruleset.split("table inet arx")[-1]:
        cmds.append(["nft", "add", "chain", "inet", "arx", "input",
                     "{", "type", "filter", "hook", "input", "priority", "0;",
                     "policy", "accept;", "}"])
    if "chain output" not in ruleset.split("table inet arx")[-1]:
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
    if "ip saddr @block_ipv4" not in ruleset:
        cmds += [["nft", "add", "rule", "inet", "arx", "input", "ip", "saddr",
                  "@block_ipv4", "drop"],
                 ["nft", "add", "rule", "inet", "arx", "input", "ip6", "saddr",
                  "@block_ipv6", "drop"]]
    if "@scan4" not in ruleset.split("chain input")[-1]:
        cmds += [["nft", "add", "rule", "inet", "arx", "input", "tcp", "flags", "&",
                  "(", "syn", "|", "ack", ")", "==", "syn", "add", "@scan4",
                  "{", "ip", "saddr", ".", "tcp", "dport", "}"],
                 ["nft", "add", "rule", "inet", "arx", "input", "tcp", "flags", "&",
                  "(", "syn", "|", "ack", ")", "==", "syn", "add", "@scan6",
                  "{", "ip6", "saddr", ".", "tcp", "dport", "}"]]
    # TARPIT / estrangulamiento (Core): la IP hostil entra en tarpit4/6 y DOS reglas la
    # limitan POR ORIGEN con meters dinámicos per-IP — pocas conexiones nuevas/s y poco
    # caudal/s. No es un tarpit clásico de RETENCIÓN de conexión (eso exige userspace y es
    # la vía Pro/Business del honeypot); es rate-limiting agresivo que ahoga a escáneres y
    # fuerza bruta dejándoles solo un hilillo, reversible y con timeout nativo.
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
            subprocess.run(argv, capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired):
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
    if kind in ("port_scan", "auth_bruteforce") and target.get("ip"):
        ip = str(target["ip"])
        try:
            fam = ipaddress.ip_address(ip).version
        except ValueError:
            return f"IP inválida ({ip}): no se bloquea", None
        # Política de respuesta (Core): "tarpit" estrangula per-IP en vez de bloquear.
        # Necesita nftables (ufw no limita por IP de origen); sin nft, se informa y se
        # cae a bloqueo honesto en vez de fingir un estrangulamiento que no existe.
        if (cfg or {}).get("ip_response") == "tarpit":
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
        if shutil.which("ufw") and _ufw_active():
            r = subprocess.run(["ufw", "deny", "from", ip],
                               capture_output=True, text=True, timeout=15)
            if r.returncode == 0:
                revert = {"tool": "ufw_ip", "ip": ip}
                register_block(finding, revert)
                return (f"IP {ip} bloqueada en ufw "
                        f"(auto-expira en {DEFAULT_TTL_MIN} min)"), revert
            return f"no se pudo bloquear la IP ({r.stderr.strip()[:48]})", None
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
            status, revert = _execute_tier1(finding, cfg)
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
