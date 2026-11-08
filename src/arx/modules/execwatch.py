"""Arx · execwatch — lo que lanzan los servicios, en el momento (F18.2).

El conector de procesos del kernel (netlink, biblioteca estándar) avisa de cada `exec` al instante y
sin coste para el programa. Tres reglas:

  · sshd, antes de autenticar, no lanza nada que no sea suyo (sshd, sshd-session, sshd-auth) o que su
    configuración declare (AuthorizedKeysCommand, AuthorizedPrincipalsCommand, pam_exec). Lo demás es
    el patrón de la puerta trasera de xz: se congela en el acto, se aísla sin red y alerta crítica.
  · Un servidor web o una base de datos que, con su usuario de servicio, lanza una shell o un
    descargador: la firma de una webshell, desde el primer día.
  · Un servicio vigilado que lanza un programa que no lanzó mientras se le observaba: ese hijo se
    queda sin red y se avisa. El servicio sigue.

Se actúa sobre ESE proceso, nunca sobre «todos los de ese programa»: /bin/sh es de todos.
Sin el conector (un contenedor sin CAP_NET_ADMIN) se mira /proc en cada barrido: solo ve lo que dura.
"""
from __future__ import annotations

import collections
import os
import re
import shutil
import signal
import socket
import struct
import subprocess
import threading
import time

NETLINK_CONNECTOR = 11
CN_IDX_PROC = CN_VAL_PROC = 1
PROC_CN_MCAST_LISTEN = 1
PROC_EVENT_EXEC = 0x00000002
NLMSG_DONE = 3
MAX_EVENTS = 4000
ALLOW_REFRESH_S = 60
SSHD_PIECES = {"sshd", "sshd-session", "sshd-auth"}
# sshd como servicio, o una instancia por conexión (socket con Accept=yes: Debian 13, por ejemplo)
SSH_UNIT_RE = re.compile(r"^(?:.+/)?system\.slice/(?:system-sshd?\.slice/sshd?@[^/]+|sshd?)\.service$")
# también instancias de plantilla dentro de su slice (system-sshd.slice/sshd@….service)
_SERVICE_RE = re.compile(r"^((?:.+/)?system\.slice/(?:[A-Za-z0-9_.:\\-]{1,200}\.slice/)?"
                         r"[A-Za-z0-9@_.:\\-]{1,200}\.service)(?:/.*)?$")
# títulos de sshd antes de autenticar; uno con «@» ya es una sesión autenticada. «[priv]» no vale: el
# monitor lo lleva antes y después, y tras autenticar ejecuta pam_motd
_PREAUTH_TITLE_RE = re.compile(r"\[(?:accepted|net|preauth|listener)\]|\bunknown\b")
_DOWNLOADERS_AND_SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "ash", "busybox", "nc", "ncat", "netcat",
                           "socat", "curl", "wget", "telnet"}
_SERVICE_USERS = {"www-data", "nginx", "apache", "http", "httpd", "tomcat", "jetty", "caddy", "lighttpd",
                  "php-fpm", "mysql", "postgres", "redis", "mongodb"}

_events: collections.deque = collections.deque(maxlen=MAX_EVENTS)
_state = {"mode": None, "lost": 0}
_allow = {"at": 0.0, "paths": set(), "sure": False}
_declared: dict = {}  # (pid, inicio) de comandos declarados: lo que ejecuten en sí mismos sigue siendo suyo
_seen: set = set()


# ── el conector de procesos ──────────────────────────────────────────────────
def parse(data: bytes) -> list[int]:
    """Los tgid de los `exec` que trae un datagrama del conector (puede traer varios mensajes)."""
    return [tgid for tgid, _ in parse_events(data)]


def parse_events(data: bytes) -> list[tuple[int, int]]:
    """(tgid, instante del kernel en ns, reloj monotónico) de cada `exec` del datagrama."""
    out, off = [], 0
    while off + 16 <= len(data):
        length = struct.unpack_from("=I", data, off)[0]
        if length < 16 or off + length > len(data):
            break
        body = data[off + 16:off + length]
        if len(body) >= 44 and struct.unpack_from("=I", body, 0)[0] == CN_IDX_PROC:
            what, _, ts = struct.unpack_from("=IIQ", body, 20)  # cn_msg (20 bytes) y luego proc_event
            if what == PROC_EVENT_EXEC:
                out.append((struct.unpack_from("=I", body, 40)[0], ts))  # process_tgid
        off += (length + 3) & ~3
    return out


def _subscribe() -> socket.socket:
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_CONNECTOR)
    sock.bind((0, CN_IDX_PROC))
    payload = struct.pack("=IIIIHH", CN_IDX_PROC, CN_VAL_PROC, 0, 0, 4, 0) + struct.pack("=I", PROC_CN_MCAST_LISTEN)
    sock.send(struct.pack("=IHHII", 16 + len(payload), NLMSG_DONE, 0, 0, sock.getsockname()[0]) + payload)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    except OSError:
        pass
    return sock


# ── qué proceso es ───────────────────────────────────────────────────────────
def _read(path: str, limit: int = 4096) -> str:
    try:
        with open(path, "rb") as f:
            return f.read(limit).decode("utf-8", "replace")
    except OSError:
        return ""


def _stat(pid: int) -> tuple[int, int] | None:
    """(ppid, inicio en ticks): el inicio distingue un proceso de otro que reutilice su pid."""
    raw = _read(f"/proc/{pid}/stat")
    try:
        fields = raw.rsplit(")", 1)[1].split()
        return int(fields[1]), int(fields[19])
    except (IndexError, ValueError):
        return None


def _owner(pid: int) -> str:
    import pwd
    try:
        return pwd.getpwuid(os.stat(f"/proc/{pid}").st_uid).pw_name
    except (OSError, KeyError):
        return ""


def describe(pid: int, root: str = "") -> dict | None:
    """Lo que hace falta para decidir, leído al instante: el proceso puede durar milisegundos. Su usuario,
    lo primero: un comando de claves breve ya habría terminado al final y saldría sin usuario."""
    user = _owner(pid)
    try:
        exe = os.readlink(f"/proc/{pid}/exe").removesuffix(" (deleted)")
    except OSError:
        return None
    if not user:
        return None
    cg = next((ln[3:].strip().strip("/") for ln in _read(f"/proc/{pid}/cgroup").splitlines()
               if ln.startswith("0::")), "")
    if root:
        if not cg.startswith(root + "/"):
            return None
        cg = cg[len(root) + 1:]
    m = _SERVICE_RE.match(cg)
    st = _stat(pid)
    if not m or not st:
        return None
    ppid, start = st
    try:
        pexe = os.readlink(f"/proc/{ppid}/exe").removesuffix(" (deleted)")
    except OSError:
        pexe = ""
    argv, gone = _read(f"/proc/{pid}/cmdline", 1024).split("\0")[:3], False
    for _ in range(3):  # una cadena de exec rápida: que exe y argv sean del mismo programa
        try:
            now = os.readlink(f"/proc/{pid}/exe").removesuffix(" (deleted)")
        except OSError:
            gone = True  # ya terminó: argv puede ser del programa siguiente de la cadena
            break
        if now == exe:
            break
        exe, argv = now, _read(f"/proc/{pid}/cmdline", 1024).split("\0")[:3]
    return {"pid": pid, "start": start, "exe": exe, "argv": argv, "user": user, "unit": m.group(1), "ppid": ppid,
            "parent_exe": pexe, **({"gone": True} if gone else {}),
            "parent_title": _read(f"/proc/{ppid}/cmdline", 512).replace("\0", " ").strip(),
            "parent_user": _owner(ppid)}


def same_process(pid: int, exe: str, start: int) -> bool:
    st = _stat(pid)
    try:
        return bool(st) and st[1] == start and os.readlink(f"/proc/{pid}/exe").removesuffix(" (deleted)") == exe
    except OSError:
        return False


# ── reglas ───────────────────────────────────────────────────────────────────
SSHD_CONFIG = "/etc/ssh/sshd_config"
_COMMAND_KEYS = ("authorizedkeyscommand", "authorizedprincipalscommand")
_USER_KEYS = ("authorizedkeyscommanduser", "authorizedprincipalscommanduser")
_CONFIG_LINE_RE = re.compile(r"^(\S+?)(?:\s*=\s*|\s+)(.+)$")


def config_commands(path: str | None = None, depth: int = 0, seen: set | None = None) -> tuple[set[str], bool]:
    """(comandos, seguro) que sshd_config declara, también dentro de bloques Match y de sus Include. `sshd -T`
    sin -C no ve los de un Match (lo típico con LDAP o sssd): solo con él, se congelarían esos logins."""
    import glob
    import shlex
    seen = set() if seen is None else seen
    path = path or SSHD_CONFIG
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read(1 << 20)
    except OSError:
        return set(), False
    commands, sure = set(), True
    seen.add(path)
    for raw in text.splitlines():
        m = _CONFIG_LINE_RE.match(raw.split("#", 1)[0].strip())
        if not m:
            continue
        key, value = m.group(1).lower(), m.group(2).strip()
        try:
            words = shlex.split(value)
        except ValueError:
            sure = False
            continue
        if key in _COMMAND_KEYS and words and words[0].lower() != "none":
            commands.add(words[0])
        elif key in _USER_KEYS and words and words[0] not in ("root", "0", "none"):
            commands.add(f"user:{words[0]}")  # con quién corre ese comando: nunca root
        elif key == "include":
            if depth >= 8:
                sure = False
                continue
            for pattern in words:
                pattern = pattern if pattern.startswith("/") else os.path.join(os.path.dirname(SSHD_CONFIG), pattern)
                seen.add(os.path.dirname(pattern))  # su directorio también: un fichero nuevo cambia su mtime
                for inc in sorted(glob.glob(pattern)):
                    if inc not in seen:
                        seen.add(inc)
                        more, ok = config_commands(inc, depth + 1, seen)
                        commands |= more
                        sure = sure and ok
    return commands, sure


_SEARCH_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
_SKIP_WORDS = {"exec", "env", "command", "nohup", "then", "do", "else", "if", "while", "until", "time", "!", "{", "}"}
# un intérprete ejecuta lo que le den: cuenta solo con un script conocido, nunca suelto ni con `-c`
_INTERPRETER_RE = re.compile(r"^(?:sh|bash|dash|zsh|ksh|mksh|ash|python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|php[0-9.]*|"
                             r"node|nodejs|lua[0-9.]*|tclsh[0-9.]*|[gm]?awk)$")
# con estas, un intérprete o el cargador ejecutan código ajeno; sshd lanza sus comandos con un entorno mínimo
_INJECT_ENV = {"BASH_ENV", "ENV", "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "PERL5OPT", "PERL5LIB", "PERLLIB",
               "PYTHONSTARTUP", "PYTHONPATH", "PYTHONHOME", "RUBYOPT", "RUBYLIB", "NODE_OPTIONS", "NODE_PATH",
               "SHELLOPTS", "BASHOPTS", "PS4", "LUA_INIT", "LUA_PATH", "PHPRC", "PHP_INI_SCAN_DIR"}
_SYSTEM_PATH = set(_SEARCH_PATH.split(":")) | {"/usr/games", "/usr/local/games", "/snap/bin"}


def script_commands(path: str, depth: int = 0, seen: set | None = None) -> tuple[set[str], set[str]]:
    """Lo que un comando de claves ejecuta: (en su propio proceso, nombrado). En su proceso, el hijo directo de
    sshd: él mismo y lo que hace con `exec` (y lo que eso a su vez hace con `exec`). Nombrado: lo que lanza como
    hijo suyo, que nunca es hijo directo de sshd (ni dash ni bash hacen exec del último comando de un script).
    Su intérprete no: cuenta solo con el script (`_script_arg`), nunca suelto."""
    import shlex
    seen = set() if seen is None else seen
    real = os.path.realpath(path)
    runs, named = {path, real}, set()
    if real in seen or depth > 3:
        return runs, named
    seen.add(real)
    try:
        with open(real, "rb") as f:
            data = f.read(1 << 16)
    except OSError:
        return runs, named
    if not data.startswith(b"#!"):
        return runs, named  # un binario: solo él
    rest = data.decode("utf-8", "replace").partition("\n")[2]
    for line in rest.splitlines():
        for seg in re.split(r"[;&|`()]|\$\(", line.split("#", 1)[0]):
            try:
                words = shlex.split(seg)
            except ValueError:
                continue
            replaces = False  # `exec prog`: prog sigue en el mismo proceso
            while words and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", words[0]) or words[0] in _SKIP_WORDS):
                replaces = replaces or words[0] == "exec"
                words.pop(0)
            if not words:
                continue
            cmd = words[0] if words[0].startswith("/") else shutil.which(words[0], path=_SEARCH_PATH)
            args = [w for w in words[1:] if w.startswith("/") and os.path.isfile(w)]
            # un intérprete con su script cuenta por el script (`python3 /opt/x.py`); suelto (`awk '…'`), por sí
            interp = bool(cmd) and bool(_INTERPRETER_RE.match(os.path.basename(cmd)))
            for target in (args if interp and args else [cmd] + args):
                if not (target and os.path.isfile(target) and (interp or os.access(target, os.X_OK))):
                    continue
                if replaces:
                    more_runs, more_named = script_commands(target, depth + 1, seen)
                    runs |= more_runs
                    named |= more_named
                else:
                    named |= {target, os.path.realpath(target)}
    return runs, named


def _shebang(path: str) -> tuple[str, str]:
    """(intérprete, argumento) del shebang de un script, como lo lee el kernel: el resto de la línea es uno."""
    try:
        with open(path, "rb") as f:
            first = f.read(256).split(b"\n", 1)[0].decode("utf-8", "replace")
    except OSError:
        return "", ""
    parts = first[2:].strip().split(None, 1) if first.startswith("#!") else []
    return (parts[0], parts[1].strip() if len(parts) > 1 else "") if parts else ("", "")


def _interpreters(path: str) -> set[str]:
    """Lo que el kernel ejecuta para un script: su intérprete y, con env, lo que env lanza."""
    interp, arg = _shebang(path)
    if not interp:
        return set()
    out = {os.path.realpath(interp)}
    if os.path.basename(interp) == "env":
        prog = next((w for w in arg.split() if not w.startswith("-") and "=" not in w), "")
        found = prog if prog.startswith("/") else shutil.which(prog, path=_SEARCH_PATH) if prog else None
        if found:
            out.add(os.path.realpath(found))
    return out


def _script_arg(exe: str, argv: list, known) -> str:
    """El script conocido que corre un intérprete: el de su shebang (`sh /ruta`, o `sh -e /ruta` con
    `#!/bin/sh -e` y solo ese argumento; con `#!/usr/bin/env python3`, env y luego python3) o un intérprete
    habitual con el script de primer argumento (`python3 /opt/x.py`). Nunca `sh -c …`, ni un programa
    cualquiera con un script conocido detrás."""
    real = os.path.realpath(exe)
    for i in (1, 2):
        script = argv[i] if len(argv) > i else ""
        if not script.startswith("/") or not known(script):
            continue
        interp, arg = _shebang(script)
        if i == 2 and (not interp or argv[1] != arg):
            continue
        if real in _interpreters(script) or (i == 1 and (_INTERPRETER_RE.match(os.path.basename(exe))
                                        or _INTERPRETER_RE.match(os.path.basename(real)))):
            return script
    return ""


def _injected_env(pid: int) -> list[str]:
    """Lo que en el entorno de un comando declarado le haría ejecutar otra cosa (BASH_ENV, LD_PRELOAD, un PATH
    con directorios que no son del sistema): eso no lo pone sshd."""
    try:
        with open(f"/proc/{pid}/environ", "rb") as f:
            data = f.read(1 << 16)
    except OSError:
        return []
    found = set()
    for var in data.split(b"\0"):
        name, eq, value = var.decode("utf-8", "replace").partition("=")
        if not eq:
            continue
        if name in _INJECT_ENV or name.startswith("BASH_FUNC_"):
            found.add(name)
        elif name == "PATH" and any(d not in _SYSTEM_PATH for d in value.split(":")):
            found.add(name)
    return sorted(found)


def sshd_allowed(refresh: bool = False, hot: bool = False) -> set[str]:
    """Lo que sshd y PAM declaran que se ejecuta antes de autenticar. Se relee cada minuto. Si algo de esto no
    se pudo leer con certeza, `_allow["sure"]` queda en falso y la regla de sshd solo avisa (A#6)."""
    # en el camino caliente (un exec de sshd) solo se relee si cambió la configuración; por edad, en el barrido
    if not refresh and _allow["at"] and (hot or time.monotonic() - _allow["at"] < ALLOW_REFRESH_S) and not _changed():
        return _allow["paths"] | _accepted_now()
    paths = {"/usr/sbin/unix_chkpwd", "/sbin/unix_chkpwd"}
    sshd = shutil.which("sshd") or "/usr/sbin/sshd"
    try:
        r = subprocess.run([sshd, "-T"], capture_output=True, text=True, timeout=10)
        out, sure = r.stdout, r.returncode == 0 and bool(r.stdout.strip())
    except (OSError, subprocess.TimeoutExpired):
        out, sure = "", False
    keys_cmds = set()
    for line in out.splitlines():
        key, _, value = line.partition(" ")
        if key in _COMMAND_KEYS and value.strip() not in ("", "none"):
            keys_cmds.add(value.split()[0])
        elif key in _USER_KEYS and value.strip() not in ("", "none", "root", "0"):
            paths.add(f"user:{value.split()[0]}")
    read: set = {"/etc/pam.d"}
    declared, parsed = config_commands(seen=read)
    paths |= {d for d in declared if d.startswith("user:")}
    keys_cmds |= {d for d in declared if not d.startswith("user:")}
    sure = sure and parsed
    paths |= keys_cmds
    scripts: set = set()
    for cmd in keys_cmds:  # lo que esos comandos ejecutan, solo con su usuario, nunca con root (DEC#15)
        runs, named = script_commands(cmd, seen=scripts)
        paths |= {f"akc:{x}" for x in runs} | {f"akcn:{x}" for x in named}
    read |= scripts
    for text in _pam_stack("sshd"):
        for line in text.splitlines():
            tokens = line.split("#", 1)[0].split()
            if "pam_exec.so" in tokens:
                cmd = next((t for t in tokens[tokens.index("pam_exec.so") + 1:] if t.startswith("/")), None)
                if cmd:
                    paths.add(cmd)
    from arx.modules import profile  # lo que una persona aceptó (vale con o sin usuario de claves) y lo aprendido
    st = profile.load()
    accepted = set(st.get("sshd_allowed") or [])
    paths |= accepted | {f"akc:{x}" for x in accepted}
    paths |= {f"akc:{x}" for x in st.get("sshd_akc_seen") or []}
    # los intérpretes de esos scripts: solo para un proceso que terminó antes de poder leer sus argumentos
    paths |= {f"akci:{i}" for p in [p[4:] for p in paths if p.startswith("akc:")] for i in _interpreters(p)}
    paths |= {os.path.realpath(p) for p in paths}
    files = read | {f"/etc/pam.d/{n}" for n in _PAM_SEEN}
    _allow.update(at=time.monotonic(), paths=paths, sure=sure, stamps=_stamps(files))
    return paths


def _accepted_now() -> set[str]:
    """Lo que una persona acaba de aceptar, sin esperar al barrido: `arx accept` corre en otro proceso, y con sshd
    por conexión cada login hasta entonces se congelaría (A#11). Un fichero pequeño: en el camino caliente, un stat."""
    from arx import config
    path = config.state_dir() / "sshd_accepted.json"
    try:
        mtime = os.stat(path).st_mtime_ns
    except OSError:
        return set()
    if mtime != _allow.get("accepted_at"):
        accepted = {p for p in config.read_json(path).get("paths") or [] if isinstance(p, str) and p.startswith("/")}
        accepted |= {os.path.realpath(p) for p in accepted}
        _allow.update(accepted_at=mtime, accepted=accepted | {f"akc:{x}" for x in accepted})
    return _allow.get("accepted") or set()


def _stamps(files) -> dict:
    out = {}
    for f in files:
        try:
            out[f] = os.stat(f).st_mtime_ns
        except OSError:
            out[f] = None
    return out


def _changed() -> bool:
    """¿Cambió algo de lo que se leyó? Un admin que añade un AuthorizedKeysCommand no espera un minuto."""
    stamps = _allow.get("stamps") or {}
    return not stamps or _stamps(stamps) != stamps


def sshd_sure() -> bool:
    """¿Se leyó la configuración de sshd con certeza? Si no, la regla de sshd solo avisa: nunca un login
    legítimo congelado por una lectura incompleta."""
    sshd_allowed(hot=True)
    return bool(_allow.get("sure"))


_PAM_SEEN: set = set()


def _pam_stack(name: str, depth: int = 0) -> list[str]:
    _PAM_SEEN.add(name)
    text = _read(f"/etc/pam.d/{name}", 65536)
    out = [text]
    if depth < 3:
        for inc in re.findall(r"^\s*@include\s+(\S+)", text, re.M):
            if re.fullmatch(r"[\w.-]+", inc):
                out += _pam_stack(inc, depth + 1)
    return out


def sshd_preauth(ev: dict, allowed: set[str] | None = None, sessions: bool | None = None) -> bool:
    """¿Es sshd, antes de autenticar, lanzando algo que no es suyo ni declarado? (el patrón de xz)"""
    if not SSH_UNIT_RE.match(ev["unit"]) or os.path.basename(ev["parent_exe"]) not in SSHD_PIECES:
        return False
    if os.path.basename(ev["exe"]) in SSHD_PIECES:
        return False
    allowed = sshd_allowed(hot=True) if allowed is None else allowed  # solo aquí: el resto de eventos no la necesitan
    key = (ev["pid"], ev.get("start"))
    argv = ev.get("argv") or []
    # El comando de claves corre con su AuthorizedKeysCommandUser (nunca root): esa señal no la cambia la
    # carrera de una cadena de exec rápida (envoltorio → programa real → cat), que al leer /proc ya va por el
    # final. Con ese usuario, en silencio solo lo que su comando puede ejecutar (o lo aprendido), en cada exec
    # de la cadena: un root que cambie a ese usuario para lanzar otra cosa no pasa. Fuera de eso, aviso sin
    # congelar: ningún login se bloquea.
    user = ev.get("user") or ""
    if user and user != "root" and f"user:{user}" in allowed:
        def akc(p):
            return f"akc:{p}" in allowed or f"akc:{os.path.realpath(p)}" in allowed
        exe = ev["exe"]
        # terminó antes de leerlo entero (una cadena breve: envoltorio → real → cat): con el intérprete de su
        # comando no se puede decir más, y no se avisa de cada login
        gone = ev.get("gone") and f"akci:{os.path.realpath(exe)}" in allowed
        # lo que el script solo nombra corre como hijo suyo: como hijo directo de sshd, solo dentro de la misma
        # cadena de exec que ya empezó como su comando (DEC#15)
        chained = key in _declared and any(f"akcn:{n}" in allowed for n in (exe, os.path.realpath(exe)))
        if not (akc(exe) or _script_arg(exe, argv, akc) or gone or chained):
            interp = _INTERPRETER_RE.match(os.path.basename(exe)) or \
                _INTERPRETER_RE.match(os.path.basename(os.path.realpath(exe)))
            script = argv[1] if len(argv) > 1 and argv[1].startswith("/") else ""
            # lo que se aprende: el script de un intérprete (nunca el intérprete suelto), o el programa
            ev["akc_unknown"], ev["akc_learn"] = True, (script or None) if interp else os.path.realpath(exe)
            return True
        bad = _injected_env(ev["pid"])
        if bad:
            ev["env_injected"] = bad
            return True
        _declared[key] = True  # lo que esta cadena ejecute después sigue siendo de su comando
        while len(_declared) > 4096:
            _declared.pop(next(iter(_declared)))
        return False
    if key in _declared:  # un comando declarado que se reemplaza (`exec` del binario real, o su última orden)
        return False

    def declared(p):
        return p in allowed or os.path.realpath(p) in allowed
    # un comando declarado, o uno que es un script: el kernel ejecuta el intérprete con el script como primer
    # argumento (`sh /usr/local/bin/akc`, o `sh -e /usr/local/bin/akc` con `#!/bin/sh -e`). Nunca `sh -c …`
    if declared(ev["exe"]) or _script_arg(ev["exe"], argv, declared):
        bad = _injected_env(ev["pid"])
        if bad:  # su entorno le haría ejecutar otra cosa: aviso crítico, sin congelar (un login legítimo, nunca)
            ev["env_injected"] = bad
            return True
        _declared[key] = True
        while len(_declared) > 4096:
            _declared.pop(next(iter(_declared)))
        return False
    title = ev.get("parent_title") or ""
    if "@" in title:  # sesión ya autenticada (sin pam_systemd se queda en este cgroup)
        return False
    if sessions is None:
        sessions = os.path.isdir("/run/systemd/sessions")
    # con logind, lo autenticado se va a session-N.scope; sin él, solo cuenta un título de antes de autenticar
    return sessions or bool(_PREAUTH_TITLE_RE.search(title))


def webshell(ev: dict) -> bool:
    """Un servidor web o una base de datos que, con su usuario de servicio, lanza una shell o un descargador."""
    from arx.modules import provenance
    return (os.path.basename(ev["exe"]) in _DOWNLOADERS_AND_SHELLS
            and bool(provenance._NET_PARENT_RE.match(os.path.basename(ev["parent_exe"])))
            and ev.get("parent_user") in _SERVICE_USERS)


# ── el hilo y la cola ────────────────────────────────────────────────────────
def descendants(pid: int) -> list[int]:
    """Los procesos que cuelgan de `pid` (hijos, nietos…), leídos de /proc."""
    children: dict[int, list[int]] = {}
    try:
        names = [int(n) for n in os.listdir("/proc") if n.isdigit()]
    except OSError:
        return []
    for p in names:
        st = _stat(p)
        if st:
            children.setdefault(st[0], []).append(p)
    out, todo = [], [pid]
    while todo:
        for c in children.get(todo.pop(), []):
            if c not in out:
                out.append(c)
                todo.append(c)
    return out


FREEZE_BUDGET_S = 0.5
MAX_FAMILY = 1024


def freeze_family(pid: int) -> list[dict]:
    """Congela a `pid` y a lo que ya hubiera lanzado: un `sh -c` crea su hijo en menos de un milisegundo,
    antes de que nadie lo pare. Se repasa hasta que no aparezca nadie nuevo, con tope de vueltas, de tiempo
    y de procesos: un bucle de forks no puede colgar a Arx (lo que quede lo atrapa el cgroup congelado)."""
    family: list[dict] = []
    seen = {pid}
    deadline = time.monotonic() + FREEZE_BUDGET_S
    for _ in range(5):
        new = [c for c in descendants(pid) if c not in seen][:MAX_FAMILY - len(family)]
        if not new or time.monotonic() > deadline:
            break
        for c in new:
            seen.add(c)
            st = _stat(c)
            try:
                exe = os.readlink(f"/proc/{c}/exe").removesuffix(" (deleted)")
                os.kill(c, signal.SIGSTOP)
            except OSError:
                continue
            family.append({"pid": c, "exe": exe, "start": st[1] if st else None})
    return family


def _freeze(ev: dict) -> bool:
    if ev["pid"] in (os.getpid(), 1) or not same_process(ev["pid"], ev["exe"], ev["start"]):
        return False
    try:
        os.kill(ev["pid"], signal.SIGSTOP)
    except OSError:
        return False
    if ev.get("ts"):  # el kernel fecha el exec con el mismo reloj monotónico: lo que tardó el SIGSTOP
        ev["latency_ms"] = max(0, (time.monotonic_ns() - ev["ts"]) // 1_000_000)
    ev["family"] = freeze_family(ev["pid"])
    # su scope congelado, ya: un SIGSTOP lo deshace cualquier cómplice con un SIGCONT; un cgroup congelado, no.
    # El barrido solo registra lo hecho.
    try:
        from arx.modules import response
        if _state.get("confine") is None:
            _state["confine"] = response._can_confine()
        scope = response._adopt_into_scope(ev["pid"], [m["pid"] for m in ev["family"]]) if _state["confine"] else None
        if scope:
            ev["scope"] = scope
            ev["scope_frozen"] = response._freeze_cgroup(scope["path"], True)
    except Exception:
        pass
    return True


def handle_pid(pid: int, root: str, enforce, ts: int | None = None) -> dict | None:
    ev = describe(pid, root)
    if not ev:
        return None
    ev["preauth"] = sshd_preauth(ev)
    ev["sure"] = sshd_sure() if ev["preauth"] else True
    if ev["preauth"] and ev["sure"] and not (ev.get("akc_unknown") or ev.get("env_injected")) and enforce():
        ev["ts"] = ts
        ev["stopped"] = _freeze(ev)
    _events.append(ev)
    return ev


def _listen(sock: socket.socket, root: str, enforce) -> None:
    while True:
        try:
            data = sock.recv(1 << 16)
        except OSError:  # ENOBUFS: el kernel tiró eventos; se cuenta y se sigue
            _state["lost"] += 1
            continue
        for pid, ts in parse_events(data):
            try:
                handle_pid(pid, root, enforce, ts)
            except Exception:
                continue


def start(enforce) -> str:
    """Arranca el hilo (una vez). `enforce`: función que dice si se puede actuar ahora."""
    if _state["mode"]:
        return _state["mode"]
    from arx.modules import provenance
    try:
        sock = _subscribe()
    except (OSError, AttributeError):  # sin el conector: se mira /proc en cada barrido
        _state["mode"] = "scan"
        return "scan"
    try:  # la lista de sshd, ya leída: nunca un `sshd -T` entre un exec y su congelación
        sshd_allowed(refresh=True)
    except Exception:
        pass
    threading.Thread(target=_listen, args=(sock, provenance.system_root(), enforce), name="arx-exec",
                     daemon=True).start()
    _state["mode"] = "netlink"
    return "netlink"


def _scan(root: str) -> list[dict]:
    out = []
    try:
        pids = [int(n) for n in os.listdir("/proc") if n.isdigit()]
    except OSError:
        return out
    if len(_seen) > 50000:
        _seen.clear()
    for pid in pids:
        ev = describe(pid, root)
        if not ev or (pid, ev["start"]) in _seen:
            continue
        _seen.add((pid, ev["start"]))
        ev["preauth"] = sshd_preauth(ev)
        ev["sure"] = sshd_sure() if ev["preauth"] else True
        out.append(ev)
    return out


def drain() -> list[dict]:
    """Lo ocurrido desde el barrido anterior. De paso, la lista de sshd se renueva aquí, fuera del camino caliente."""
    try:
        sshd_allowed()
    except Exception:
        pass
    out = []
    while _events:
        out.append(_events.popleft())
    if _state["mode"] == "scan":
        from arx.modules import provenance
        out += _scan(provenance.system_root())
    return out
