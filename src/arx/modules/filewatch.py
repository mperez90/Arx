"""Arx · filewatch — quién abre los ficheros que valen oro (F18.4).

fanotify (con ctypes, biblioteca estándar) avisa de cada apertura de shadow, de las llaves privadas de
host y de usuarios, de credenciales de nube y de claves TLS. Lo que un servicio abre mientras se le
observa se aprende; un servicio que después abre uno nuevo es lo que hace un intruso que busca llaves:
ese proceso se queda sin red (no puede sacarlas) y se avisa. Los procesos de un usuario no cuentan: son
sesiones, no servicios.
"""
from __future__ import annotations

import collections
import ctypes
import glob
import os
import struct
import threading
import time

FAN_CLASS_NOTIF, FAN_CLOEXEC = 0x0, 0x1
FAN_OPEN = 0x20
FAN_MARK_ADD = 0x1
AT_FDCWD = -100
MARK_EVERY_S = 600
MAX_EVENTS = 4000
SENSITIVE = ("/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/ssh/ssh_host_*_key", "/root/.ssh/id_*",
             "/home/*/.ssh/id_*", "/root/.aws/credentials", "/home/*/.aws/credentials", "/root/.kube/config",
             "/home/*/.kube/config", "/root/.docker/config.json", "/home/*/.docker/config.json", "/etc/ssl/private/*",
             "/root/.gnupg/private-keys-v1.d/*", "/home/*/.gnupg/private-keys-v1.d/*", "/home/*/.bitcoin/wallet.dat",
             "/home/*/.ethereum/keystore/*")

_events: collections.deque = collections.deque(maxlen=MAX_EVENTS)
_state = {"running": False}
_EVENT = struct.Struct("=IBBHQii")  # fanotify_event_metadata


def sensitive_files() -> list[str]:
    out = set()
    for pattern in SENSITIVE:
        out |= {p for p in glob.glob(pattern) if not p.endswith(".pub") and os.path.isfile(p)}
    return sorted(out)


def parse(data: bytes) -> list[tuple[int, int, int]]:
    """(máscara, fd, pid) de cada evento de un bloque leído de fanotify."""
    out, off = [], 0
    while off + _EVENT.size <= len(data):
        length, _, _, _, mask, fd, pid = _EVENT.unpack_from(data, off)
        if length < _EVENT.size:
            break
        out.append((mask, fd, pid))
        off += length
    return out


def _libc():
    libc = ctypes.CDLL(None, use_errno=True)
    libc.fanotify_init.argtypes = [ctypes.c_uint, ctypes.c_uint]
    libc.fanotify_mark.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.c_uint64, ctypes.c_int, ctypes.c_char_p]
    return libc


def _mark(libc, fd: int) -> None:
    for path in sensitive_files():  # un fichero reescrito (passwd) es otro inodo: se vuelve a marcar
        libc.fanotify_mark(fd, FAN_MARK_ADD, FAN_OPEN, AT_FDCWD, path.encode())


def _record(pid: int, path: str, root: str) -> dict | None:
    from arx.modules import execwatch
    if pid == os.getpid() or not path:
        return None
    ev = execwatch.describe(pid, root)  # solo procesos de un servicio; las sesiones no cuentan
    if not ev:
        # el lector efímero (un cat del señuelo vive ms) ya murió: su exec reciente lo nombra (B57, F3)
        ev = execwatch.recent_exec(pid)
    if not ev:
        return None
    ev["file"] = path
    _events.append(ev)
    return ev


def _listen(libc, fd: int, root: str) -> None:
    marked = time.monotonic()
    while True:
        if time.monotonic() - marked > MARK_EVERY_S:
            _mark(libc, fd)
            marked = time.monotonic()
        try:
            data = os.read(fd, 8192)
        except OSError:
            time.sleep(0.5)
            continue
        for _, efd, pid in parse(data):
            if efd < 0:
                continue
            try:
                path = os.readlink(f"/proc/self/fd/{efd}")
            except OSError:
                path = ""
            finally:
                os.close(efd)
            _record(pid, path, root)


def start() -> bool:
    if _state["running"]:
        return True
    try:
        libc = _libc()
        fd = libc.fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC, os.O_RDONLY | getattr(os, "O_LARGEFILE", 0))
    except (OSError, AttributeError):
        return False
    if fd < 0:
        return False
    from arx.modules import provenance
    _mark(libc, fd)
    threading.Thread(target=_listen, args=(libc, fd, provenance.system_root()), name="arx-files",
                     daemon=True).start()
    _state["running"] = True
    return True


def drain() -> list[dict]:
    out = []
    while _events:
        out.append(_events.popleft())
    return out
