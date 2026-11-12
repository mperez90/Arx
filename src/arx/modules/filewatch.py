"""Arx · filewatch — quién abre los ficheros que valen oro (F18.4/B59).

`FAN_OPEN_PERM` retiene una apertura sensible solo mientras capturamos `(pid, nacimiento)`; después
respondemos `FAN_ALLOW` en `finally`. Esa identidad fuerte evita atribuir una llave a un proceso que
reutilizó el pid. No hay análisis, hashes ni respuesta defensiva en el camino del permiso.
"""
from __future__ import annotations

import collections
import ctypes
import glob
import os
import select
import struct
import threading
import time

FAN_CLASS_CONTENT, FAN_CLOEXEC = 0x4, 0x1
FAN_OPEN_PERM = 0x00010000
FAN_Q_OVERFLOW = 0x00004000
FAN_ALLOW = 0x01
FANOTIFY_METADATA_VERSION = 3
FAN_MARK_ADD = 0x1
AT_FDCWD = -100
MARK_EVERY_S = 600
POLL_MS = 500
WATCHDOG_STALL_S = 5
MAX_EVENTS = 4000
SENSITIVE = ("/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/ssh/ssh_host_*_key", "/root/.ssh/id_*",
             "/home/*/.ssh/id_*", "/root/.aws/credentials", "/home/*/.aws/credentials", "/root/.kube/config",
             "/home/*/.kube/config", "/root/.docker/config.json", "/home/*/.docker/config.json", "/etc/ssl/private/*",
             "/root/.gnupg/private-keys-v1.d/*", "/home/*/.gnupg/private-keys-v1.d/*", "/home/*/.bitcoin/wallet.dat",
             "/home/*/.ethereum/keystore/*")

_events: collections.deque = collections.deque(maxlen=MAX_EVENTS)
_state = {"running": False, "mode": "off", "fd": -1, "marks": [], "failed": [],
          "overflow": 0, "late": 0, "errors": 0, "responses": 0, "last_progress": 0.0}
_lock = threading.Lock()
_EVENT = struct.Struct("=IBBHQii")  # fanotify_event_metadata
_RESPONSE = struct.Struct("=iI")    # fanotify_response


def sensitive_files() -> list[str]:
    out = set()
    for pattern in SENSITIVE:
        out |= {p for p in glob.glob(pattern) if not p.endswith(".pub") and os.path.isfile(p)}
    return sorted(out)


def parse(data: bytes) -> list[tuple[int, int, int]]:
    """(máscara, fd, pid) de cada evento de un bloque leído de fanotify."""
    out, off = [], 0
    while off + _EVENT.size <= len(data):
        length, version, _, metadata_len, mask, fd, pid = _EVENT.unpack_from(data, off)
        if (version != FANOTIFY_METADATA_VERSION or metadata_len < _EVENT.size or length < metadata_len
                or off + length > len(data)):
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
    marked, failed = [], []
    for path in sensitive_files():  # un fichero reescrito (passwd) es otro inodo: se vuelve a marcar
        ctypes.set_errno(0)
        rc = libc.fanotify_mark(fd, FAN_MARK_ADD, FAN_OPEN_PERM, AT_FDCWD, path.encode())
        if rc == 0:
            marked.append(path)
        else:
            failed.append({"path": path, "errno": ctypes.get_errno()})
    _state["marks"], _state["failed"] = marked, failed


def _record(pid: int, start: int, path: str, root: str) -> dict | None:
    from arx.modules import execwatch
    if pid == os.getpid() or not path or not isinstance(start, int):
        return None
    ev = execwatch.describe(pid, root)  # solo procesos de un servicio; las sesiones no cuentan
    if ev and ev.get("start") != start:
        ev = None  # el pid cambió de proceso entre el permiso y describe()
    if not ev:
        # el lector efímero ya murió: solo el exec con el MISMO nacimiento puede nombrarlo
        ev = execwatch.recent_exec(pid, start)
    if not ev:
        return None
    ev["file"] = path
    _events.append(ev)
    return ev


def _respond(fd: int, efd: int) -> bool:
    failed = False
    with _lock:
        if not _state["running"] or _state["fd"] != fd:
            _state["late"] += 1
            return False
        try:
            ok = os.write(fd, _RESPONSE.pack(efd, FAN_ALLOW)) == _RESPONSE.size
        except OSError:
            ok = False
        if ok:
            _state["responses"] += 1
        else:
            _state["late"] += 1
            failed = True
    if failed:
        _close(fd)
    return ok


def _permission(fd: int, efd: int, pid: int, path: str, start: int | None, root: str) -> None:
    try:
        _record(pid, start, path, root)
    except Exception:
        _state["errors"] += 1
    finally:
        try:
            _respond(fd, efd)
        finally:
            try:
                os.close(efd)
            except OSError:
                pass


def _event(fd: int, efd: int, pid: int, root: str) -> None:
    """Todo lo necesario para la atribución se captura antes de responder FAN_ALLOW."""
    try:
        path = os.readlink(f"/proc/self/fd/{efd}")
    except OSError:
        path = ""
    from arx.modules import execwatch
    st = execwatch._stat(pid)
    start = st[1] if st else None
    _permission(fd, efd, pid, path, start, root)


def _close(fd: int) -> None:
    with _lock:
        if _state["fd"] != fd:
            return
        _state.update(running=False, fd=-1, mode="degraded")
        try:
            os.close(fd)  # libera en el kernel cualquier apertura que estuviera esperando
        except OSError:
            pass


def _watchdog(fd: int) -> None:
    while _state["running"] and _state["fd"] == fd:
        if time.monotonic() - _state["last_progress"] > WATCHDOG_STALL_S:
            _state["mode"] = "degraded"
            _close(fd)
            return
        time.sleep(0.5)


def _listen(libc, fd: int, root: str) -> None:
    try:
        poll = select.poll()
        poll.register(fd, select.POLLIN)
        marked = time.monotonic()
        while _state["running"] and _state["fd"] == fd:
            _state["last_progress"] = time.monotonic()
            try:
                ready = poll.poll(POLL_MS)
            except OSError:
                if not _state["running"]:
                    break
                _state["errors"] += 1
                time.sleep(0.1)
                continue
            _state["last_progress"] = time.monotonic()
            if time.monotonic() - marked > MARK_EVERY_S:
                _mark(libc, fd)
                marked = time.monotonic()
            if not ready:
                continue
            try:
                data = os.read(fd, 65536)
            except OSError:
                if not _state["running"]:
                    break
                _state["errors"] += 1
                time.sleep(0.1)
                continue
            for mask, efd, pid in parse(data):
                if mask & FAN_Q_OVERFLOW:
                    _state["overflow"] += 1
                if efd < 0:
                    continue
                if mask & FAN_OPEN_PERM:
                    _event(fd, efd, pid, root)
                else:
                    try:
                        os.close(efd)
                    except OSError:
                        pass
    finally:
        _close(fd)


def start() -> bool:
    if _state["running"]:
        return True
    for key in ("marks", "failed"):
        _state[key] = []
    for key in ("overflow", "late", "errors", "responses"):
        _state[key] = 0
    try:
        libc = _libc()
        fd = libc.fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC,
                                os.O_RDONLY | getattr(os, "O_LARGEFILE", 0) | os.O_CLOEXEC)
    except (OSError, AttributeError):
        _state["mode"] = "unavailable"
        return False
    if fd < 0:
        _state["mode"] = "unavailable"
        return False
    _state.update(running=True, fd=fd, mode="full", last_progress=time.monotonic())
    from arx.modules import provenance
    _mark(libc, fd)
    if not _state["marks"]:
        _close(fd)
        _state["mode"] = "unavailable"
        return False
    _state["mode"] = "partial" if _state["failed"] else "full"
    try:
        threading.Thread(target=_listen, args=(libc, fd, provenance.system_root()), name="arx-files",
                         daemon=True).start()
        threading.Thread(target=_watchdog, args=(fd,), name="arx-files-wd", daemon=True).start()
    except (OSError, RuntimeError):
        _close(fd)
        _state["mode"] = "unavailable"
        return False
    return True


def stop() -> None:
    fd = _state["fd"]
    if fd >= 0:
        _close(fd)
    _state["mode"] = "off"


def status() -> dict:
    with _lock:
        return {key: (list(value) if isinstance(value, list) else value) for key, value in _state.items()
                if key != "fd"}


def drain() -> list[dict]:
    out = []
    while _events:
        out.append(_events.popleft())
    return out
