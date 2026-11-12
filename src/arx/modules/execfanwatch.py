"""Arx · execfanwatch — identidad mínima antes de permitir cada exec (B59).

Netlink confirma que un `exec` ocurrió, pero su aviso puede llegar cuando el proceso ya terminó.
Este grupo fanotify retiene `FAN_OPEN_EXEC_PERM` solo mientras guarda el ejecutable aportado por el
fd y la identidad de `/proc`; responde `FAN_ALLOW` en `finally`. No lee contenido, no calcula hashes,
no consulta perfiles ni ejecuta ningún auxiliar en ese camino.

Sin `FAN_UNLIMITED_QUEUE`: el desbordamiento y toda pérdida quedan contados. Si el lector se bloquea,
el watchdog cierra el grupo: el kernel libera entonces todos los permisos pendientes (fail-open) y la
cobertura queda explícitamente degradada.
"""
from __future__ import annotations

import collections
import ctypes
import os
import re
import select
import struct
import threading
import time

FAN_CLASS_CONTENT, FAN_CLOEXEC, FAN_NONBLOCK = 0x4, 0x1, 0x2
FAN_OPEN_EXEC_PERM = 0x00040000
FAN_Q_OVERFLOW = 0x00004000
FAN_ALLOW = 0x01
FANOTIFY_METADATA_VERSION = 3
FAN_MARK_ADD, FAN_MARK_FILESYSTEM = 0x1, 0x100
AT_FDCWD = -100
MAX_SNAPSHOTS = 4096
SNAPSHOT_TTL_S = 120
MARK_EVERY_S = 300
POLL_MS = 500
WATCHDOG_STALL_S = 5
MOUNTINFO = "/proc/self/mountinfo"
_EVENT = struct.Struct("=IBBHQii")  # fanotify_event_metadata
_RESPONSE = struct.Struct("=iI")    # fanotify_response

# No son ejecutables locales: pseudo-fs del kernel y montajes de red. Un tipo desconocido se intenta
# marcar; si el kernel no lo admite, queda en `failed` y la cobertura es parcial, nunca «completa».
_IGNORED_FILESYSTEMS = {
    "autofs", "bpf", "cgroup", "cgroup2", "configfs", "debugfs", "devpts", "efivarfs", "fusectl",
    "hugetlbfs", "mqueue", "proc", "pstore", "securityfs", "sysfs", "tracefs", "binfmt_misc",
    "nfs", "nfs4", "cifs", "smb3", "sshfs", "9p", "ceph", "glusterfs", "afs", "ncpfs",
}

_state = {
    "running": False, "mode": "off", "fd": -1, "marks": [], "failed": [],
    "captured": 0, "dropped": 0, "expired": 0, "superseded": 0,
    "overflow": 0, "late": 0, "errors": 0, "responses": 0, "last_progress": 0.0,
}
_lock = threading.Lock()
_snapshots: collections.OrderedDict = collections.OrderedDict()  # secuencia → snapshot; cota estricta
_sequence = 0


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


def _read(path: str, limit: int = 4096) -> str:
    try:
        with open(path, "rb") as fh:
            return fh.read(limit).decode("utf-8", "replace")
    except OSError:
        return ""


def _stat(pid: int) -> tuple[int, int] | None:
    raw = _read(f"/proc/{pid}/stat")
    try:
        fields = raw.rsplit(")", 1)[1].split()
        return int(fields[1]), int(fields[19])
    except (IndexError, ValueError):
        return None


def _uid(pid: int) -> int | None:
    try:
        return os.stat(f"/proc/{pid}").st_uid
    except OSError:
        return None


def _snapshot(efd: int, pid: int, root: str) -> dict | None:
    """Solo identidad, antes de FAN_ALLOW. En particular, nunca copia cmdline/environ: son pre-exec."""
    st = _stat(pid)
    if not st:
        return None
    ppid, start = st
    try:
        exe = os.readlink(f"/proc/self/fd/{efd}").removesuffix(" (deleted)")
    except OSError:
        return None
    cg = next((line[3:].strip().strip("/") for line in _read(f"/proc/{pid}/cgroup").splitlines()
               if line.startswith("0::")), "")
    root = root.strip("/")
    if root:
        if not cg.startswith(root + "/"):
            return None
        cg = cg[len(root) + 1:]
    from arx.modules import execwatch  # ya cargado cuando el hilo corre; solo su regex, ninguna lectura extra
    match = execwatch._SERVICE_RE.match(cg)
    if not match or not exe.startswith("/"):
        return None
    try:
        parent_exe = os.readlink(f"/proc/{ppid}/exe").removesuffix(" (deleted)")
    except OSError:
        parent_exe = ""
    return {
        "pid": pid, "start": start, "ppid": ppid, "exe": exe, "unit": match.group(1),
        "uid": _uid(pid), "parent_uid": _uid(ppid), "parent_exe": parent_exe,
        "_captured_ns": time.monotonic_ns(), "_root": root,
    }


def _prune_locked() -> None:
    cutoff = time.monotonic_ns() - SNAPSHOT_TTL_S * 1_000_000_000
    for key, ev in list(_snapshots.items()):
        if ev.get("_stored_ns", 0) < cutoff:
            _snapshots.pop(key, None)
            _state["expired"] += 1


def _store(ev: dict) -> None:
    global _sequence
    with _lock:
        _prune_locked()
        while len(_snapshots) >= MAX_SNAPSHOTS:
            _snapshots.popitem(last=False)
            _state["dropped"] += 1
        _sequence += 1
        saved = dict(ev)
        saved["_stored_ns"] = time.monotonic_ns()
        _snapshots[_sequence] = saved
        _state["captured"] += 1


def claim(pid: int, root: str, ts: int | None = None) -> tuple[dict | None, bool]:
    """Toma el ejecutable de ESTE timestamp y avisa si ya existe otro exec posterior del mismo PID.

    Un exec dinámico genera varios permisos antes de su único EXEC netlink: primero el binario o script
    solicitado y después su intérprete/cargador ELF. El timestamp separa execs; dentro de esa frontera,
    el primer snapshot es la identidad solicitada y los demás pertenecen a la misma operación. Retirar
    el grupo completo evita tanto llamar «cargador» al exec como confundirlo con un re-exec posterior.

    `_captured_ns` queda en el snapshot para que `has_later()` repita la comprobación después de leer
    `/proc`. Sin un timestamp válido no hay una frontera fiable y se conserva el último snapshot, como
    antes; el conector de los kernels soportados sí lo aporta.
    """
    with _lock:
        _prune_locked()
        root = root.strip("/")
        eligible, later = [], False
        timed = isinstance(ts, int) and ts > 0
        for key, ev in _snapshots.items():
            if ev.get("pid") != pid or ev.get("_root", "") != root:
                continue
            if timed and ev.get("_captured_ns", 0) > ts:
                later = True
                continue
            eligible.append((key, ev))
        if not eligible:
            return None, later
        start = eligible[-1][1].get("start")
        # Con timestamp, todo lo ya confirmado de este nacimiento pertenece al mismo exec. Esto incluye
        # binario/script + intérprete + cargador. Sin timestamp solo puede reclamarse el último.
        group = [pair for pair in eligible if pair[1].get("start") == start] if timed else [eligible[-1]]
        selected = group[0][1]
        for key, _ in group:
            _snapshots.pop(key, None)
        ev = dict(selected)
        captured = ev.get("_captured_ns", 0)
        later = any(other.get("pid") == pid and other.get("start") == start
                    and other.get("_captured_ns", 0) > captured
                    for other in _snapshots.values())
    ev.pop("_stored_ns", None)
    ev.pop("_root", None)
    return ev, later


def has_later(snapshot: dict) -> bool:
    """Descarta enriquecer con `/proc` si hubo otro exec mientras se leía el proceso."""
    captured = snapshot.get("_captured_ns")
    if not isinstance(captured, int):
        return True
    with _lock:
        return any(ev.get("pid") == snapshot.get("pid") and ev.get("start") == snapshot.get("start")
                   and ev.get("_captured_ns", 0) > captured for ev in _snapshots.values())


def has_pending(pid: int, root: str) -> bool:
    """Sin snapshot previo, uno concurrente impide confiar en una identidad leída a posteriori."""
    with _lock:
        return any(ev.get("pid") == pid and ev.get("_root", "") == root.strip("/")
                   for ev in _snapshots.values())


def recover(pid: int, root: str, ts: int | None = None) -> dict | None:
    """Recupera evidencia forense de un exec cuyo proceso ya no puede describirse."""
    ev, _ = claim(pid, root, ts)
    if ev is None:
        return None
    ev.pop("_captured_ns", None)
    ev.update(argv=[], parent_title="", partial=True, gone=True)
    return ev


def discard_through(pid: int, start: int, ts: int | None) -> None:
    """Una descripción viva sustituye los snapshots que netlink ya ha superado."""
    with _lock:
        for key, ev in list(_snapshots.items()):
            if ev.get("pid") != pid or ev.get("start") != start:
                continue
            if isinstance(ts, int) and ts > 0 and ev.get("_captured_ns", 0) > ts:
                continue
            _snapshots.pop(key, None)
            _state["superseded"] += 1


def _respond(fd: int, efd: int) -> bool:
    """El lock impide que un close concurrente reutilice el fd para escribir en otro objeto."""
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
        _close(fd)  # una respuesta corta/fallida no debe dejar este open ni los siguientes esperando
    return ok


def _permission(fd: int, efd: int, pid: int, root: str) -> None:
    """Ni una excepción de captura puede dejar un exec esperando permiso."""
    try:
        snapshot = _snapshot(efd, pid, root)
        if snapshot:
            _store(snapshot)
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


def _unescape(path: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), path)


def discover_mounts(text: str) -> list[tuple[str, str, str]]:
    """(dispositivo, montaje, tipo) locales donde un exec es posible; uno por filesystem."""
    rows, seen = [], set()
    for line in text.splitlines():
        fields = line.split()
        try:
            sep = fields.index("-")
            dev, path, options, fstype = fields[2], _unescape(fields[4]), fields[5], fields[sep + 1]
        except (ValueError, IndexError):
            continue
        if "noexec" in options.split(",") or fstype in _IGNORED_FILESYSTEMS or dev in seen:
            continue
        seen.add(dev)
        rows.append((dev, path, fstype))
    return rows


def _mounts() -> list[tuple[str, str, str]]:
    try:
        with open(MOUNTINFO, encoding="utf-8", errors="replace") as fh:
            return discover_mounts(fh.read())
    except OSError:
        return []


def _mark_mounts(libc, fd: int) -> tuple[list[str], list[dict]]:
    marked, failed = [], []
    for _, path, _ in _mounts():
        ctypes.set_errno(0)
        rc = libc.fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM, FAN_OPEN_EXEC_PERM,
                                AT_FDCWD, os.fsencode(path))
        if rc == 0:
            marked.append(path)
        else:
            failed.append({"path": path, "errno": ctypes.get_errno()})
    if _state["running"] and _state["fd"] == fd:
        _state["marks"], _state["failed"] = marked, failed
    return marked, failed


def _close(fd: int) -> None:
    with _lock:
        if _state["fd"] != fd:
            return
        # Invalida antes de entrar al kernel: ningún write nuevo usará este fd, y un close lento
        # no deja al listener esperando el mutex que necesita para liberar otros permisos.
        _state.update(running=False, fd=-1, mode="degraded")
    try:
        os.close(fd)  # el kernel contesta por nosotros todos los permisos pendientes
    except OSError:
        pass


def _watchdog(fd: int) -> None:
    while _state["running"] and _state["fd"] == fd:
        if time.monotonic() - _state["last_progress"] > WATCHDOG_STALL_S:
            _state["mode"] = "degraded"
            _close(fd)
            return
        time.sleep(0.5)


def _listen(libc, fd: int, root: str, ready: threading.Event) -> None:
    try:
        # Marcar activa permisos de inmediato: nunca se hace antes de tener listener y watchdog.
        marked, failed = _mark_mounts(libc, fd)
        if not marked or not _state["running"] or _state["fd"] != fd:
            return
        _state["mode"] = "partial" if failed else "full"
        _state["last_progress"] = time.monotonic()
        poll = select.poll()
        poll.register(fd, select.POLLIN)
        marked_at = time.monotonic()
        ready.set()
        while _state["running"] and _state["fd"] == fd:
            _state["last_progress"] = time.monotonic()
            try:
                ready_events = poll.poll(POLL_MS)
            except OSError:
                if not _state["running"]:
                    break
                _state["errors"] += 1
                time.sleep(0.1)
                continue
            _state["last_progress"] = time.monotonic()
            if time.monotonic() - marked_at >= MARK_EVERY_S:
                _mark_mounts(libc, fd)  # montajes nuevos e inodos reemplazados; ADD es idempotente
                marked_at = time.monotonic()
            if not ready_events:
                continue
            try:
                data = os.read(fd, 65536)
            except BlockingIOError:
                continue  # poll puede quedar desactualizado al drenar o cerrar desde otro hilo
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
                if mask & FAN_OPEN_EXEC_PERM:
                    _permission(fd, efd, pid, root)
                else:
                    try:
                        os.close(efd)
                    except OSError:
                        pass
    finally:
        ready.set()
        _close(fd)  # también si una excepción inesperada mata al hilo


def start(root: str) -> str:
    """full / partial / unavailable. Netlink sigue siendo la confirmación del exec."""
    if _state["running"]:
        return _state["mode"]
    for key in ("marks", "failed"):
        _state[key] = []
    for key in ("captured", "dropped", "expired", "superseded", "overflow", "late", "errors", "responses"):
        _state[key] = 0
    try:
        libc = _libc()
        fd = libc.fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK,
                                os.O_RDONLY | getattr(os, "O_LARGEFILE", 0) | os.O_CLOEXEC)
    except (OSError, AttributeError):
        _state["mode"] = "unavailable"
        return "unavailable"
    if fd < 0:
        _state["mode"] = "unavailable"
        return "unavailable"
    _state.update(running=True, fd=fd, mode="full", last_progress=time.monotonic())
    ready = threading.Event()
    try:
        threading.Thread(target=_listen, args=(libc, fd, root, ready), name="arx-exec-fan", daemon=True).start()
        threading.Thread(target=_watchdog, args=(fd,), name="arx-exec-fan-wd", daemon=True).start()
    except (OSError, RuntimeError):
        _close(fd)
        _state["mode"] = "unavailable"
        return "unavailable"
    deadline = time.monotonic() + WATCHDOG_STALL_S + 1
    while not ready.wait(0.05):
        if not _state["running"] or time.monotonic() >= deadline:
            break
    if not _state["running"] or not _state["marks"]:
        _close(fd)
        _state["mode"] = "unavailable"
    return _state["mode"]


def stop() -> None:
    fd = _state["fd"]
    if fd >= 0:
        _close(fd)
    _state["mode"] = "off"


def status() -> dict:
    with _lock:
        return {key: (list(value) if isinstance(value, list) else value) for key, value in _state.items()
                if key != "fd"} | {"snapshots": len(_snapshots)}
