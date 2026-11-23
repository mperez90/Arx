"""Arx · procring — qué procesos son del script de mantenimiento de un paquete, visto en tiempo real.

auditd dice quién escribió un fichero y de quién es hijo (el `ppid`), pero cuando Arx barre, 30 s después, ese proceso y su
padre llevan tiempo muertos: la ascendencia no se puede reconstruir a posteriori. Aquí se guarda al momento, en un anillo
acotado, solo lo que sirve para eso:

  · un `exec` cuyo padre es `/usr/bin/dpkg` y que ejecuta `/var/lib/dpkg/info/<P>.{pre,post}{inst,rm}` (o
    `/var/lib/dpkg/tmp.ci/…`, con el paquete que dpkg pone en `DPKG_MAINTSCRIPT_PACKAGE`): el script de mantenimiento de P;
  · un `exec` cuyo padre ya está en el anillo: lo que lanza ese script (y lo que lanza eso).

Nada más: ni los demás hijos de dpkg ni lo que cuelgue de cualquier otro proceso del host. Lo alimenta el hilo del conector
de procesos de `execwatch` (cada `exec` y cada salida del kernel), antes de su trabajo lento, porque lo que se lanza vive
milisegundos.

`ancestry(pid, ppid, instante)` contesta, para lo que auditd vio escribir, si el padre era un proceso del anillo vivo en ese
instante (con el margen del reloj entre lo que apunta Arx y lo que apunta el kernel). Límites:
  · Solo se prueba lo que el vigilante leyó a tiempo: un ayudante que muere antes de que se le lea no figura, y lo que
    cuelgue de él no se prueba. Lo habitual (el chown, el chmod, el sed del propio script) cuelga directamente del script.
  · El anillo vive en el proceso: tras un reinicio de Arx no hay nada de antes (lo que esperaba en `pkgtx` sí se guarda).
  · Quien sea root puede editar `/var/lib/dpkg/info/P.postinst` y lanzar `dpkg --configure P`: sus hijos saldrían como del
    paquete. Lo que cambien de contenido o permisos lo ve la comprobación de integridad.
"""
from __future__ import annotations

import os
import re
import threading
import time

DPKG = "/usr/bin/dpkg"
TTL_S = 3600          # cuánto se recuerda un proceso; una transacción larga, o un evento que espera, caben de sobra
MAX_ENTRIES = 2048
SLACK_S = 2.0         # el instante de Arx y el del kernel no son el mismo reloj ni el mismo momento
MAX_DEPTH = 8
_SCRIPT = re.compile(r"^/var/lib/dpkg/(?:info/(?P<pkg>[A-Za-z0-9][A-Za-z0-9+.:_-]*)\.(?:preinst|postinst|prerm|postrm)"
                     r"|tmp\.ci/(?:preinst|postinst|prerm|postrm))$")

_lock = threading.Lock()
_ring: dict = {}      # (pid, nacimiento) → entrada
_by_pid: dict = {}    # pid → [claves], las más recientes al final


def clear() -> None:
    with _lock:
        _ring.clear()
        _by_pid.clear()


# ── lo que se lee de /proc (aparte, para poder simularlo) ────────────────────
def _read(path: str, limit: int) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(limit)
    except OSError:
        return b""


def _stat(pid: int) -> tuple[int, int] | None:
    """(ppid, nacimiento)."""
    try:
        fields = _read(f"/proc/{pid}/stat", 4096).rsplit(b")", 1)[1].split()
        return int(fields[1]), int(fields[19])
    except (IndexError, ValueError):
        return None


def _exe(pid: int) -> str | None:
    try:
        return os.readlink(f"/proc/{pid}/exe").removesuffix(" (deleted)")
    except OSError:
        return None


def _argv(pid: int) -> list[str]:
    return _read(f"/proc/{pid}/cmdline", 2048).decode("utf-8", "replace").split("\0")[:6]


def _env_package(pid: int) -> str | None:
    for item in _read(f"/proc/{pid}/environ", 65536).split(b"\0"):
        if item.startswith(b"DPKG_MAINTSCRIPT_PACKAGE="):
            return item.split(b"=", 1)[1].decode("utf-8", "replace") or None
    return None


# ── el anillo ─────────────────────────────────────────────────────────────────
def _forget(key: tuple) -> None:
    entry = _ring.pop(key, None)
    if entry:
        keys = _by_pid.get(entry["pid"], [])
        if key in keys:
            keys.remove(key)
        if not keys:
            _by_pid.pop(entry["pid"], None)


def _store(entry: dict, now: float) -> None:
    with _lock:
        for key in [k for k, e in _ring.items() if now - e["at"] > TTL_S]:
            _forget(key)
        key = (entry["pid"], entry["start"])
        _forget(key)
        _ring[key] = entry
        _by_pid.setdefault(entry["pid"], []).append(key)
        while len(_ring) > MAX_ENTRIES:
            _forget(next(iter(_ring)))


def _alive_entry(pid: int) -> dict | None:
    """La entrada más reciente de ese pid que no ha salido (dentro del cerrojo)."""
    for key in reversed(_by_pid.get(pid, [])):
        entry = _ring.get(key)
        if entry and entry["exit"] is None:
            return entry
    return None


def observe_exec(pid: int, now: float | None = None) -> None:
    """Un `exec` del kernel: se guarda si es el script de mantenimiento de un paquete (hijo de dpkg) o si cuelga de uno."""
    try:
        now = time.time() if now is None else now
        st = _stat(pid)
        if not st:
            return
        ppid, start = st
        with _lock:
            parent = _alive_entry(ppid)
        if parent:
            _store({"pid": pid, "start": start, "ppid": ppid, "at": now, "exit": None, "kind": "desc",
                    "parent": (parent["pid"], parent["start"]), "pkg": parent["pkg"], "script": parent["script"],
                    "exe": _exe(pid), "argv": _argv(pid)[:3]}, now)
            return
        if _exe(ppid) != DPKG:
            return
        argv = _argv(pid)
        script = next((a for a in argv[:3] if _SCRIPT.match(a)), None)
        if not script:
            return
        pkg = _SCRIPT.match(script).group("pkg") or _env_package(pid)
        if not pkg:
            return
        _store({"pid": pid, "start": start, "ppid": ppid, "at": now, "exit": None, "kind": "script", "parent": None,
                "pkg": pkg.partition(":")[0], "script": script, "exe": _exe(pid), "argv": argv[:3]}, now)
    except Exception:  # noqa: BLE001 - este camino es el del hilo del conector: nunca lo para
        return


def observe_exit(pid: int, now: float | None = None) -> None:
    """Un proceso del anillo sale: su número deja de ser suyo desde ese instante."""
    try:
        now = time.time() if now is None else now
        with _lock:
            for key in _by_pid.get(pid, ()):
                entry = _ring.get(key)
                if entry and entry["exit"] is None:
                    entry["exit"] = now
    except Exception:  # noqa: BLE001
        return


def _covering(pid: int, at: float) -> dict | None:
    """La entrada de ese pid que estaba viva en `at`."""
    best = None
    for key in _by_pid.get(pid, ()):
        e = _ring.get(key)
        if e and e["at"] - SLACK_S <= at and (e["exit"] is None or at <= e["exit"] + SLACK_S):
            if best is None or e["at"] > best["at"]:
                best = e
    return best


def ancestry(pid: int, ppid: int, at: float) -> dict | None:
    """{"package", "script"} si el proceso `pid`, hijo de `ppid`, escribió en `at` siendo descendiente de un script de
    mantenimiento de dpkg (visto en tiempo real); None si no se puede probar."""
    try:
        with _lock:
            own = _covering(pid, at)
            if own and own["ppid"] != ppid:
                return None  # el número de este proceso lo llevaba otro, con otro padre
            node, depth = _covering(ppid, at), 0
            while node and depth < MAX_DEPTH:
                if node["kind"] == "script":
                    return {"package": node["pkg"], "script": node["script"]}
                node, depth = _ring.get(node["parent"]), depth + 1
    except Exception:  # noqa: BLE001
        return None
    return None
