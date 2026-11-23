"""Arx · pkgtx — ¿esta escritura en un fichero de identidad es de una actualización de paquete?

Piloto d13 (2026-11-22 06:27, unattended-upgrades de sudo): auditd vio nueve escrituras en `/etc/sudoers` y
`/etc/sudoers.d` y cada una salió como un high. Las hicieron `/usr/bin/dpkg` (desplegando `README`) y el `chown` y el
`chmod` del postinst de sudo, hijos suyos, sin sesión de login (auid sin poner). Era sudo, firmado, actualizándose.

Una escritura se explica por una transacción de paquete solo si TODO esto es cierto:
  · dpkg es el auténtico (su md5 contra el del paquete, y de un repositorio firmado): sin él, ni sus hijos ni su
    `dpkg.log` valen, porque un dpkg cambiado escribiría las líneas que quisiera;
  · cada fichero tocado es de un paquete cuya versión instalada viene de un repositorio firmado (no un `.deb` local
    ni un repositorio `trusted=yes`: B43, HZ#7) y ese paquete está EN TRANSACCIÓN según `dpkg.log` cuando se escribió;
  · lo escribió el propio dpkg, o un hijo de sus scripts: una herramienta de un paquete firmado y sin alterar, root y
    sin sesión (una sesión de login nunca se atribuye a un paquete).

Lo que no cumpla algo de eso sigue siendo un high. Los límites, escritos tal cual:
  · A un hijo no se le puede seguir el árbol de procesos (auditd solo trae su ppid, y el proceso ya no existe cuando
    Arx barre): se le atribuye por ventana de tiempo y por ser de un paquete en transacción. Un root sin sesión (un
    servicio comprometido) que escriba, con una herramienta del sistema, un fichero de ese paquete en el segundo de su
    transacción, y lo deje como estaba, no avisa. Si lo deja distinto, lo ve la comprobación de integridad, que
    compara el contenido con la base sellada y solo da por buena la escritura si TODOS los autores son dpkg.
  · `dpkg.log` va en segundos enteros y lo puede escribir un root: la ventana es el segundo entero de sus líneas.
  · Lo que escribe un hijo de dpkg en una sesión de login (un `sudo apt upgrade` interactivo) no se atribuye: queda
    high. El propio dpkg sí se explica, tenga o no sesión.
  · Un fichero que el paquete deja de traer ya no consta como suyo cuando Arx barre: queda high.
"""
from __future__ import annotations

import collections
import os
import time

from arx.modules import integrity, pkgdb, provenance, sensors

DPKG_LOGS = ("/var/log/dpkg.log.1", "/var/log/dpkg.log")
TAIL_BYTES = 4 << 20       # de cada log, solo el final: una transacción reciente está ahí
OPEN_MAX_S = 900           # una transacción sin línea final (dpkg muerto a medias) no queda abierta para siempre
INODES_MAX = 256           # inodos con nombre recordados: lo que un fd escribe luego no trae nombre
INODE_TTL_S = 60.0
INODE_NAMES = 4            # nombres por inodo (se reutiliza al borrar y crear)
_DPKG_SUFFIXES = (".dpkg-new", ".dpkg-tmp", ".dpkg-old", ".dpkg-dist", ".dpkg-bak")
_UNSET = ("4294967295", "-1", "unset")

# Cada acción de dpkg.log y la línea de estado que la termina (la de `upgrade` es la de la versión NUEVA: la vieja
# también sale como «unpacked» a mitad de camino).
_ENDS = {"install": ("unpacked",), "upgrade": ("unpacked",), "configure": ("installed",),
         "trigproc": ("installed",), "remove": ("config-files", "not-installed"), "purge": ("not-installed",)}
_BY_VERSION = ("unpacked", "installed")  # los demás estados terminales no repiten la versión

_windows_cache: dict = {"sig": None, "windows": {}}
_inodes: collections.OrderedDict = collections.OrderedDict()  # (dev, inodo) → [(instante, ruta)]


def clear_cache() -> None:
    _windows_cache.update(sig=None, windows={})
    _inodes.clear()


# ── transacciones: dpkg.log ──────────────────────────────────────────────────
def _to_epoch(text: str) -> float | None:
    """`2026-11-22 06:26:49` (dpkg escribe la hora local) → segundos."""
    try:
        return time.mktime(time.strptime(text, "%Y-%m-%d %H:%M:%S"))
    except (ValueError, OverflowError):
        return None


def _signature() -> tuple:
    out = []
    for path in DPKG_LOGS:
        try:
            st = os.stat(path)
            out.append((path, st.st_ino, st.st_size, st.st_mtime_ns))
        except OSError:
            out.append((path, None))
    return tuple(out)


def _tail_lines(path: str) -> list[str]:
    try:
        with open(path, "rb") as f:
            size = f.seek(0, os.SEEK_END)
            start = max(0, size - TAIL_BYTES)
            f.seek(start)
            data = f.read()
    except OSError:
        return []
    if start:
        data = data[data.find(b"\n") + 1:]  # la primera línea del final puede venir cortada
    return data.decode("utf-8", "replace").splitlines()


def _parse(lines: list[str]) -> dict[str, list[dict]]:
    """{paquete: [{t0, t1, ver, kind}]}: cada acción abre una ventana y su línea de estado final la cierra."""
    out: dict[str, list[dict]] = {}
    for line in lines:
        parts = line.split()
        if len(parts) < 5:
            continue
        kind = parts[2]
        if kind in _ENDS:
            t = _to_epoch(f"{parts[0]} {parts[1]}")
            if t is None:
                continue
            name = parts[3].partition(":")[0]
            ver = parts[5] if kind in ("install", "upgrade") and len(parts) >= 6 else parts[4]
            out.setdefault(name, []).append({"t0": t, "t1": None, "ver": ver, "kind": kind})
        elif kind == "status" and len(parts) >= 6:
            t = _to_epoch(f"{parts[0]} {parts[1]}")
            if t is None:
                continue
            state, name, ver = parts[3], parts[4].partition(":")[0], parts[5]
            for w in reversed(out.get(name, ())):
                if w["t1"] is None and state in _ENDS[w["kind"]] and (state not in _BY_VERSION or ver == w["ver"]):
                    w["t1"] = t
                    break
    return out


def windows() -> dict[str, list[dict]]:
    sig = _signature()
    if _windows_cache["sig"] != sig:
        lines: list[str] = []
        for path in DPKG_LOGS:
            lines += _tail_lines(path)
        _windows_cache.update(sig=sig, windows=_parse(lines))
    return _windows_cache["windows"]


def transaction(name: str, ts: float) -> dict | None:
    """La ventana del paquete que cubre el instante `ts` (el segundo entero de su línea final: dpkg.log no tiene más
    resolución), o None."""
    for w in reversed(windows().get(name.partition(":")[0], ())):
        end = w["t1"] + 1.0 if w["t1"] is not None else w["t0"] + OPEN_MAX_S
        if w["t0"] <= ts < end:
            return w
    return None


def in_transaction(name: str, ts: float) -> bool:
    return transaction(name, ts) is not None


# ── lo que dice auditd de un evento ──────────────────────────────────────────
def facts(records: list[str]) -> dict | None:
    """Los campos de un evento (SYSCALL + CWD + PATH…) que sirven para atribuirlo."""
    sc, cwd, at, paths = {}, "", None, []
    for line in records:
        e = sensors._AUDIT_EVENT.search(line)
        if e and at is None:
            at = float(e.group(1))
        fields = {k: sensors._audit_value(k, v) for k, v in sensors._AUDIT_FIELD.findall(line)}
        if line.startswith("type=SYSCALL"):
            sc = fields
        elif line.startswith("type=CWD"):
            cwd = fields.get("cwd", "")
        elif line.startswith("type=PATH"):
            paths.append(fields)
    if not sc or at is None:
        return None
    return {"at": at, "sc": sc, "cwd": cwd, "paths": paths}


def _absolute(name: str, cwd: str) -> str:
    return os.path.normpath(name if name.startswith("/") or not cwd else os.path.join(cwd, name))


def remember(events: list[list[str]]) -> None:
    """Los nombres de los inodos que los eventos nombran: un `fchown`/`fchmod` sobre un descriptor no trae nombre
    (`name=(null)`), solo el inodo, y el nombre lo dijo el evento que lo creó o abrió, a veces en el barrido anterior."""
    for records in events:
        f = facts(records)
        if not f:
            continue
        for p in f["paths"]:
            name = p.get("name")
            if not name or name == "(null)" or p.get("nametype") == "PARENT" or not p.get("inode"):
                continue
            key = (p.get("dev"), p["inode"])
            names: list = []
            for at, path in sorted(_inodes.pop(key, []) + [(f["at"], _absolute(name, f["cwd"]))]):
                if not names or names[-1][1] != path:  # una racha del mismo nombre cuenta desde la primera vez
                    names.append((at, path))
            _inodes[key] = names[-INODE_NAMES:]
    while len(_inodes) > INODES_MAX:
        _inodes.popitem(last=False)


def _files(f: dict) -> list[str] | None:
    """Los ficheros que tocó el evento (no los directorios padre), con ruta absoluta; None si alguno no se sabe."""
    out = []
    for p in f["paths"]:
        if p.get("nametype") == "PARENT":
            continue
        name = p.get("name")
        if name == "(null)" or not name:
            # el nombre más reciente que se le conoció a ese inodo hasta este evento (un inodo se reutiliza)
            known = [path for at, path in _inodes.get((p.get("dev"), p.get("inode")), ())
                     if 0 <= f["at"] - at <= INODE_TTL_S]
            if not known:
                return None
            out.append(known[-1])
        else:
            out.append(_absolute(name, f["cwd"]))
    return out or None


def _stem(path: str) -> str:
    """El fichero que dpkg está dejando en su sitio: `README.dpkg-new` es `README`."""
    for suffix in _DPKG_SUFFIXES:
        if path.endswith(suffix) and len(path) > len(suffix) and not path.endswith("/" + suffix):
            return path[:-len(suffix)]
    return path


# ── el criterio de «lo escribió un paquete firmado» (el mismo para el sensor y para la integridad) ──────────────
def verified_owner(path: str) -> str | None:
    """El paquete dueño de `path` si dpkg es el auténtico y el paquete y dpkg vienen de un repositorio firmado
    (la versión INSTALADA de ambos: un .deb local con nombre de repositorio no basta, HZ#7); si no, None."""
    pkg = pkgdb.owner(path)
    if not pkg or provenance.intact(integrity.DPKG, "dpkg") is not True:
        return None
    if provenance.signed_origin("dpkg", installed_only=True)[0] and \
            provenance.signed_origin(pkg, installed_only=True)[0]:
        return pkg
    return None


class Checker:
    """Las comprobaciones de un barrido, una vez por ruta y no una vez por evento."""

    def __init__(self):
        self._owner: dict[str, str | None] = {}
        self._tool: dict[str, bool] = {}
        self._dpkg: bool | None = None

    def dpkg_ok(self) -> bool:
        if self._dpkg is None:
            try:
                self._dpkg = (provenance.intact(integrity.DPKG, "dpkg") is True
                              and bool(provenance.signed_origin("dpkg", installed_only=True)[0]))
            except Exception:  # noqa: BLE001 - sin respuesta de dpkg no se rebaja nada
                self._dpkg = False
        return self._dpkg

    def owner(self, path: str) -> str | None:
        if path not in self._owner:
            try:
                self._owner[path] = verified_owner(path)
            except Exception:  # noqa: BLE001
                self._owner[path] = None
        return self._owner[path]

    def tool(self, exe: str) -> bool:
        """¿Es `exe` un binario de un paquete firmado, sin alterar? (un hijo de un script de mantenimiento)"""
        if exe not in self._tool:
            ok = False
            try:
                pkg = pkgdb.owner(exe) if exe.startswith("/") else None
                ok = bool(pkg and provenance.intact(exe, pkg) is True
                          and provenance.signed_origin(pkg, installed_only=True)[0])
            except Exception:  # noqa: BLE001
                ok = False
            self._tool[exe] = ok
        return self._tool[exe]


def explain(records: list[str], checker: Checker | None = None) -> dict | None:
    """Si el evento es una escritura de una transacción de paquete: {package, version, files, writer, key}; si no, None.
    Ante cualquier duda, None (sigue siendo un high)."""
    try:
        return _explain(records, checker or Checker())
    except Exception:  # noqa: BLE001 - un fallo aquí nunca esconde un evento
        return None


def _explain(records: list[str], checker: Checker) -> dict | None:
    f = facts(records)
    if not f or f["sc"].get("success") != "yes":
        return None
    files = _files(f)
    if not files or not checker.dpkg_ok():
        return None
    sc = f["sc"]
    exe = sc.get("exe", "")
    if exe == integrity.DPKG:
        writer = "dpkg"
    else:
        if sc.get("uid") != "0" or sc.get("euid", sc.get("uid")) != "0" or sc.get("auid") not in _UNSET \
                or sc.get("ses") not in _UNSET or not checker.tool(exe):
            return None
        writer = "script"
    owners: dict[str, dict] = {}
    stems = []
    for path in files:
        stem = _stem(path)
        pkg = checker.owner(stem)
        if not pkg:
            return None
        window = transaction(pkg, f["at"])
        if not window:
            return None
        owners.setdefault(pkg.partition(":")[0], window)
        if stem not in stems:
            stems.append(stem)
    names = sorted(owners)
    return {"packages": names, "package": ", ".join(names), "files": stems, "writer": writer,
            "version": ", ".join(owners[n]["ver"] for n in names),
            "key": "|".join(f"{n}|{owners[n]['ver']}" for n in names)}
