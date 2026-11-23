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

Una transacción todavía abierta (sin su línea final) no se da por buena a ciegas: el evento ESPERA a que cierre, 5 min
como mucho contados desde el evento, y se decide entonces con la ventana ya cerrada; sin cierre, high. Lo que espera se
guarda en disco (un reinicio de Arx no lo pierde) y tiene tope (el exceso es high, no se descarta).

Lo que no cumpla algo de eso sigue siendo un high. La ventana de un evento es la de SU paquete (el dueño del fichero),
nunca la unión de los paquetes que haya en transacción: de `upgrade P` hasta que dpkg deja P «unpacked» en la versión
nueva, y de `configure P` hasta su «status installed».

El residuo, con su tamaño real. En el dpkg.log del piloto d13 (65 ventanas cerradas de 28 paquetes) la ventana dura 1 s
de mediana y 13 s como máximo (`trigproc` de initramfs-tools); las dos de sudo, 1 s cada una. Un root sin sesión (un
servicio comprometido) que en ese intervalo escriba, con una herramienta de un paquete firmado y sin alterar, un
fichero DE ESE PAQUETE y lo deje como estaba, no avisa: lo que sí cambie de contenido o de permisos lo ve la comprobación
de integridad, que compara con la base sellada y solo da por buena la escritura si TODOS los autores son dpkg. Además:
  · A un hijo no se le puede seguir el árbol de procesos (auditd solo trae su ppid y el proceso ya no existe cuando Arx
    barre): se le atribuye por la ventana y por ser una herramienta firmada. Es la causa del residuo de arriba.
  · `dpkg.log` va en segundos enteros y lo puede escribir un root: la ventana es el segundo entero de sus líneas (hasta
    2 s de dpkg.log contado por exceso); un dpkg alterado no vale (se comprueba antes), un dpkg.log falsificado por
    un root con un dpkg auténtico sí podría abrir una ventana falsa de ese tamaño.
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
DEFER_MAX_S = 300          # lo que cae en una transacción aún abierta espera su cierre esto, desde el evento; luego, high
MAX_DEFERRED = 64          # eventos esperando: el exceso es high, no se descarta
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
_DEFERRED_STATE = "audit-deferred.json"
_deferred: list = []  # [{"at", "records"}]
_deferred_loaded = [False]
_inodes: collections.OrderedDict = collections.OrderedDict()  # (dev, inodo) → [(instante, ruta)]


def clear_cache() -> None:
    _windows_cache.update(sig=None, windows={})
    _inodes.clear()
    _deferred.clear()
    _deferred_loaded[0] = False


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
    resolución), o None. Una ventana cerrada que cubre gana; si solo hay una abierta (`t1` None: sin línea final), esa."""
    open_one = None
    for w in reversed(windows().get(name.partition(":")[0], ())):
        if w["t0"] > ts:
            continue
        if w["t1"] is None:
            open_one = open_one or w
        elif ts < w["t1"] + 1.0:
            return w
    return open_one


def in_transaction(name: str, ts: float) -> bool:
    return transaction(name, ts) is not None


# ── lo que espera a que cierre una transacción ──────────────────────────────
def _deferred_path():
    from arx import config
    return config.state_dir() / _DEFERRED_STATE


def _load_deferred() -> None:
    if _deferred_loaded[0]:
        return
    _deferred_loaded[0] = True
    from arx import config
    data = config.read_json(_deferred_path(), []) or []
    _deferred[:] = [d for d in data if isinstance(d, dict) and isinstance(d.get("at"), (int, float))
                    and isinstance(d.get("records"), list) and all(isinstance(r, str) for r in d["records"])]
    for d in _deferred:  # los nombres que los descriptores de ese evento tenían: la memoria de inodos no sobrevive al reinicio
        for item in d.get("inodes") or []:
            if isinstance(item, list) and len(item) == 3 and all(isinstance(x, str) for x in item):
                _inodes[(item[0], item[1])] = [(d["at"], item[2])]
    while len(_inodes) > INODES_MAX:
        _inodes.popitem(last=False)


def take_deferred() -> list[list[str]]:
    """Lo que esperaba, para volver a juzgarlo; vacía la lista (`defer` lo devuelve si sigue esperando)."""
    _load_deferred()
    out = [d["records"] for d in _deferred]
    _deferred.clear()
    return out


def defer(records: list[str], at: float) -> bool:
    """Deja el evento esperando. False si ya no cabe (el llamador lo da por no explicado)."""
    _load_deferred()
    if len(_deferred) >= MAX_DEFERRED:
        return False
    entry = {"at": at, "records": list(records), "inodes": []}
    f = facts(records)
    for p in (f or {}).get("paths", ()):
        if p.get("nametype") != "PARENT" and p.get("name") in (None, "", "(null)") and p.get("inode"):
            known = [path for when, path in _inodes.get((p.get("dev"), p["inode"]), ()) if 0 <= at - when <= INODE_TTL_S]
            if known:
                entry["inodes"].append([str(p.get("dev")), str(p["inode"]), known[-1]])
    _deferred.append(entry)
    return True


def save_deferred() -> None:
    from arx import config
    try:
        config.write_json(_deferred_path(), _deferred)
    except OSError:
        pass  # sin disco lo que espera sigue en memoria


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


def judge(records: list[str], checker: Checker | None = None) -> tuple[str, dict | None]:
    """("explained", veredicto) · ("pending", {"at"}) si todo cuadra pero el paquete dueño sigue en transacción (hay que
    esperar a que cierre) · ("unexplained", None). Ante cualquier duda, no explicado: sigue siendo un high."""
    try:
        return _judge(records, checker or Checker())
    except Exception:  # noqa: BLE001 - un fallo aquí nunca esconde un evento
        return "unexplained", None


def explain(records: list[str], checker: Checker | None = None) -> dict | None:
    """El veredicto si el evento ya es una escritura de una transacción de paquete cerrada; si no, None."""
    state, verdict = judge(records, checker)
    return verdict if state == "explained" else None


def _judge(records: list[str], checker: Checker) -> tuple[str, dict | None]:
    f = facts(records)
    if not f or f["sc"].get("success") != "yes":
        return "unexplained", None
    files = _files(f)
    if not files or not checker.dpkg_ok():
        return "unexplained", None
    sc = f["sc"]
    exe = sc.get("exe", "")
    if exe == integrity.DPKG:
        writer = "dpkg"
    else:
        if sc.get("uid") != "0" or sc.get("euid", sc.get("uid")) != "0" or sc.get("auid") not in _UNSET \
                or sc.get("ses") not in _UNSET or not checker.tool(exe):
            return "unexplained", None
        writer = "script"
    owners: dict[str, dict] = {}
    stems = []
    pending = False
    for path in files:
        stem = _stem(path)
        pkg = checker.owner(stem)
        if not pkg:
            return "unexplained", None
        window = transaction(pkg, f["at"])
        if not window:
            return "unexplained", None
        pending = pending or window["t1"] is None  # sin línea final: aún no se sabe cuándo acaba
        owners.setdefault(pkg.partition(":")[0], window)
        if stem not in stems:
            stems.append(stem)
    if pending:
        return "pending", {"at": f["at"]}
    names = sorted(owners)
    return "explained", {"packages": names, "package": ", ".join(names), "files": stems, "writer": writer,
                         "version": ", ".join(owners[n]["ver"] for n in names),
                         "key": "|".join(f"{n}|{owners[n]['ver']}" for n in names)}
