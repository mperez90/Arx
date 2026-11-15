"""Arx · pkgdb: lo que dpkg sabe, preguntado una vez por cambio (B78)

Cada pregunta a dpkg abre un scope de systemd (el aislamiento del OOM de rc1, ver `maintenance`). Antes, cada
barrido de 30 s volvía a pedir el inventario completo y a preguntar por cada fichero: ~490 scopes/h, ~1.000
líneas/h de journal y un 2 % de CPU en un host en reposo. Aquí hay una sola puerta:

  · `generation()`: la identidad de la base de dpkg. Cambia cuando dpkg termina una transacción
    (`status` se reemplaza), mientras corre una (`updates/` tiene su diario) o cuando cambian los desvíos.
  · `versions()`: UN `dpkg-query -W` por generación, con paquete, arquitectura, versión y paquete fuente.
  · `owners(rutas)`: `dpkg-query -S` por lotes (una llamada para todas las rutas), en caché por generación.

Reglas que no se negocian:
  · Una falta de respuesta (`NoAnswer`) sube a quien preguntó y no se guarda nunca: un `{}` o un «de ningún
    paquete» inventado se leería como «nada cambió» y callaría una actualización o una librería inyectada.
  · La generación se lee ANTES de preguntar. Si dpkg cambia mientras tanto, el dato queda guardado bajo la
    generación vieja y la siguiente consulta lo renueva: nunca se guarda un dato viejo bajo una generación nueva.
  · Sin generación (no hay `status`, no se puede leer `updates/`) no se guarda nada: se pregunta cada vez.

El que ejecuta es `provenance._q`, por `maintenance`: mismo aislamiento, mismo `NoAnswer`.
"""
from __future__ import annotations

import os
import threading
from collections import OrderedDict
from collections.abc import Iterable, Mapping
from types import MappingProxyType
from typing import NamedTuple

from arx.modules import maintenance

STATUS = "/var/lib/dpkg/status"
UPDATES = "/var/lib/dpkg/updates"
DIVERSIONS = "/var/lib/dpkg/diversions"

NoAnswer = maintenance.NoAnswer

_FORMAT = "-f=${Package}\t${Architecture}\t${Version}\t${source:Package}\t${source:Version}\n"
INVENTORY_TIMEOUT_S = 30
SEARCH_TIMEOUT_S = 30
BATCH_PATHS = 200            # rutas por `dpkg-query -S`: el coste es recorrer las listas de dpkg, no cuántas se piden
BATCH_BYTES = 64 * 1024      # y el argv, lejos del límite del sistema
MAX_PATH = 4096
CACHE_MAX = 4096             # rutas en caché por generación
WARM_MAX = 512               # las usadas en la generación anterior se renuevan en la misma llamada que la primera

# dpkg-query -S imprime los desvíos como «diversion by X from: ruta»; no dicen quién es el dueño
_DIVERSION = ("diversion by", "local diversion")


class Package(NamedTuple):
    name: str
    arch: str
    version: str
    source: str
    source_version: str


class Inventory:
    """Los paquetes de una generación de dpkg. Se busca por `nombre:arq` o por `nombre`.

    Un nombre sin arquitectura que está instalado en varias (multiarch) se resuelve al primero que lista dpkg,
    como siempre hizo el inventario de versiones; quien necesite otro pide `nombre:arq`."""

    def __init__(self, generation: str | None, rows: list[Package]):
        self.generation = generation
        self.entries: tuple[Package, ...] = tuple(rows)
        by_key: dict[str, Package] = {}
        for pkg in rows:
            by_key[f"{pkg.name}:{pkg.arch}"] = pkg
            by_key.setdefault(pkg.name, pkg)
        self._by_key = by_key
        self.by_key: Mapping[str, Package] = MappingProxyType(by_key)
        self.versions: Mapping[str, str] = MappingProxyType({k: p.version for k, p in by_key.items()})

    def get(self, pkg: str) -> Package | None:
        found = self._by_key.get(pkg)
        if found is None:
            name, _, arch = pkg.partition(":")
            if arch == "any":  # `dpkg-query -W nombre:any`
                found = self._by_key.get(name)
        return found

    def __len__(self) -> int:
        return len(self.entries)


_lock = threading.Lock()                 # estado compartido: el inventario y la caché de dueños
_inventory_flight = threading.Lock()     # un solo `dpkg-query -W` a la vez: los demás esperan su resultado
_inventory: Inventory | None = None
_owner_gen: str | None = None
_owner_cache: "OrderedDict[str, str | None]" = OrderedDict()


def clear() -> None:
    """Olvida todo lo guardado (las pruebas, y quien sepa que dpkg cambió sin dejar rastro)."""
    global _inventory, _owner_gen
    with _lock:
        _inventory, _owner_gen = None, None
        _owner_cache.clear()


def _q(argv: list[str], timeout: int, ok: tuple = (0,)) -> str | None:
    from arx.modules import provenance  # perezoso: provenance importa este módulo
    return provenance._q(argv, timeout=timeout, strict=True, ok=ok)


# ── la identidad de la base de dpkg ──────────────────────────────────────────
def generation() -> str | None:
    """Identidad de la base de dpkg, o None si no se puede asegurar (entonces nada se guarda).

    `status`: inodo, tamaño y `mtime_ns` (dpkg lo reemplaza entero, y un `touch` también se nota). `updates/`:
    el diario de una transacción en curso o interrumpida, con tamaño y fecha de cada entrada. `diversions`:
    `dpkg-divert` cambia quién es dueño de una ruta sin tocar `status`."""
    try:
        st = os.stat(STATUS)
    except OSError:
        return None
    parts = [f"s{st.st_ino}:{st.st_size}:{st.st_mtime_ns}"]
    try:
        with os.scandir(UPDATES) as entries:
            journal = []
            for entry in entries:
                try:
                    es = entry.stat(follow_symlinks=False)
                    journal.append(f"{entry.name}:{es.st_size}:{es.st_mtime_ns}")
                except OSError:  # desapareció entre listar y mirar: la transacción acaba de terminar
                    journal.append(entry.name)
    except FileNotFoundError:
        journal = []
    except OSError:
        return None
    parts.append("u" + ",".join(sorted(journal)))
    try:
        ds = os.stat(DIVERSIONS)
        parts.append(f"d{ds.st_ino}:{ds.st_size}:{ds.st_mtime_ns}")
    except OSError:
        parts.append("d-")
    return "|".join(parts)


# ── versiones ────────────────────────────────────────────────────────────────
def _parse_inventory(out: str) -> list[Package]:
    rows = []
    for line in out.splitlines():
        f = line.split("\t")
        if len(f) == 5 and f[0] and f[2]:  # sin versión no hay nada que comparar (como antes)
            rows.append(Package(f[0], f[1], f[2], f[3] or f[0], f[4] or f[2]))
    return rows


def versions() -> Inventory:
    """El inventario de esta generación de dpkg: un `dpkg-query -W` por cambio, compartido por todos.
    Sin respuesta de dpkg lanza NoAnswer (nunca un inventario vacío que se leería como «nada cambió»)."""
    global _inventory
    gen = generation()
    with _lock:
        if gen is not None and _inventory is not None and _inventory.generation == gen:
            return _inventory
    with _inventory_flight:
        with _lock:  # quien esperaba la ranura encuentra ya el resultado de otro
            if gen is not None and _inventory is not None and _inventory.generation == gen:
                return _inventory
        out = _q(["dpkg-query", "-W", _FORMAT], INVENTORY_TIMEOUT_S)
        if out is None and gen is not None:  # en un host dpkg, no poder ejecutar la consulta no es «sin paquetes»
            raise NoAnswer("dpkg-query: could not run")
        inv = Inventory(gen, _parse_inventory(out or ""))
        if gen is not None:  # sin generación (no es un host dpkg) se pregunta cada vez y no se guarda
            with _lock:
                _inventory = inv
        return inv


def installed_versions() -> Mapping[str, str]:
    """{`paquete:arq` y `paquete`: versión} de todo lo instalado (lectura: no se puede modificar)."""
    return versions().versions


def lookup(pkg: str) -> Package | None:
    """El paquete instalado (`nginx` o `libc6:arm64`), o None si dpkg no lo conoce."""
    return versions().get(pkg)


def version_of(pkg: str) -> str | None:
    found = lookup(pkg)
    return found.version if found else None


# ── dueños de ficheros ───────────────────────────────────────────────────────
def variants(path: str) -> list[str]:
    """La misma ruta antes y después de la fusión de /usr: dpkg puede conocer cualquiera."""
    out = [path]
    real = os.path.realpath(path)
    if real != path:
        out.append(real)
    for p in list(out):
        for short in ("/bin/", "/sbin/", "/lib/", "/lib64/"):
            if p.startswith("/usr" + short):
                out.append(p[4:])
            elif p.startswith(short):
                out.append("/usr" + p)
    return list(dict.fromkeys(out))


def _askable(path) -> bool:
    """Solo rutas absolutas y sanas: `dpkg-query -S` toma patrones y busca por subcadena lo que no empieza por `/`;
    nada de eso se puede dejar a un nombre de fichero que elige quien lo crea."""
    return isinstance(path, str) and path.startswith("/") and len(path) <= MAX_PATH \
        and "\n" not in path and "\0" not in path


def _batches(paths: list[str]) -> Iterable[list[str]]:
    batch, size = [], 0
    for p in paths:
        if batch and (len(batch) >= BATCH_PATHS or size + len(p) > BATCH_BYTES):
            yield batch
            batch, size = [], 0
        batch.append(p)
        size += len(p) + 1
    if batch:
        yield batch


def _search(paths: list[str], dpkg_host: bool) -> dict[str, str]:
    """{ruta: paquete} de las que dpkg conoce, de una llamada por lote. NoAnswer si dpkg no contesta."""
    found: dict[str, str] = {}
    wanted = set(paths)
    for batch in _batches(paths):
        out = _q(["dpkg-query", "-S", *batch], SEARCH_TIMEOUT_S, ok=(0, 1))  # 1: alguna de ningún paquete
        if out is None and dpkg_host:  # no poder ejecutarlo no es «de ningún paquete»: se guardaría días
            raise NoAnswer("dpkg-query: could not run")
        for line in (out or "").splitlines():
            if line.startswith(_DIVERSION):
                continue
            pkgs, sep, f = line.partition(": ")
            f = f.strip()
            if sep and f in wanted and f not in found:
                found[f] = pkgs.split(",")[0].strip()
    return found


def owners(paths: Iterable[str]) -> dict[str, str | None]:
    """{ruta: paquete dueño, o None si no es de ninguno}. Una llamada a dpkg para todas las que no estén ya en
    caché; la caché vale hasta el siguiente cambio de dpkg. NoAnswer si dpkg no contesta (y no se guarda nada
    de lo que faltó: un «no hay respuesta» no es «no es de ningún paquete»)."""
    global _owner_gen
    result: dict[str, str | None] = {}
    todo: list[str] = []
    for p in dict.fromkeys(paths):
        if _askable(p):
            todo.append(p)
        else:
            result[p] = None
    if not todo:
        return result
    gen = generation()
    refresh: list[str] = []
    with _lock:
        if gen is None:
            _owner_cache.clear()
            _owner_gen = None
        elif _owner_gen != gen:  # dpkg cambió: lo de antes ya no vale, pero se vuelve a preguntar junto
            refresh = list(_owner_cache)[-WARM_MAX:]
            _owner_cache.clear()
            _owner_gen = gen
        for p in todo:
            if p in _owner_cache:
                _owner_cache.move_to_end(p)
                result[p] = _owner_cache[p]
    missing = [p for p in todo if p not in result]
    if not missing:
        return result
    # las rutas se piden con sus variantes (fusión de /usr) y se queda con la primera que dpkg conozca
    asked = {p: variants(p) for p in missing}
    warm = [r for r in refresh if _askable(r) and r not in asked]
    for r in warm:
        asked[r] = variants(r)
    query = list(dict.fromkeys(v for vs in asked.values() for v in vs))
    found = _search(query, gen is not None)  # NoAnswer sube: nada se guarda
    resolved = {p: next((found[v] for v in vs if v in found), None) for p, vs in asked.items()}
    with _lock:
        if gen is not None and _owner_gen == gen:  # nadie rotó la caché a otra generación mientras tanto
            for p, owner in resolved.items():
                _owner_cache[p] = owner
            while len(_owner_cache) > CACHE_MAX:
                _owner_cache.popitem(last=False)
    for p in missing:
        result[p] = resolved[p]
    return result


def owner(path: str) -> str | None:
    return owners([path])[path]

