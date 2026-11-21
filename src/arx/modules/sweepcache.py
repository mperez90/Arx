"""Arx · sweepcache: lo que se lee de fuera, una vez por barrido (B78, A#4)

Cada lectura a `nft` o a `ss` es un proceso nuevo, y `nft list set` de un set con elementos de cgroup cuesta ~2 ms
de CPU POR ELEMENTO (resuelve cada cgroup recorriendo /sys/fs/cgroup: 69.000 `stat` para 58 elementos): en un host en
reposo eran 17 procesos por barrido, el 2,2 % de un núcleo. Aquí se guarda lo leído hasta que empieza el barrido
siguiente (`begin_sweep`), con un tope de edad por si alguien lo usa fuera del bucle.

Reglas: un productor que falla devuelve None y no se guarda (un error no es un «vacío»); quien escribe lo que se leyó
llama a `forget` para no ver lo anterior a su propio cambio; y nada de esto se usa en un camino de acción (bloquear,
cerrar una sesión): ahí se pregunta de nuevo.
"""
from __future__ import annotations

import threading
import time
from typing import Callable, TypeVar

T = TypeVar("T")
MAX_AGE_S = 20.0  # el barrido más largo no llega a esto; fuera del bucle, nada se queda viejo

_lock = threading.Lock()
_store: dict[tuple, tuple[float, object]] = {}
_owner: list = [None]  # el hilo del barrido: solo él usa la caché; fuera de un barrido nada se guarda


def begin_sweep() -> None:
    """Empieza un barrido (en el hilo que lo hace): lo leído en el anterior ya no vale."""
    with _lock:
        _store.clear()
        _owner[0] = threading.get_ident()


def in_sweep() -> bool:
    """¿Estamos en la parte de lectura de un barrido, en su hilo? Fuera (acciones, otros hilos) se pregunta de nuevo."""
    return _owner[0] == threading.get_ident()


def end_sweep() -> None:
    """Acaba la parte de lectura del barrido: lo que venga después (las respuestas, otros hilos) pregunta de nuevo."""
    with _lock:
        _store.clear()
        _owner[0] = None


def memo(key: tuple, produce: Callable[[], T | None], max_age: float = MAX_AGE_S) -> T | None:
    """El valor de `key` de este barrido; si no está, lo produce. Un None (fallo) no se guarda. Fuera de un barrido, o
    desde otro hilo, siempre se produce de nuevo: nadie ve un dato viejo por haber llegado en mal momento."""
    if _owner[0] != threading.get_ident():
        return produce()
    now = time.monotonic()
    with _lock:
        hit = _store.get(key)
        if hit is not None and now - hit[0] < max_age:
            return hit[1]  # type: ignore[return-value]
    value = produce()
    if value is not None:
        with _lock:
            _store[key] = (now, value)
    return value


def forget(prefix: tuple = ()) -> None:
    """Olvida lo guardado bajo `prefix` (todo si va vacío): alguien acaba de cambiar lo que se leyó."""
    with _lock:
        for key in [k for k in _store if k[:len(prefix)] == prefix]:
            del _store[key]
