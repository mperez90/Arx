"""Pista Q · revisión adversaria de la caché de integridad (bf72497).

La caché evita releer/hashear ~100 ficheros cada 30 s. Un fichero se relee si cambia su `lstat` (incluido
`ctime_ns`, que un `touch -r` no puede devolver), si auditd vio una escritura, o cada FULL_RECHECK_S (1 h).

Anclas en VERDE (buena conducta, regresión):
  - un fichero sin cambios se sirve de la caché (no se relee);
  - un cambio de contenido (sube mtime/ctime) se relee y se ve;
  - un cambio de permisos (el modo entra en la clave; chmod sube ctime) se relee;
  - un escritor de auditd en tiempo real invalida la caché;
  - tras FULL_RECHECK_S se relee aunque nada parezca cambiar.

HZ#8 (ROJO, acotado) — evasión por reloj: un atacante con root y CAP_SYS_TIME retrocede el reloj a la fecha
original del fichero, escribe contenido malicioso del MISMO tamaño y restaura mtime/ctime/modo → `lstat` idéntica;
y el evento de auditd de esa escritura queda con fecha vieja, así que `writers_of(path, since)` lo filtra. Las
DOS defensas (clave de lstat y escritor) dependen del reloj → la caché sirve el estado LIMPIO hasta la relectura
horaria. Fix sugerido: invalidar por una señal monótona (el serial de auditd), no por el `at` de reloj de pared.

Ejecutar:  python3 -m pytest tests/test_adv_integrity_cache.py -q
"""
import os

os.environ["ARX_LANG"] = "es"

import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from arx.modules import integrity as I  # noqa: E402


def _writers_of(events):
    """Como sensors.writers_of: filtra los eventos por `since` (at >= since)."""
    def w(path, since):
        return [e for e in events if since is None or float(e["at"]) >= since]
    return w


class CacheGoodBehavior(unittest.TestCase):

    def setUp(self):
        I.clear_cache()
        self.d = tempfile.mkdtemp()
        self.p = os.path.join(self.d, "sudoers")
        open(self.p, "w").write("nobody ALL=(ALL) ALL\n")

    def test_unchanged_file_is_served_from_cache(self):
        s1 = I.cached_state(self.p, "sudoers_d", _writers_of([]), now=1000.0)
        s2 = I.cached_state(self.p, "sudoers_d", _writers_of([]), now=1001.0)
        self.assertIs(s1, s2)

    def test_content_change_is_reread(self):
        s1 = I.cached_state(self.p, "sudoers_d", _writers_of([]), now=1000.0)
        time.sleep(0.01)
        open(self.p, "w").write("nobody ALL=(ALL) NOPASSWD: ALL\n")
        s2 = I.cached_state(self.p, "sudoers_d", _writers_of([]), now=1001.0)
        self.assertNotEqual(s1["sha"], s2["sha"])

    def test_permission_change_is_reread(self):
        I.cached_state(self.p, "sudoers_d", _writers_of([]), now=1000.0)
        time.sleep(0.01)
        os.chmod(self.p, 0o666)
        s2 = I.cached_state(self.p, "sudoers_d", _writers_of([]), now=1001.0)
        self.assertEqual(s2["mode"], 0o666)

    def test_realtime_writer_invalidates(self):
        s1 = I.cached_state(self.p, "sudoers_d", _writers_of([]), now=2000.0)
        ev = [{"at": s1["at"] + 1, "exe": "/usr/bin/sed"}]
        s2 = I.cached_state(self.p, "sudoers_d", _writers_of(ev), now=2001.0)
        self.assertIsNot(s2, s1)

    def test_hourly_full_recheck(self):
        s1 = I.cached_state(self.p, "sudoers_d", _writers_of([]), now=3000.0)
        s2 = I.cached_state(self.p, "sudoers_d", _writers_of([]), now=3000.0 + I.FULL_RECHECK_S + 1)
        self.assertIsNot(s2, s1)


class ClockRollbackEvadesCache(unittest.TestCase):
    """HZ#8: el retroceso de reloj vence las dos defensas a la vez (acotado a FULL_RECHECK_S)."""

    def setUp(self):
        self._stat_key = I._stat_key
        self.addCleanup(lambda: setattr(I, "_stat_key", self._stat_key))
        I.clear_cache()
        self.d = tempfile.mkdtemp()
        self.p = os.path.join(self.d, "sudoers")
        open(self.p, "w").write("nobody ALL=(ALL) ALL\n")

    def test_restored_stat_key_plus_backdated_writer_is_still_detected(self):
        clean = I.cached_state(self.p, "sudoers_d", _writers_of([]), now=3000.0)
        at_cache, sha_clean = clean["at"], clean["sha"]
        # el atacante escribe contenido malicioso en disco…
        open(self.p, "w").write("nobody ALL=(ALL) NOPASSWD: ALL\n")
        # …pero restaura dev/ino/size/mtime/ctime/modo/dueño (reloj retrocedido): lstat idéntica
        fixed_key = (1, 2, 21, 1234, 1234, 0o440, 0, 0)
        I._stat_key = lambda path: fixed_key
        I.clear_cache()
        I._cache[self.p] = (fixed_key, {**clean, "sha": sha_clean}, 3000.0)
        # y el evento de auditd de esa escritura queda con fecha vieja (reloj retrocedido) → se filtra
        ev_backdated = [{"at": at_cache - 9999, "exe": "/usr/bin/sed", "pid": "1"}]
        served = I.cached_state(self.p, "sudoers_d", _writers_of(ev_backdated), now=3001.0)
        # DEBE releer y ver el contenido malicioso; hoy sirve el sha LIMPIO (hueco acotado a 1 h)
        self.assertNotEqual(served["sha"], sha_clean,
                            "el retroceso de reloj esconde el cambio hasta la relectura horaria")


if __name__ == "__main__":
    unittest.main()
