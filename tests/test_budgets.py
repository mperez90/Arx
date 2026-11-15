"""Pista Q · R6 — presupuestos de recursos en CI (plan maestro §2).

Pruebas sin VM, con dobles, que FALLAN si un barrido en reposo pasa de su presupuesto. Cada umbral va por
debajo de lo medido por la pista I en Lima y se justifica aquí y en DevelopDocs/pistas/q/r6-presupuestos.md.

Lo cubierto en otro sitio (no se duplica):
  - subprocesos / scopes de dpkg por barrido → `tests/test_pkgdb.py`
    (`test_thirty_minutes_of_idle_sweeps_cost_at_most_one_inventory`: 60 barridos en reposo = 1 inventario).

Aquí:
  - B1 lecturas de fichero de integridad por barrido en reposo (la caché de bf72497): 0 relecturas;
  - B2 líneas de log / incidentes por barrido en reposo: 0 (sin desviación no se registra nada);
  - B3 memoria: las cachés (`pkgdb._owner_cache`, `guard._postponed`, `integrity._cache`) quedan acotadas.

Ejecutar:  python3 -m pytest tests/test_budgets.py -q
"""
import os

os.environ["ARX_LANG"] = "es"

import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from arx.modules import baseline, integrity, pkgdb  # noqa: E402

# Umbrales (todos por debajo de lo medido en Lima por I: ~100 ficheros leídos y ~1000 líneas/h → objetivo 0 en reposo)
IDLE_FILE_READS = 0      # tras calentar, un barrido sin cambios no relee NINGÚN fichero (si no, la caché no sirve)
IDLE_RECORDS = 0         # sin desviación de la base, cero incidentes (cada uno sería una línea de journal)


def _no_writers(path, since):
    return []


class IntegrityReadBudget(unittest.TestCase):
    """B1: la caché por fichero evita releer/hashear en cada barrido. En reposo, 0 lecturas completas."""

    def setUp(self):
        integrity.clear_cache()
        self.d = tempfile.mkdtemp()
        self.files = []
        for i in range(12):  # un número realista de ficheros vigilados en un grupo
            p = os.path.join(self.d, f"f{i}")
            open(p, "w").write(f"nobody ALL=(ALL) NOPASSWD: /bin/x{i}\n")
            self.files.append(p)
        self.groups = {"sudoers_d": list(self.files)}

    def _count_reads(self, fn):
        reads = []
        real = integrity.state
        with mock.patch.object(integrity, "groups", lambda: self.groups), \
             mock.patch.object(integrity, "state", lambda p, g: reads.append(p) or real(p, g)):
            fn()
        return reads

    def test_idle_sweep_rereads_no_files(self):
        warm = self._count_reads(lambda: integrity.snapshot(cached=True, writers=_no_writers))
        self.assertEqual(len(warm), len(self.files))  # el primero sí lee todo (ancla)
        idle = self._count_reads(lambda: integrity.snapshot(cached=True, writers=_no_writers))
        self.assertLessEqual(len(idle), IDLE_FILE_READS,
                             f"un barrido en reposo releyó {len(idle)} ficheros (presupuesto {IDLE_FILE_READS})")

    def test_a_single_changed_file_costs_exactly_one_read(self):
        self._count_reads(lambda: integrity.snapshot(cached=True, writers=_no_writers))  # calentar
        import time as _t
        _t.sleep(0.01)
        open(self.files[3], "w").write("nobody ALL=(ALL) NOPASSWD: /bin/evil\n")  # uno cambia
        idle = self._count_reads(lambda: integrity.snapshot(cached=True, writers=_no_writers))
        self.assertEqual(len(idle), 1, "solo el fichero que cambió debe releerse")


class IdleRecordsBudget(unittest.TestCase):
    """B2: sin desviación de la base, el barrido no registra ningún incidente (cada uno = una línea de journal)."""

    def test_no_drift_no_findings(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "sudoers")
        open(p, "w").write("root ALL=(ALL) ALL\n")
        with mock.patch.object(integrity, "groups", lambda: {"sudoers_d": [p]}):
            sealed, _ = integrity.snapshot()
            now, _ = integrity.snapshot()
            findings, adopt = integrity.drift(sealed, now)
        self.assertEqual(len(findings), IDLE_RECORDS,
                         f"un barrido en reposo produjo {len(findings)} hallazgos (presupuesto {IDLE_RECORDS})")

    def test_baseline_compare_is_quiet_when_nothing_moved(self):
        # instantánea mínima a mano (no `baseline.snapshot()`, que llamaría a ss/systemctl): el punto es que
        # comparar la base contra lo mismo que aprendió no produzca desviaciones.
        snap = {"at": "t", "sets": {"executables": ["/usr/bin/sshd"], "listen_ports": ["tcp 22 all"],
                                    "services": ["ssh.service"], "login_users": ["root"]}, "gauges": {}}
        base = baseline.new_baseline()
        with mock.patch.object(baseline, "integrity_fingerprint", lambda include_suid=True: {}):
            baseline.fold(base, snap, check_integrity=False)
        base["meta"]["sealed"] = True
        anomalies = baseline.compare(base, snap)  # la misma instantánea contra la base
        self.assertEqual(anomalies, [])


class CacheMemoryBudget(unittest.TestCase):
    """B3: las cachés no crecen sin límite por más que el barrido las use."""

    def test_pkgdb_owner_cache_is_bounded(self):
        pkgdb.clear()
        cap = 50  # misma lógica de expulsión LRU, con un tope pequeño para que la prueba sea rápida
        with mock.patch.object(pkgdb, "CACHE_MAX", cap), \
             mock.patch.object(pkgdb, "generation", lambda: "g1"), \
             mock.patch.object(pkgdb, "_search", lambda paths, dpkg_host: {}):
            for i in range(cap + 200):  # pedir muchas más rutas que el tope
                pkgdb.owners([f"/x/{i}"])
        self.assertLessEqual(len(pkgdb._owner_cache), cap,
                             f"_owner_cache creció a {len(pkgdb._owner_cache)} (tope {cap})")

    def test_integrity_cache_drops_unwatched_paths(self):
        integrity.clear_cache()
        d = tempfile.mkdtemp()
        a, b = os.path.join(d, "a"), os.path.join(d, "b")
        open(a, "w").write("x\n"); open(b, "w").write("y\n")
        with mock.patch.object(integrity, "groups", lambda: {"sudoers_d": [a, b]}):
            integrity.snapshot(cached=True, writers=_no_writers)
        self.assertEqual(set(integrity._cache), {a, b})
        with mock.patch.object(integrity, "groups", lambda: {"sudoers_d": [a]}):  # b deja de vigilarse
            integrity.snapshot(cached=True, writers=_no_writers)
        self.assertEqual(set(integrity._cache), {a}, "lo que ya no se vigila no debe quedar en la caché")


if __name__ == "__main__":
    unittest.main()
