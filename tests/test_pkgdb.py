"""B78 · Mantenimiento casi en reposo: presupuesto de consultas a dpkg en el barrido del perfil.

Un dpkg simulado (`dpkgfake`) detrás de `maintenance.run` cuenta cada consulta (en el host, cada una es un scope
de systemd). Lo que se comprueba: un host quieto no consulta; un cambio de dpkg cuesta una consulta de inventario
y una de dueños; los servicios sin nada que aprender esperan cada vez más; y ninguna respuesta que falte se lee
como «nada cambió». Corre con:  python -m unittest discover -s tests
"""
import os

os.environ["ARX_LANG"] = "es"

import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

from dpkgfake import FakeDpkg, fake_world  # noqa: E402


class HostIdleBudgetTests(unittest.TestCase):
    """El reposo no consulta a dpkg: los servicios sin proceso no se reintentan cada barrido."""

    NOW = datetime(2026, 11, 14, tzinfo=timezone.utc)

    def setUp(self):
        from arx.modules import profile
        self.p = profile
        self.fake = fake_world(self)
        self.fake.install("nginx", "1.24.0-1", owns=["/lib/systemd/system/nginx.service"])
        self.fake.install("libssl3", "3.0.13-1", arch="amd64", owns=["/usr/lib/x86_64-linux-gnu/libssl.so.3"])
        self.fake.install("libc6", "2.39-0ubuntu8", arch="amd64", owns=["/usr/lib/x86_64-linux-gnu/libc.so.6"])
        self.fake.fragment = {"nginx.service": "/lib/systemd/system/nginx.service"}
        for i in range(4):  # con paquete pero sin proceso: no hay nada que aprender todavía
            frag = f"/lib/systemd/system/parked{i}.service"
            self.fake.fragment[f"parked{i}.service"] = frag
            self.fake.install(f"parked{i}", "1.0", owns=[frag])
        self.loaded = {"nginx.service": ["/usr/lib/x86_64-linux-gnu/libssl.so.3",
                                         "/usr/lib/x86_64-linux-gnu/libc.so.6"]}
        self.pids = {"system.slice/nginx.service": [100]}
        self.fake.main_pid["nginx.service"] = 100
        for patcher in [mock.patch.object(self.p, "_loaded_libraries", lambda unit, *a: self.loaded.get(unit, [])),
                        mock.patch.object(self.p, "_cgroup_pids", lambda path: self.pids.get(path, []))]:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.subjects = {f"system.slice/{u}": {"unit": u, "package": pkg, "version": ver, "libs": None, "updates": []}
                         for u, pkg, ver in [("nginx.service", "nginx", "1.24.0-1"),
                                             *((f"parked{i}.service", f"parked{i}", "1.0") for i in range(4))]}
        self.st = {}

    def _sweep(self, seconds: float):
        """Como `profile.sweep`: ¿cambió dpkg? y, si sí o no, el aprendizaje de lo que toque."""
        now = self.NOW + timedelta(seconds=seconds)
        incomplete: list = []
        found = self.p._updates(self.subjects, {}, now, check_versions=self.p._dpkg_changed(self.st),
                                incomplete=incomplete)
        if incomplete:  # como `sweep`: el cambio no se da por visto y el barrido siguiente lo repite
            self.st.pop("dpkg_mtime", None)
            self.st.pop("dpkg_gen", None)
        return found

    def test_thirty_minutes_of_idle_sweeps_cost_at_most_one_inventory(self):
        for tick in range(60):  # 30 min, un barrido cada 30 s
            self._sweep(tick * 30)
        self.assertEqual(self.fake.count("inventory"), 1)
        # inventario, unidades de todos y librerías aprendidas: tres consultas, no una por servicio
        self.assertLessEqual(self.fake.queries(), 3)

    def test_parked_services_wait_longer_each_time_instead_of_every_sweep(self):
        probes = []
        original = self.p._loaded_libraries
        with mock.patch.object(self.p, "_loaded_libraries",
                               lambda unit, *a: probes.append(unit) or original(unit, *a)):
            for tick in range(60):
                self._sweep(tick * 30)
        parked = [u for u in probes if u.startswith("parked")]
        self.assertLessEqual(len(parked), 4 * 3)  # 3 intentos por servicio en 30 min, no 60

    def test_a_service_that_starts_is_learned_at_the_next_sweep_not_after_the_whole_wait(self):
        for tick in range(6):
            self._sweep(tick * 30)
        self.assertIsNone(self.subjects["system.slice/parked0.service"]["libs"])
        self.fake.main_pid["parked0.service"] = 777
        self.pids["system.slice/parked0.service"] = [777]
        self.loaded["parked0.service"] = ["/usr/lib/x86_64-linux-gnu/libssl.so.3"]
        self._sweep(6 * 30 + 60)  # hay proceso nuevo: se mira ya
        self.assertEqual(self.subjects["system.slice/parked0.service"]["libs"], {"libssl3": "3.0.13-1"})

    def test_a_dpkg_change_costs_one_inventory_and_still_detects_the_update(self):
        updates = []
        with mock.patch.object(self.p, "_investigate_later", lambda pkg, why, cfg, version=None: updates.append(pkg)):
            for tick in range(10):
                self._sweep(tick * 30)
            self.assertEqual(self.fake.count("inventory"), 1)
            self.fake.install("nginx", "1.24.0-2")  # actualización
            before = self.fake.count("inventory")
            for tick in range(10, 20):
                self._sweep(tick * 30)
        self.assertEqual(self.fake.count("inventory") - before, 1)
        self.assertEqual(updates, ["nginx"])
        self.assertEqual(self.subjects["system.slice/nginx.service"]["version"], "1.24.0-2")

    def test_a_dpkg_change_costs_one_renewal_of_owners_not_one_per_service(self):
        for tick in range(4):
            self._sweep(tick * 30)
        before = self.fake.count("search")
        self.fake.install("nginx", "1.24.0-2")
        self._sweep(5 * 30)
        self.assertEqual(self.fake.count("search") - before, 1)

    def test_a_library_update_is_still_seen_after_the_next_dpkg_change(self):
        updates = []
        with mock.patch.object(self.p, "_investigate_later", lambda pkg, why, cfg, version=None: updates.append(pkg)):
            for tick in range(4):
                self._sweep(tick * 30)
            self.assertTrue(self.subjects["system.slice/nginx.service"]["libs"])
            self.fake.install("libssl3", "3.0.13-2")
            self._sweep(4 * 30)
        self.assertEqual(updates, ["libssl3"])

    def test_no_answer_from_dpkg_is_not_taken_for_nothing_changed(self):
        self.fake.fail = "busy"
        incomplete: list = []
        found = self.p._updates(self.subjects, {}, self.NOW, check_versions=True, incomplete=incomplete)
        self.assertEqual(found, [])
        self.assertTrue(incomplete)  # el barrido siguiente lo repite
        self.assertEqual(self.subjects["system.slice/nginx.service"]["version"], "1.24.0-1")
        self.assertIsNone(self.subjects["system.slice/nginx.service"]["libs"])  # sin inventar «sin librerías»
        self.fake.fail = None
        self._sweep(30)
        self.assertTrue(self.subjects["system.slice/nginx.service"]["libs"])

    def test_the_libraries_of_a_service_are_resolved_in_one_batch(self):
        libs = [f"/usr/lib/x86_64-linux-gnu/libfake{i}.so.1" for i in range(40)]
        for i, path in enumerate(libs):
            self.fake.files[path] = f"libfake{i}"
            self.fake.packages[(f"libfake{i}", "amd64")] = ("1.0", f"libfake{i}", "1.0")
        self.fake.touch()
        self.loaded["nginx.service"] = libs
        got = self.p._library_packages("nginx.service", "nginx", self.p._installed_versions())
        self.assertEqual(len(got), 40)
        self.assertEqual(self.fake.count("search"), 1)  # no 40 consultas

    def test_a_service_without_loaded_libraries_costs_no_query_to_dpkg(self):
        self.assertEqual(self.p._library_packages("parked0.service", "parked0"), {})
        self.assertEqual(self.fake.queries(), 0)


class LibraryProbeBudgetTests(HostIdleBudgetTests):
    """Variantes de lo que puede ser un servicio sin librerías que aprender."""

    def test_a_static_binary_with_a_live_process_is_not_probed_every_sweep(self):
        self.fake.main_pid["parked1.service"] = 55
        self.pids["system.slice/parked1.service"] = [55]  # hay proceso y no carga ninguna librería (Go, Rust…)
        probes = []
        original = self.p._loaded_libraries
        with mock.patch.object(self.p, "_loaded_libraries",
                               lambda unit, *a: probes.append(unit) or original(unit, *a)):
            for tick in range(120):  # una hora
                self._sweep(tick * 30)
        self.assertLessEqual(probes.count("parked1.service"), 4)

    def test_a_probe_without_an_answer_from_dpkg_is_retried_at_the_next_sweep_not_after_a_wait(self):
        self.fake.fail = "busy"
        self._sweep(0)
        self.assertIsNone(self.subjects["system.slice/nginx.service"]["libs"])
        self.assertNotIn("libs_probe", self.subjects["system.slice/nginx.service"])
        self.fake.fail = None
        self._sweep(30)
        self.assertTrue(self.subjects["system.slice/nginx.service"]["libs"])

    def test_the_first_sweep_of_many_new_services_asks_dpkg_once_for_their_unit_files(self):
        self.fake.calls.clear()
        self.p._warm_unit_owners([f"parked{i}.service" for i in range(4)])
        self.assertEqual(self.fake.count("search"), 1)
        for i in range(4):
            self.assertEqual(self.p._package_version(f"parked{i}.service"), (f"parked{i}", "1.0"))
        self.assertEqual(self.fake.count("search"), 1)
        self.assertEqual(self.fake.count("single"), 0)  # la versión sale del inventario, no de una consulta por servicio

    def test_an_unanswered_batch_of_unit_files_postpones_the_whole_pass(self):
        self.fake.fail = "busy"
        incomplete: list = []
        found = self.p._updates(self.subjects, {}, self.NOW, check_versions=True, incomplete=incomplete)
        self.assertEqual((found, bool(incomplete)), ([], True))


class LibraryLearningTests(unittest.TestCase):
    """La espera creciente de los servicios sin librerías que aprender."""

    NOW = datetime(2026, 11, 14, tzinfo=timezone.utc)

    def setUp(self):
        from arx.modules import profile
        self.p = profile
        self.pids: dict = {}
        patcher = mock.patch.object(profile, "_cgroup_pids", lambda path: self.pids.get(path, []))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.s = {"unit": "a.service", "package": "a", "libs": None}
        self.path = "system.slice/a.service"

    def _fail(self, seconds):
        self.p._libs_wait(self.s, self.path, self.NOW + timedelta(seconds=seconds))

    def test_the_wait_grows_with_each_failed_attempt_up_to_a_cap(self):
        waits = []
        for i in range(7):
            self._fail(i * 1000)
            waits.append(self.s["libs_probe"]["wait"])
        self.assertEqual(waits, [120, 600, 3600, 21600, 21600, 21600, 21600])

    def test_it_is_due_the_first_time_and_after_the_wait(self):
        self.assertTrue(self.p._libs_due(self.s, self.path, self.NOW))
        self._fail(0)
        self.assertFalse(self.p._libs_due(self.s, self.path, self.NOW + timedelta(seconds=119)))
        self.assertTrue(self.p._libs_due(self.s, self.path, self.NOW + timedelta(seconds=120)))

    def test_a_new_process_in_the_cgroup_makes_it_due_but_not_faster_than_the_minimum(self):
        self._fail(0)
        self.pids[self.path] = [4242]  # arrancó
        self.assertFalse(self.p._libs_due(self.s, self.path, self.NOW + timedelta(seconds=self.p.LIBS_MIN_S - 1)))
        self.assertTrue(self.p._libs_due(self.s, self.path, self.NOW + timedelta(seconds=self.p.LIBS_MIN_S)))

    def test_a_service_whose_processes_did_not_change_keeps_waiting(self):
        self.pids[self.path] = [100]
        self._fail(0)  # un binario estático: hay proceso y ninguna librería
        self.assertFalse(self.p._libs_due(self.s, self.path, self.NOW + timedelta(seconds=119)))
        self.pids[self.path] = [101]  # reinició
        self.assertTrue(self.p._libs_due(self.s, self.path, self.NOW + timedelta(seconds=self.p.LIBS_MIN_S)))

    def test_a_clock_that_goes_back_or_a_damaged_record_never_stops_the_learning(self):
        self._fail(10_000)
        self.assertTrue(self.p._libs_due(self.s, self.path, self.NOW))  # ahora es antes del último intento
        for broken in ({"at": "garbage", "wait": 600}, {"at": None}, "text", 7):
            self.s["libs_probe"] = broken
            self.assertTrue(self.p._libs_due(self.s, self.path, self.NOW))

    def test_dpkg_changed_follows_the_generation_and_forgets_the_old_key(self):
        from arx.modules import pkgdb
        fake = FakeDpkg()
        with mock.patch.object(pkgdb, "STATUS", fake.status), mock.patch.object(pkgdb, "UPDATES", fake.updates), \
                mock.patch.object(pkgdb, "DIVERSIONS", fake.diversions):
            st = {"dpkg_mtime": 123.4}
            self.assertTrue(self.p._dpkg_changed(st))   # la primera vez tras actualizar: un repaso de más
            self.assertNotIn("dpkg_mtime", st)
            self.assertFalse(self.p._dpkg_changed(st))  # un host quieto
            fake.touch()
            self.assertTrue(self.p._dpkg_changed(st))
            self.assertFalse(self.p._dpkg_changed(dict(st)))  # el estado se guarda y se vuelve a leer
        with mock.patch.object(pkgdb, "STATUS", os.path.join(fake.dir, "missing")):
            self.assertTrue(self.p._dpkg_changed(st))   # sin identidad no se asegura que nada cambió
            self.assertIn("dpkg_gen", st)


if __name__ == "__main__":
    unittest.main()
