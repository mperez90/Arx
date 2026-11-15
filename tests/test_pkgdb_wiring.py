"""B78 · Quién usa `pkgdb`: `trust`, `provenance` y `recon` sacan lo de dpkg del inventario compartido.

Los mismos resultados que antes (hechos de un paquete, dueño de un fichero, paquete fuente, recuento) con una
consulta por cambio de dpkg en vez de una por paquete, y con la falta de respuesta como error, nunca como
«paquete desconocido». Corre con:  python -m unittest discover -s tests
"""
import os

os.environ["ARX_LANG"] = "es"

import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

from arx.modules import maintenance  # noqa: E402
from dpkgfake import fake_world  # noqa: E402


class WiringTests(unittest.TestCase):
    def setUp(self):
        from arx.modules import pkgdb, provenance
        self.db, self.v = pkgdb, provenance
        self.fake = fake_world(self)
        self.fake.install("coreutils", "9.4-3", owns=["/usr/bin/ls", "/bin/cat"])
        self.fake.install("nginx", "1.24.0-1", source="nginx", owns=["/usr/sbin/nginx"])
        self.fake.install("libc6", "2.39-0ubuntu8", arch="amd64", source="glibc", source_version="2.39-0ubuntu8",
                          owns=["/usr/lib/x86_64-linux-gnu/libc.so.6"])
        self.fake.install("libc6", "2.39-0ubuntu8", arch="i386", source="glibc", source_version="2.39-0ubuntu8")

    def test_trust_facts_come_from_the_inventory_and_keep_their_shape(self):
        from arx.modules import trust
        self.assertEqual(trust.package_facts("libc6:i386"), {
            "package": "libc6:i386", "version": "2.39-0ubuntu8", "arch": "i386", "source": "glibc",
            "source_version": "2.39-0ubuntu8"})
        self.assertEqual(trust.package_facts("nginx")["source"], "nginx")
        self.assertIsNone(trust.package_facts("nope"))
        self.assertIsNone(trust.package_facts("-W"))  # no es un nombre de paquete: ni se pregunta
        for _ in range(10):
            trust.package_facts("nginx")
        self.assertEqual(self.fake.count("inventory"), 1)
        self.assertEqual(self.fake.count("single"), 0)
        self.fake.fail = "busy"
        self.fake.touch()
        with self.assertRaises(maintenance.NoAnswer):
            trust.package_facts("nginx")
        self.fake.fail = "timeout"
        with self.assertRaises(maintenance.NoAnswer):  # un tiempo agotado tampoco es «paquete desconocido»
            trust.package_facts("nginx")


    def test_a_version_dpkg_would_never_print_is_not_taken_as_facts(self):
        from arx.modules import trust
        self.fake.packages[("odd", "all")] = ("1.0 ; rm", "odd", "1.0")
        self.fake.touch()
        self.assertIsNone(trust.package_facts("odd"))


    def test_source_package_uses_the_same_inventory(self):
        self.assertEqual(self.v.source_package("libc6:i386"), "glibc")
        self.assertEqual(self.v.source_package("nginx"), "nginx")
        self.assertEqual(self.v.source_package("unknown:amd64"), "unknown")  # como antes: el nombre sin arquitectura
        self.assertEqual(self.fake.count("single"), 0)


    def test_recon_counts_the_installed_packages_from_the_shared_inventory(self):
        from arx.modules import recon
        with mock.patch.object(recon, "_has", lambda cmd: True):
            self.assertEqual(recon.collect_packages(), {"manager": "dpkg", "count": 4})
            self.fake.fail = "busy"
            self.fake.touch()
            self.assertEqual(recon.collect_packages(), {})

    def test_clear_cache_forgets_dpkg_answers_too(self):
        self.v.package_of("/usr/bin/ls")
        self.db.versions()
        self.v.clear_cache()
        self.assertEqual(dict(self.db._owner_cache), {})
        self.assertIsNone(self.db._inventory)

    def test_package_of_is_the_batch_owner_with_no_answer_as_an_error(self):
        self.assertEqual(self.v.package_of("/usr/bin/ls"), "coreutils")
        self.assertEqual(self.v.package_of("/usr/bin/ls"), "coreutils")
        self.assertEqual(self.fake.count("search"), 1)
        self.assertIsNone(self.v.package_of("/opt/loose/server"))  # un «no» de dpkg sí es respuesta
        for failure in ("busy", "timeout", "exit2", "oserror"):
            self.fake.fail = failure
            self.fake.touch()
            with self.assertRaises(self.v.NoAnswer, msg=failure):
                self.v.package_of("/usr/sbin/nginx")


if __name__ == "__main__":
    unittest.main()
