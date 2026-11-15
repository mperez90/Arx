"""B78 · La integridad de los ficheros de Arx se comprueba en proceso, sin abrir un scope cada 5 minutos.

Lab de reposo (arx-victim, 30 min): los 7 scopes que quedaban eran todos `dpkg --verify arx` (`service.self_check`,
cada 300 s). `dpkg --verify` solo da una alerta con el md5 distinto («5») o con `missing`; eso se comprueba contra el
`arx.md5sums` que guardó dpkg sin lanzar nada. `dpkg --verify` queda de respaldo para lo que no se puede probar en
proceso. Corre con:  python -m unittest discover -s tests
"""
import os

os.environ["ARX_LANG"] = "es"

import hashlib
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

FILES = {"usr/lib/arx/arx.pyz": b"PK\x03\x04 el zipapp", "usr/bin/arx": b"#!/bin/sh\nexec python3 arx.pyz\n",
         "usr/share/man/man1/arx.1.gz": b"\x1f\x8b man"}


def _isolate():
    d = tempfile.mkdtemp()
    os.environ["ARX_CONFIG_DIR"] = os.path.join(d, "cfg")
    os.environ["ARX_STATE_DIR"] = os.path.join(d, "state")
    return d


class _R:
    def __init__(self, stdout="", returncode=0):
        self.stdout, self.returncode = stdout, returncode


class Package(unittest.TestCase):
    def setUp(self):
        self.d = _isolate()
        from arx.modules import maintenance, provenance, service
        self.s, self.v, self.m = service, provenance, maintenance
        self.root = os.path.join(self.d, "root")
        self.info = os.path.join(self.d, "dpkg-info")
        os.makedirs(self.info)
        for rel, data in FILES.items():
            self.write(rel, data)
        self.write_sums()
        for p in (mock.patch.object(provenance, "PKG_ROOT", self.root),
                  mock.patch.object(provenance, "DPKG_INFO", self.info),
                  mock.patch.object(service, "_runs_from_package", return_value=True)):
            p.start()
            self.addCleanup(p.stop)
        self.runs = []

    def write(self, rel, data):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)

    def write_sums(self, files=None, extra=""):
        with open(os.path.join(self.info, "arx.md5sums"), "w") as f:
            for rel, data in (FILES if files is None else files).items():
                f.write(f"{hashlib.md5(data).hexdigest()}  {rel}\n")
            f.write(extra)

    def check(self, dpkg_out="", rc=0, busy=False):
        def run(argv, **kw):
            self.runs.append(argv)
            if busy:
                raise self.m.SlotBusy("busy")
            return _R(dpkg_out, rc)
        with mock.patch.object(self.m, "run", run):
            return self.s.self_check(dropin_dirs=())


class VerifyPackageTests(Package):
    def test_an_untouched_package_has_nothing_changed_or_missing(self):
        self.assertEqual(self.v.verify_package("arx"), ([], []))

    def test_a_changed_file_and_a_missing_one_are_told_apart_with_absolute_paths(self):
        self.write("usr/lib/arx/arx.pyz", b"otro contenido")
        os.unlink(os.path.join(self.root, "usr/bin/arx"))
        self.assertEqual(self.v.verify_package("arx"), (["/usr/lib/arx/arx.pyz"], ["/usr/bin/arx"]))

    def test_the_same_size_with_other_content_is_changed(self):
        original = FILES["usr/bin/arx"]
        self.write("usr/bin/arx", bytes([original[0] ^ 1]) + original[1:])  # un bit distinto, el mismo tamaño
        self.assertEqual(self.v.verify_package("arx")[0], ["/usr/bin/arx"])

    def test_it_cannot_prove_what_it_cannot_read(self):
        os.unlink(os.path.join(self.info, "arx.md5sums"))
        self.assertIsNone(self.v.verify_package("arx"))  # sin md5sums no hay prueba

    def test_a_file_that_is_not_a_regular_file_is_not_proved_either(self):
        os.unlink(os.path.join(self.root, "usr/bin/arx"))
        os.mkdir(os.path.join(self.root, "usr/bin/arx"))  # un directorio donde iba el fichero
        self.assertIsNone(self.v.verify_package("arx"))

    def test_an_unreadable_file_is_not_proved(self):
        with mock.patch.object(self.v, "_md5_file", return_value=None):
            self.assertIsNone(self.v.verify_package("arx"))

    def test_a_damaged_md5sums_is_not_trusted(self):
        for extra in ("zzz  usr/bin/x\n", "d41d8cd98f00b204e9800998ecf8427e  ../../etc/passwd\n",
                      "d41d8cd98f00b204e9800998ecf8427e  /etc/passwd\n", "sin separador\n"):
            self.write_sums(extra=extra)
            self.assertIsNone(self.v.verify_package("arx"), extra)

    def test_an_empty_md5sums_proves_nothing(self):
        self.write_sums(files={})
        self.assertIsNone(self.v.verify_package("arx"))

    def test_the_multiarch_form_is_read_too(self):
        os.rename(os.path.join(self.info, "arx.md5sums"), os.path.join(self.info, "arx:amd64.md5sums"))
        self.assertEqual(self.v.verify_package("arx:amd64"), ([], []))


class SelfCheckTests(Package):
    def test_an_untouched_arx_says_nothing_and_opens_no_scope(self):
        for _ in range(12):  # una hora de vueltas
            self.assertEqual(self.check(), [])
        self.assertEqual(self.runs, [])

    def test_a_changed_file_is_a_critical_alert_without_dpkg(self):
        self.write("usr/lib/arx/arx.pyz", b"parcheado")
        found = self.check()
        self.assertEqual([(f["kind"], f["sev"]) for f in found], [("self_tamper", "crit")])
        self.assertIn("/usr/lib/arx/arx.pyz", found[0]["detail"])
        self.assertEqual(self.runs, [])

    def test_a_missing_file_is_a_critical_alert_too(self):
        os.unlink(os.path.join(self.root, "usr/bin/arx"))
        found = self.check()
        self.assertEqual([(f["kind"], f["sev"]) for f in found], [("self_tamper", "crit")])
        self.assertIn("/usr/bin/arx", found[0]["detail"])

    def test_it_says_the_same_as_dpkg_would_have_said(self):
        self.write("usr/lib/arx/arx.pyz", b"parcheado")
        in_process = self.check()
        os.unlink(os.path.join(self.info, "arx.md5sums"))  # sin prueba en proceso: respaldo con dpkg
        via_dpkg = self.check("??5??????   /usr/lib/arx/arx.pyz\n", rc=1)
        self.assertEqual(self.runs, [["dpkg", "--verify", "arx"]])
        self.assertEqual((in_process[0]["detail"], in_process[0]["fp_key"], in_process[0]["sev"]),
                         (via_dpkg[0]["detail"], via_dpkg[0]["fp_key"], via_dpkg[0]["sev"]))

    def test_without_md5sums_dpkg_verify_is_still_the_fallback(self):
        os.unlink(os.path.join(self.info, "arx.md5sums"))
        self.assertEqual(self.check(), [])
        self.assertEqual(self.runs, [["dpkg", "--verify", "arx"]])

    def test_the_fallback_keeps_its_own_rules_for_a_failed_verification(self):
        os.unlink(os.path.join(self.info, "arx.md5sums"))
        found = self.check("", rc=2)
        self.assertEqual([f["kind"] for f in found], ["self_check_unavailable"])
        self.assertEqual(self.check(busy=True), [])  # ranura ocupada: se repite en la vuelta siguiente

    def test_a_file_replaced_by_a_directory_is_decided_by_dpkg_not_called_clean(self):
        os.unlink(os.path.join(self.root, "usr/bin/arx"))
        os.mkdir(os.path.join(self.root, "usr/bin/arx"))
        found = self.check("missing     /usr/bin/arx\n", rc=1)
        self.assertEqual([f["kind"] for f in found], ["self_tamper"])
        self.assertEqual(self.runs, [["dpkg", "--verify", "arx"]])

    def test_a_copy_that_dpkg_did_not_install_is_not_judged_by_it(self):
        with mock.patch.object(self.s, "_runs_from_package", return_value=False):
            self.write("usr/lib/arx/arx.pyz", b"otro")
            self.assertEqual(self.check(), [])
        self.assertEqual(self.runs, [])


if __name__ == "__main__":
    unittest.main()
