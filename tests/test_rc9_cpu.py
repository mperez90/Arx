"""rc9 en el piloto A (u24, 12 h): 1,05 % de CPU. Dos órdenes de nft de más en cada barrido, medidas con strace:

1. `_cleanup_dead` leía la línea `typeof socket cgroupv2 level 0` de un set VACÍO como un cgroup muerto «0» y mandaba
   `nft delete element … { 0 }` en cada barrido; nft lo rechaza («cgroupv2 path fails»), y cada escritura invalida lo
   leído en el barrido, así que la tabla (0,09 s) se volvía a listar: 3 veces por barrido en vez de 1.
2. `_restore_confinements` preguntaba con `nft get element` por el MISMO confinamiento una vez por cada bloqueo que lo
   recordaba (6 bloqueos de nginx en u24 → 6 preguntas de 0,02 s por barrido).

Listados con el formato real de nft 1.0.9 (Ubuntu 24.04). Corre con:  python -m unittest discover -s tests
"""
import os

os.environ["ARX_LANG"] = "es"

import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from arx.modules import profile, response, sweepcache  # noqa: E402

EMPTY = "table inet arx {{\n\tset {name} {{\n\t\ttypeof socket cgroupv2 level 0\n\t}}\n}}\n"
WITH_DEAD = ("table inet arx {{\n\tset {name} {{\n\t\ttypeof socket cgroupv2 level 0\n"
             "\t\telements = {{ \"system.slice/nginx.service\",\n\t\t\t     4242 }}\n\t}}\n}}\n")
OK_EMPTY = ("table inet arx {{\n\tset {name} {{\n\t\ttypeof socket cgroupv2 level 2 . meta l4proto . ip daddr . "
            "th dport\n\t\tflags interval\n\t}}\n}}\n")


class _R:
    def __init__(self, returncode=0, stdout=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, ""


class CleanupDead(unittest.TestCase):
    def _run(self, listing_for):
        calls = []

        def fake(cmd, *a, **k):
            calls.append(cmd)
            if cmd[1:3] == ["list", "set"]:
                return _R(0, listing_for(cmd[5]))
            if cmd[1:3] == ["delete", "element"]:
                return _R(1)  # como nft con «{ 0 }»: el cgroup 0 no existe
            return _R(0)

        sweepcache.forget()
        with mock.patch.object(profile.subprocess, "run", side_effect=fake):
            profile._cleanup_dead()
        return [c for c in calls if c[1:3] == ["delete", "element"]]

    def test_an_empty_set_is_not_a_dead_cgroup_zero(self):
        deletes = self._run(lambda name: (OK_EMPTY if name.startswith("ok") else EMPTY).format(name=name))
        self.assertEqual(deletes, [], "la línea «typeof … level 0» de un set vacío no es un elemento")

    def test_a_dead_numeric_cgroup_is_still_removed(self):
        deletes = self._run(lambda name: (OK_EMPTY if name.startswith("ok") else
                                          WITH_DEAD if name == "watched_obs" else EMPTY).format(name=name))
        self.assertEqual(deletes, [["nft", "delete", "element", "inet", "arx", "watched_obs", "{ 4242 }"]])


class RestoreConfinements(unittest.TestCase):
    def test_one_question_per_confinement_not_per_block(self):
        entry = {"path": "system.slice/nginx.service", "set": "confined2", "unit": "nginx.service"}
        blocks = [{"revert": {"tool": "confine", "units": [dict(entry)]}} for _ in range(6)]
        gets = []

        def fake(cmd, *a, **k):
            if cmd[1:3] == ["get", "element"]:
                gets.append(cmd)
            return _R(0)

        with mock.patch.object(response, "_load_blocks", return_value=blocks), \
                mock.patch.object(response.os.path, "isdir", return_value=True), \
                mock.patch.object(response.subprocess, "run", side_effect=fake):
            self.assertEqual(response._restore_confinements(), 0)  # sigue en el kernel: nada que reponer
        self.assertEqual(len(gets), 1, gets)

    def test_a_missing_confinement_is_still_put_back(self):
        entry = {"path": "system.slice/nginx.service", "set": "confined2"}
        blocks = [{"revert": {"tool": "confine", "units": [dict(entry)]}} for _ in range(3)]
        adds = []

        def fake(cmd, *a, **k):
            if cmd[1:3] == ["get", "element"]:
                return _R(1)  # ya no está (un flush)
            if cmd[1:3] == ["add", "element"]:
                adds.append(cmd)
            return _R(0)

        with mock.patch.object(response, "_load_blocks", return_value=blocks), \
                mock.patch.object(response.os.path, "isdir", return_value=True), \
                mock.patch.object(response.subprocess, "run", side_effect=fake):
            self.assertEqual(response._restore_confinements(), 1)
        self.assertEqual(len(adds), 1, adds)


class StructureByGeneration(unittest.TestCase):
    """rc10 en u24: con un servicio confinado, `restore_kernel_blocks` lista la estructura de la tabla en cada barrido
    (0,09 s: nft resuelve los 46 cgroups de las reglas). La estructura solo cambia en una transacción de nf_tables, y
    cada transacción sube la generación del kernel: con la misma generación, lo listado sigue valiendo (5 min como mucho)."""

    def setUp(self):
        response._struct_cache.update(gen=None, at=0.0, text=None)
        self.listings = 0

        def fake(cmd, *a, **k):
            if cmd[:3] == ["nft", "-t", "list"]:
                self.listings += 1
                return _R(0, "table inet arx {\n}\n")
            return _R(0)
        self.fake = fake

    def _sweeps(self, gens, clock=None):
        clock = clock or [1000.0 + 30 * i for i in range(len(gens))]
        it = iter(gens)
        with mock.patch.object(response.subprocess, "run", side_effect=self.fake), \
                mock.patch.object(response, "_ruleset_generation", side_effect=lambda: next(it)):
            for now in clock:
                with mock.patch.object(response.time, "monotonic", return_value=now):
                    sweepcache.begin_sweep()
                    try:
                        self.assertIsNotNone(response._table_listing())
                    finally:
                        sweepcache.end_sweep()

    def test_same_generation_lists_once(self):
        self._sweeps([7, 7, 7, 7])
        self.assertEqual(self.listings, 1)

    def test_a_new_generation_lists_again(self):
        self._sweeps([7, 7, 8, 8])
        self.assertEqual(self.listings, 2)

    def test_without_netlink_every_sweep_lists(self):
        self._sweeps([None, None, None])
        self.assertEqual(self.listings, 3)

    def test_at_most_five_minutes(self):
        self._sweeps([7, 7, 7], clock=[1000.0, 1200.0, 1301.0])
        self.assertEqual(self.listings, 2)

    def test_outside_a_sweep_always_lists(self):
        response._struct_cache.update(gen=7, at=0.0, text="table inet arx {\n}\n")
        with mock.patch.object(response.subprocess, "run", side_effect=self.fake), \
                mock.patch.object(response, "_ruleset_generation", return_value=7), \
                mock.patch.object(response.time, "monotonic", return_value=10.0):
            response._table_listing()
            response._table_listing()
        self.assertEqual(self.listings, 2)

    def test_parse_a_real_newgen_reply(self):
        # NFT_MSG_NEWGEN (subsistema 10, tipo 15) con NFTA_GEN_ID=0x0001e240, PROC_PID y PROC_NAME, como el del kernel
        import struct
        attrs = (struct.pack("=HH", 8, 1) + struct.pack("!I", 123456) + struct.pack("=HH", 8, 2) + struct.pack("!I", 42)
                 + struct.pack("=HH", 8, 3) + b"nft\0")
        body = struct.pack("=BBH", 0, 0, 0) + attrs
        reply = struct.pack("=IHHII", 16 + len(body), (10 << 8) | 15, 0, 1, 0) + body
        self.assertEqual(response._parse_generation(reply), 123456)
        self.assertIsNone(response._parse_generation(struct.pack("=IHHII", 36, 2, 0, 1, 0) + struct.pack("=i", -1)))
        self.assertIsNone(response._parse_generation(b"short"))


if __name__ == "__main__":
    unittest.main()
