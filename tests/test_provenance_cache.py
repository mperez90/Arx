"""La respuesta de apt se reutiliza mientras no cambie el estado de apt (piloto A: `apt-cache policy polkitd` cada
5 min por un hallazgo pendiente, 12 scopes/h)."""
import os

os.environ["ARX_LANG"] = "es"

import tempfile  # noqa: E402
import unittest  # noqa: E402
from unittest import mock  # noqa: E402

from arx.modules import pkgdb, provenance  # noqa: E402


class AptStateCacheTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.addCleanup(self.d.cleanup)
        root = self.d.name
        self.lists = os.path.join(root, "lists")
        self.srcd = os.path.join(root, "sources.list.d")
        os.makedirs(self.lists)
        os.makedirs(self.srcd)
        self.src = os.path.join(self.srcd, "ubuntu.sources")
        with open(self.src, "w") as f:
            f.write("Types: deb\nURIs: http://archive.ubuntu.com/ubuntu\n")
        self.gen = "dpkg-1"
        self.clock = 1000.0
        self.calls = 0
        provenance.clear_cache()
        for target, name, value in ((provenance, "APT_STATE", (self.lists, self.srcd)),
                                    (pkgdb, "generation", lambda: self.gen),
                                    (provenance.time, "monotonic", lambda: self.clock)):
            p = mock.patch.object(target, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(provenance.clear_cache)

    def ask(self):
        def look():
            self.calls += 1
            return True, "http://archive.ubuntu.com/ubuntu"
        return provenance._cached(("origin", "polkitd", False), look)

    def test_nothing_changed_apt_is_asked_once_an_hour_not_every_five_minutes(self):
        for _ in range(12):  # una hora de barridos que vuelven a mirar el mismo hallazgo
            self.ask()
            self.clock += 299
        self.assertEqual(self.calls, 1)

    def test_a_dpkg_transaction_asks_again(self):
        self.ask()
        self.gen = "dpkg-2"
        self.ask()
        self.assertEqual(self.calls, 2)

    def test_an_apt_update_asks_again(self):
        self.ask()
        open(os.path.join(self.lists, "archive.ubuntu.com_dists_noble_InRelease"), "w").close()
        self.ask()
        self.assertEqual(self.calls, 2)

    def test_editing_a_source_in_place_asks_again(self):
        """`trusted=yes` añadido a un fichero de fuentes sin tocar su directorio también cuenta."""
        self.ask()
        with open(self.src, "a") as f:
            f.write("Trusted: yes\n")
        self.ask()
        self.assertEqual(self.calls, 2)

    def test_after_the_cap_it_asks_again_even_if_nothing_seemed_to_change(self):
        self.ask()
        self.clock += provenance.CACHE_S + 1
        self.ask()
        self.assertEqual(self.calls, 2)

    def test_an_unknown_dpkg_state_is_never_reused(self):
        self.gen = None
        self.ask()
        self.ask()
        self.assertEqual(self.calls, 2)


if __name__ == "__main__":
    unittest.main()
