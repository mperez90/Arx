"""El servicio de Arx no es un «servicio nuevo» en la base (piloto A: `arx.service` med al sellar)."""
import os

os.environ["ARX_LANG"] = "es"

import tempfile  # noqa: E402
import unittest  # noqa: E402
from unittest import mock  # noqa: E402

from arx import config  # noqa: E402
from arx.modules import baseline, service  # noqa: E402


class OwnServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        p = mock.patch.object(config, "state_dir", return_value=__import__("pathlib").Path(self.tmp.name))
        p.start()
        self.addCleanup(p.stop)
        self.base = {"sets": {"services": ["ssh.service", "cron.service"]}}

    def _new(self, running):
        return [a["item"] for a in baseline.compare(self.base, {"sets": {"services": running}, "gauges": {}})]

    def test_arx_s_own_sealed_service_is_not_new(self):
        config.write_json(config.state_dir() / "self.json", {p: "x" for p in service._units()})
        self.assertEqual(self._new(["ssh.service", "arx.service", "arx-firewall.service"]), [])

    def test_without_the_seal_of_arx_it_is_still_new(self):
        """Un `arx.service` que Arx no instaló (no hay self.json) no se salta."""
        self.assertEqual(self._new(["ssh.service", "arx.service"]), ["arx.service"])

    def test_any_other_new_service_is_still_reported(self):
        config.write_json(config.state_dir() / "self.json", {p: "x" for p in service._units()})
        self.assertEqual(self._new(["arx.service", "evil.service"]), ["evil.service"])


if __name__ == "__main__":
    unittest.main()
