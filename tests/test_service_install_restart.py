"""`arx service install` con el servicio ya en marcha lo reinicia: `enable --now` no cambia de modo (HZ#11)."""
import os

os.environ["ARX_LANG"] = "es"

import subprocess  # noqa: E402
import tempfile  # noqa: E402
import unittest  # noqa: E402
from pathlib import Path  # noqa: E402
from unittest import mock  # noqa: E402

from arx.modules import service  # noqa: E402


class InstallRestartTests(unittest.TestCase):
    def _install(self, active: bool, enforce: bool = True, fail_restart: bool = False):
        calls = []

        def run(cmd, check=False, **kw):
            calls.append(cmd)
            rc = 0
            if cmd[:2] == ["systemctl", "is-active"]:
                rc = 0 if active else 3
            if cmd[:2] == ["systemctl", "restart"] and fail_restart:
                rc = 1
            return subprocess.CompletedProcess(cmd, rc)

        with tempfile.TemporaryDirectory() as d:
            paths = {n: str(Path(d) / n) for n in ("UNIT_PATH", "EARLY_UNIT_PATH", "DOWN_UNIT_PATH",
                                                   "REVIVE_UNIT_PATH", "REVIVE_TIMER_PATH",
                                                   "MAINTENANCE_SLICE_PATH")}
            with mock.patch.multiple(service, **paths), \
                    mock.patch.object(service, "_prereqs_ok", return_value=True), \
                    mock.patch.object(service, "_systemd_available", return_value=True), \
                    mock.patch.object(service, "_is_root", return_value=True), \
                    mock.patch.object(service, "_seal_units"), \
                    mock.patch.object(service.subprocess, "run", side_effect=run), \
                    mock.patch("builtins.print"):
                rc = service.install("/usr/bin/arx", enforce=enforce)
                unit = Path(paths["UNIT_PATH"]).read_text()
        return rc, calls, unit

    def test_a_running_service_is_restarted_to_take_the_new_mode(self):
        rc, calls, unit = self._install(active=True)
        self.assertEqual(rc, 0)
        self.assertIn("--enforce", unit)
        self.assertIn(["systemctl", "restart", "arx"], calls)
        # el reinicio va después de escribir la unit y de daemon-reload
        self.assertLess(calls.index(["systemctl", "daemon-reload"]), calls.index(["systemctl", "restart", "arx"]))

    def test_a_stopped_service_is_only_started(self):
        rc, calls, _ = self._install(active=False)
        self.assertEqual(rc, 0)
        self.assertIn(["systemctl", "enable", "--now", "arx"], calls)
        self.assertNotIn(["systemctl", "restart", "arx"], calls)

    def test_a_failed_restart_is_reported(self):
        rc, _, _ = self._install(active=True, fail_restart=True)
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
