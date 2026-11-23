"""rc12 en u24 (2026-11-23): con el `check_files` ya corregido, nginx-common .21 pasó la confianza y Arx dijo «vuelve a
tener red»… y en el barrido siguiente repuso el confinamiento. Quedaban otros bloqueos del mismo paquete: el veredicto
de .21 hecho a las 06:23 con la comprobación rota (su huella es la de «…|verdict», no la del preventivo) y los de .20,
una versión que ya no está instalada. Solo se levantaba el preventivo de la versión actual.

Regla: cuando la versión instalada de un paquete queda verificada, deja de contener al servicio lo que se decidió por
una actualización no fiable de ESE paquete: de esta misma versión (un veredicto viejo), siempre; de otra versión, solo
si todo el servicio arrancó después del confinamiento (RV de Q: sin reiniciar, en memoria sigue el código de la versión
no fiable). Lo de otro paquete (una librería), de otro servicio, o de otra causa, sigue. El incidente se queda.

Corre con:  python -m unittest discover -s tests
"""
import os

os.environ["ARX_LANG"] = "es"

import sys
import unittest
from datetime import datetime, timezone
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from arx.modules import profile, response, trust  # noqa: E402

NGINX = "system.slice/nginx.service"


def _block(fp, path):
    return {"fp": fp, "revert": {"tool": "confine", "units": [{"unit": path.rsplit("/", 1)[-1], "path": path,
                                                                 "set": "confined2"}], "scopes": []}}


class UntrustedConfinements(unittest.TestCase):
    def test_only_this_package_and_this_service(self):
        blocks = [_block("a20", NGINX), _block("a21v", NGINX), _block("lib", NGINX), _block("other", "system.slice/x.service"),
                  _block("scan", NGINX), {"fp": "ip", "revert": {"tool": "nft_drop", "ip": "203.0.113.9"}}]
        findings = {"a20": {"set": "untrusted_update", "item": "nginx-common=1.24.0-2ubuntu7.20"},
                    "a21v": {"set": "untrusted_update", "item": "nginx-common=1.24.0-2ubuntu7.21"},
                    "lib": {"set": "untrusted_update", "item": "libssl3t64=3.0.13-0ubuntu3.6"},
                    "other": {"set": "untrusted_update", "item": "nginx-common=1.24.0-2ubuntu7.21"},
                    "scan": {"kind": "port_scan"}, "ip": {"kind": "port_scan"}}
        with mock.patch.object(response, "_load_blocks", return_value=blocks), \
                mock.patch.object(response, "load_findings", return_value=findings):
            got = response.untrusted_confinements(NGINX, "nginx-common")
        self.assertEqual(sorted((b["fp"], b["version"]) for b in got),
                         [("a20", "1.24.0-2ubuntu7.20"), ("a21v", "1.24.0-2ubuntu7.21")])


class TrustedLiftsTheStaleOnes(unittest.TestCase):
    def _run(self, confined, restarted=True):
        now = datetime(2026, 11, 23, 15, 42, tzinfo=timezone.utc)
        stale = f"untrusted_update|{NGINX}|nginx-common=1.24.0-2ubuntu7.20"
        s = {"unit": "nginx.service", "package": "nginx-common", "version": "1.24.0-2ubuntu7.21", "libs": {},
             "recheck": "2026-11-23T15:31:00+00:00", "held": {stale: "2026-11-20T06:24:00+00:00"}}
        blocks = [{"fp": "a20", "version": "1.24.0-2ubuntu7.20", "applied_at": "2026-11-20T07:24:00+00:00"},
                  {"fp": "a21v", "version": "1.24.0-2ubuntu7.21", "applied_at": "2026-11-23T06:24:00+00:00"}]
        forgotten, recorded = [], []
        with mock.patch.object(trust, "assess_async", return_value={"state": "done", "trusted": True,
                                                                    "checks": [], "reason": "ok"}), \
                mock.patch.object(response, "untrusted_confinements", return_value=blocks) as uc, \
                mock.patch.object(response, "forget", side_effect=lambda fp: forgotten.append(fp) or {"fp": fp}), \
                mock.patch.object(response, "record", side_effect=recorded.append), \
                mock.patch.object(profile, "_started_after", return_value=restarted), \
                mock.patch.object(profile, "_critical", return_value=False):
            found = profile._updates({NGINX: s}, {}, now, check_versions=False, confined=confined)
        return found, forgotten, recorded, s, uc

    def test_a_verified_version_lifts_what_older_verdicts_of_its_package_left(self):
        found, forgotten, recorded, s, _ = self._run({NGINX})
        self.assertEqual(found, [])
        self.assertEqual(sorted(forgotten), ["a20", "a21v"])
        self.assertEqual(s["held"], {}, "lo retenido de una versión que ya no corre tampoco sigue")
        self.assertEqual([r["kind"] for r in recorded], ["trust_confirmed"])

    def test_without_a_restart_only_the_same_version_is_lifted(self):
        # RV de Q: v2 no fiable corre confinada; llega v3 limpia a disco sin reiniciar el servicio. v3 verifica, pero
        # lo que corre sigue siendo v2: su confinamiento se queda. El de la MISMA versión (FP de nginx) sí se levanta.
        _, forgotten, _, s, _ = self._run({NGINX}, restarted=False)
        self.assertEqual(forgotten, ["a21v"])
        self.assertIn(f"untrusted_update|{NGINX}|nginx-common=1.24.0-2ubuntu7.20", s["held"])

    def test_nothing_is_searched_when_the_service_is_not_confined(self):
        _, forgotten, recorded, _, uc = self._run(set())
        uc.assert_not_called()  # cada barrido, para cada servicio: solo se busca si de verdad está confinado
        self.assertEqual(forgotten, [])
        self.assertEqual(recorded, [])


class StartedAfter(unittest.TestCase):
    def _fake(self, starts_ticks, btime=1_795_000_000):
        files = {"/proc/stat": f"cpu  1 2 3\nbtime {btime}\n"}
        for pid, ticks in starts_ticks.items():
            rest = ["S", "1"] + ["0"] * 17 + [str(ticks)] + ["0"] * 10  # campo 22 = índice 19 tras «)»
            files[f"/proc/{pid}/stat"] = f"{pid} (nginx: worker) " + " ".join(rest)
        real_open = open

        def fake_open(path, *a, **k):
            if path in files:
                return mock.mock_open(read_data=files[path])()
            if str(path).startswith("/proc/"):
                raise FileNotFoundError(path)
            return real_open(path, *a, **k)
        return mock.patch("builtins.open", side_effect=fake_open), mock.patch.object(profile.os, "sysconf",
                                                                                      return_value=100)

    def _check(self, starts, when):
        o, h = self._fake(starts)
        with o, h, mock.patch.object(profile, "_cgroup_pids", return_value=list(starts)):
            return profile._started_after(NGINX, when)

    def test_all_processes_newer_than_the_confinement(self):
        when = datetime.fromtimestamp(1_795_000_000 + 500, timezone.utc)
        self.assertTrue(self._check({10: 60_000, 11: 60_100}, when))      # 600 s y 601 s tras el arranque

    def test_one_old_process_is_enough_to_say_no(self):
        when = datetime.fromtimestamp(1_795_000_000 + 500, timezone.utc)
        self.assertFalse(self._check({10: 40_000, 11: 60_100}, when))     # el maestro (400 s) es de antes

    def test_no_time_or_an_unreadable_process_says_no(self):
        self.assertFalse(self._check({10: 60_000}, None))
        o, h = self._fake({})
        with o, h, mock.patch.object(profile, "_cgroup_pids", return_value=[99]):
            self.assertFalse(profile._started_after(NGINX, "2026-11-23T06:24:00+00:00"))


if __name__ == "__main__":
    unittest.main()
