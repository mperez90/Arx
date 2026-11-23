"""rc12 en u24 (2026-11-23): con el `check_files` ya corregido, nginx-common .21 pasó la confianza y Arx dijo «vuelve a
tener red»… y en el barrido siguiente repuso el confinamiento. Quedaban otros bloqueos del mismo paquete: el veredicto
de .21 hecho a las 06:23 con la comprobación rota (su huella es la de «…|verdict», no la del preventivo) y los de .20,
una versión que ya no está instalada. Solo se levantaba el preventivo de la versión actual.

Regla: cuando la versión instalada de un paquete queda verificada, deja de contener al servicio lo que se decidió por
una actualización no fiable de ESE paquete (esta versión con un veredicto viejo, o versiones que ya no corren). Lo de
otro paquete (una librería), de otro servicio, o de otra causa, sigue. El incidente se queda en el registro.

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
            self.assertEqual(sorted(response.untrusted_confinements(NGINX, "nginx-common")), ["a20", "a21v"])


class TrustedLiftsTheStaleOnes(unittest.TestCase):
    def _run(self, confined):
        now = datetime(2026, 11, 23, 15, 42, tzinfo=timezone.utc)
        stale = f"untrusted_update|{NGINX}|nginx-common=1.24.0-2ubuntu7.20"
        s = {"unit": "nginx.service", "package": "nginx-common", "version": "1.24.0-2ubuntu7.21", "libs": {},
             "recheck": "2026-11-23T15:31:00+00:00", "held": {stale: "2026-11-20T06:24:00+00:00"}}
        forgotten, recorded = [], []
        with mock.patch.object(trust, "assess_async", return_value={"state": "done", "trusted": True,
                                                                            "checks": [], "reason": "ok"}), \
                mock.patch.object(response, "untrusted_confinements", return_value=["a20", "a21v"]) as uc, \
                mock.patch.object(response, "forget", side_effect=lambda fp: forgotten.append(fp) or {"fp": fp}), \
                mock.patch.object(response, "record", side_effect=recorded.append), \
                mock.patch.object(profile, "_critical", return_value=False):
            found = profile._updates({NGINX: s}, {}, now, check_versions=False, confined=confined)
        return found, forgotten, recorded, s, uc

    def test_a_verified_version_lifts_what_older_verdicts_of_its_package_left(self):
        found, forgotten, recorded, s, _ = self._run({NGINX})
        self.assertEqual(found, [])
        self.assertEqual(sorted(forgotten), ["a20", "a21v"])
        self.assertEqual(s["held"], {}, "lo retenido de una versión que ya no corre tampoco sigue")
        self.assertEqual([r["kind"] for r in recorded], ["trust_confirmed"])

    def test_nothing_is_searched_when_the_service_is_not_confined(self):
        _, forgotten, recorded, _, uc = self._run(set())
        uc.assert_not_called()  # cada barrido, para cada servicio: solo se busca si de verdad está confinado
        self.assertEqual(forgotten, [])
        self.assertEqual(recorded, [])


if __name__ == "__main__":
    unittest.main()
