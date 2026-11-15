"""Pista Q · revisión adversaria de integrity.py (B77-2, commit d7220be).

HZ#6 (high): en `drift`, el chequeo de permisos/dueño (`_loosened`) solo se evalúa en la rama de «sha igual»
(el fichero no cambió de contenido). Si el atacante **afloja los permisos o cambia el dueño** de un fichero
crítico Y a la vez hace un cambio de contenido que `cfgsem` considera semánticamente nulo (un comentario,
espacios), la rama de contenido devuelve `classify = None` y la de permisos nunca se ejecuta: el aflojamiento
queda SIN alerta. El atacante controla ambas cosas, así que puede dejar un `sudoers.d` world-writable o un
`authorized_keys` de root propiedad de un usuario sin que Arx lo vea.

Correcto: un aflojamiento de permisos o un cambio de dueño se informa SIEMPRE, cambie o no el contenido.

Ejecutar:  python3 -m pytest tests/test_adv_integrity.py -q
"""
import hashlib
import os
import sys
import unittest

os.environ["ARX_LANG"] = "es"  # antes de importar Arx: el idioma se fija con la primera traducción
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from arx.modules import integrity as I  # noqa: E402
from arx.modules import cfgsem  # noqa: E402


def _state(group, data, mode, uid=0, gid=0):
    raw = data if isinstance(data, bytes) else data.encode()
    parsed = cfgsem.analyze(group, raw if group == "apt_keys" else raw.decode())
    return {"g": group, "mode": mode, "uid": uid, "gid": gid,
            "sha": hashlib.sha256(raw).hexdigest(),
            "ok": parsed.ok, "canon": I._jsonable(parsed.canon) if parsed.ok else None}


def _drift(path, before, after):
    findings, _adopt = I.drift({path: before}, {path: after})
    return findings


class PermissionLooseningIsNeverSilent(unittest.TestCase):

    def test_perms_only_is_detected(self):  # control: hoy ya funciona
        p = "/etc/sudoers.d/x"
        f = _drift(p, _state("sudoers_d", "nobody ALL=(ALL) ALL\n", 0o440),
                   _state("sudoers_d", "nobody ALL=(ALL) ALL\n", 0o666))
        self.assertTrue(f, "aflojar permisos sin tocar contenido debe alertar")
        self.assertEqual(f[0]["sev"], "high")

    def test_world_writable_with_null_content_change_is_detected(self):
        # mundo-escribible + un comentario (semánticamente nulo): hoy EVADE
        p = "/etc/sudoers.d/x"
        f = _drift(p, _state("sudoers_d", "nobody ALL=(ALL) ALL\n", 0o440),
                   _state("sudoers_d", "nobody ALL=(ALL) ALL\n# comentario\n", 0o666))
        self.assertTrue(f, "world-writable escondido tras un comentario quedó en silencio")
        self.assertEqual(max(x["sev"] for x in f), "high")

    def test_owner_change_with_null_content_change_is_detected(self):
        # authorized_keys de root pasa a ser de un usuario (uid 1000) + comentario: hoy EVADE
        p = "/root/.ssh/authorized_keys"
        key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 u\n"
        f = _drift(p, _state("authorized_keys_root", key, 0o600, uid=0),
                   _state("authorized_keys_root", key + "# x\n", 0o600, uid=1000))
        self.assertTrue(f, "cambio de dueño escondido tras un comentario quedó en silencio")

    def test_a_pure_null_change_stays_silent(self):  # control negativo: no debe haber FP
        p = "/etc/sudoers.d/x"
        f = _drift(p, _state("sudoers_d", "nobody ALL=(ALL) ALL\n", 0o440),
                   _state("sudoers_d", "nobody ALL=(ALL) ALL\n# comentario\n", 0o440))
        self.assertEqual(f, [], "un comentario sin cambio de permisos no debe alertar")


if __name__ == "__main__":
    unittest.main()
