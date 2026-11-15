"""Pista Q · arnés de fuzzing y propiedades (R1) contra los analizadores de cfgsem.

R1: los ficheros de configuración los controla un atacante. Propiedades que todo analizador debe cumplir,
con generadores de semilla fija (stdlib, sin dependencias):

  P1  nunca lanza: `analyze` devuelve siempre un `Parsed`.
  P2  `classify` nunca lanza para NINGÚN par (before, after), incluidos None y mezclas ok/ilegible.
  P3  determinismo: la misma entrada da el mismo `Parsed` (y la misma huella `digest`).
  P4  acotado: ninguna entrada dentro de los límites tarda más de un presupuesto por llamada.
  P5  lo ilegible no se ignora: si un fichero legible pasa a ilegible, `classify` SIEMPRE devuelve un Change
      (nunca None). (El caso ilegible→ilegible lo resuelve el hash crudo del llamador — integrity.py, aún no
      integrado: gancho marcado con GAP_INTEGRITY.)
  P6  los límites se respetan: por encima de MAX_TEXT/MAX_ITEMS el resultado es ok=False, nunca una explosión.

Ejecutar:  python3 -m pytest tests/test_adv_fuzz_cfgsem.py -q
"""
import os
import random
import sys
import time
import unittest
import zlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from arx.modules import cfgsem as c  # noqa: E402

GROUPS = ("apt_sources", "apt_conf", "systemd", "authorized_keys_root",
          "authorized_keys_users", "sudoers", "sudoers_d", "cron", "passwd", "ld_preload", "apt_keys")

# Alfabeto hostil: metacaracteres de cada formato, nulos, UTF-8 roto por sustitución y multibyte.
_ALPHABET = list("deb-src[]=#{}\";:,\\ \n\t/.@*+ABCxyzñ0123456789") + ["\x00", "é", "\U0001f600", "\\\n"]
# Semillas con forma real a las que inyectar ruido (más efectivas que el ruido puro para tocar ramas).
_SEEDS = {
    "apt_sources": ["deb [signed-by=/k.gpg] https://ex.org/r stable main",
                    "deb [trusted=yes] http://x/ ./",
                    "Types: deb\nURIs: https://ex.org/r\nSuites: s\nComponents: main\nSigned-By: /k\n"],
    "apt_conf": ['DPkg::Post-Invoke {"/x";};', 'APT::Get::AllowUnauthenticated "true";',
                 'APT { Periodic { Update "1"; }; };', '#include /x\n', '/* c */ Foo "bar";'],
    "systemd": ["[Service]\nExecStart=/a\nExecStartPre=/b\n", "[Timer]\nOnCalendar=daily\n",
                "[Socket]\nListenStream=80\n", "x\\\ny\\\nz\n"],
    "authorized_keys_root": ['ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 user',
                             'command="x",no-pty ssh-rsa AAAAB3 user', "no es una clave"],
    "sudoers": ["u ALL=(ALL) NOPASSWD: ALL", "#1000 ALL=(ALL) ALL", "@includedir /etc/sudoers.d"],
    "cron": ["* * * * * root /x", "@reboot root /y", "# comentario"],
    "passwd": ["root:x:0:0:root:/root:/bin/bash", "evil:x:0:0::/:/bin/sh"],
    "ld_preload": ["/usr/lib/x.so", "/tmp/evil.so\n/a/b.so"],
    "apt_keys": ["\x99\x01binario", "texto"],
}
_SEEDS["authorized_keys_users"] = _SEEDS["authorized_keys_root"]
_SEEDS["sudoers_d"] = _SEEDS["sudoers"]

BUDGET_S = 0.5           # ninguna entrada dentro de límites debe tardar más
CASES_PER_GROUP = 2500


def _mutate(rnd, seed):
    """Inyecta ruido hostil en una semilla: trunca, duplica, intercala metacaracteres, repite."""
    s = seed
    for _ in range(rnd.randint(1, 6)):
        op = rnd.randint(0, 5)
        if op == 0 and s:
            i = rnd.randrange(len(s)); s = s[:i] + rnd.choice(_ALPHABET) + s[i:]
        elif op == 1 and s:
            i = rnd.randrange(len(s)); s = s[:i] + s[i + 1:]
        elif op == 2:
            s = s + rnd.choice(_ALPHABET) * rnd.randint(1, 50)
        elif op == 3:
            s = s * rnd.randint(2, 4)
        elif op == 4 and s:
            i = rnd.randrange(len(s)); s = s[:i] + "\x00" + s[i:]
        else:
            s = "".join(rnd.choice(_ALPHABET) for _ in range(rnd.randint(0, 120)))
    return s


def _gen(group, n):
    rnd = random.Random(zlib.crc32(group.encode()) ^ 0x51)   # semilla fija por grupo (reproducible)
    seeds = _SEEDS[group]
    for _ in range(n):
        yield _mutate(rnd, rnd.choice(seeds))


class FuzzProperties(unittest.TestCase):

    def test_p1_p3_p4_analyze_is_total_deterministic_and_bounded(self):
        worst = 0.0
        for group in GROUPS:
            for text in _gen(group, CASES_PER_GROUP):
                for d in (False, True):
                    t = time.monotonic()
                    p = c.analyze(group, text, deb822=d)
                    dt = time.monotonic() - t
                    worst = max(worst, dt)
                    self.assertIsInstance(p, c.Parsed, f"{group} no devolvió Parsed")
                    self.assertLess(dt, BUDGET_S, f"{group} tardó {dt:.3f}s en {text[:30]!r}")
                    p2 = c.analyze(group, text, deb822=d)
                    self.assertEqual(p, p2, f"{group} no determinista")
                    self.assertEqual(c.digest(p), c.digest(p2))
        self.assertLess(worst, BUDGET_S)

    def test_p2_classify_never_raises_on_any_pair(self):
        for group in GROUPS:
            gen = list(_gen(group, 400))
            parsed = [None] + [c.analyze(group, t) for t in gen[:40]]
            for a in parsed:
                for b in parsed:
                    try:
                        ch = c.classify(group, a, b)
                    except Exception as e:  # noqa: BLE001
                        self.fail(f"classify({group}) lanzó {type(e).__name__}")
                    self.assertTrue(ch is None or isinstance(ch, c.Change))

    def test_p5_a_file_turning_unreadable_is_never_silent(self):
        # un 'before' legible y válido; cualquier 'after' ilegible debe producir un Change (no None).
        readable = {
            "apt_sources": "deb [signed-by=/k] https://e/r s m\n",
            "apt_conf": 'APT::Get::AllowUnauthenticated "false";\n',
            "systemd": "[Service]\nExecStart=/a\n",
            "authorized_keys_root": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 u\n",
            "sudoers": "u ALL=(ALL) ALL\n",
            "cron": "* * * * * root /x\n",
            "passwd": "root:x:0:0::/root:/bin/sh\n",
            "ld_preload": "/usr/lib/x.so\n",
        }
        bad_inputs = ["a\x00b", "x" * (c.MAX_TEXT + 1), 12345, b"bytes"]
        for group, before_txt in readable.items():
            before = c.analyze(group, before_txt)
            self.assertTrue(before.ok, group)
            for bad in bad_inputs:
                after = c.analyze(group, bad)
                if after.ok:
                    continue  # algunas entradas 'malas' podrían ser legibles-vacías en algún grupo
                ch = c.classify(group, before, after)
                self.assertIsNotNone(ch, f"{group}: fichero legible→ilegible quedó en silencio (P5)")
                self.assertEqual(ch.sev, "high", f"{group}: cambio a ilegible debería ser high")

    def test_p6_limits_are_enforced_not_exploded(self):
        self.assertFalse(c.apt_conf("{" * (c.MAX_ITEMS + 100)).ok)      # anidamiento
        self.assertFalse(c.apt_sources("x" * (c.MAX_TEXT + 1)).ok)       # tamaño
        self.assertFalse(c.systemd_unit("x" * (c.MAX_TEXT + 1)).ok)
        # muchos ítems: por encima de MAX_ITEMS no debe devolver un canon gigante
        many = "\n".join(f"deb http://h{i}/ s m" for i in range(c.MAX_ITEMS + 50))
        p = c.apt_sources(many)
        self.assertFalse(p.ok and p.canon is not None and len(p.canon) > c.MAX_ITEMS)


if __name__ == "__main__":
    unittest.main()
