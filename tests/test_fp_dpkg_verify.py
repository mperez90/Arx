"""rc11 en el piloto A (u24, 2026-11-23 06:23): la actualización desatendida de nginx salió crit «untrusted_update»,
confianza 0,00 — «cambiado desde que se instaló: etc/nginx/nginx.conf». Era el nginx.conf que edita el administrador.

`check_files` leía `dpkg --verify` por posiciones fijas (la «c» de conffile en la columna 11 y la ruta desde la 13),
pero dpkg escribe «%.9s %c %s»: la «c» va en la 10 y la ruta empieza en la 12. Ningún conffile cambiado se reconocía
como tal (y a las rutas les faltaba la «/»). Las pruebas usaban dos espacios: el formato que no existe.

Líneas copiadas tal cual de dpkg 1.22.6 en Ubuntu 24.04 (`dpkg --verify nginx nginx-common | sed -n l`).
Corre con:  python -m unittest discover -s tests
"""
import os

os.environ["ARX_LANG"] = "es"

import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from arx.modules import trust  # noqa: E402

F = {"package": "nginx", "version": "1.24.0-2ubuntu7.21", "arch": "amd64", "source": "nginx"}
REAL_CONFFILE = "??5?????? c /etc/nginx/nginx.conf\n"          # dpkg 1.22.6, byte a byte
REAL_PROGRAM = "??5??????   /usr/sbin/nginx\n"                  # «%.9s %c %s» con atributo «espacio»


class DpkgVerifyRealFormat(unittest.TestCase):
    def _check(self, out, rc=1, conffiles=frozenset()):
        with mock.patch.object(trust, "_run", return_value=(rc, out)), \
                mock.patch.object(trust, "_conffiles", return_value=set(conffiles)), \
                mock.patch.object(trust, "_dpkg_filters", return_value=[]):
            return trust.check_files(F)

    def test_an_edited_conffile_is_the_admins_not_a_tampered_package(self):
        r = self._check(REAL_CONFFILE, conffiles={"/etc/nginx/nginx.conf"})
        self.assertEqual(r["result"], "pass", r["detail"])

    def test_the_conffile_mark_alone_is_enough(self):
        # sin `.conffiles` legible, la «c» que pone dpkg basta
        self.assertEqual(self._check(REAL_CONFFILE)["result"], "pass")

    def test_a_file_dpkg_lists_as_conffile_counts_even_without_the_mark(self):
        self.assertEqual(self._check("??5??????   /etc/nginx/nginx.conf\n",
                                     conffiles={"/etc/nginx/nginx.conf"})["result"], "pass")

    def test_a_changed_program_still_fails_and_is_named_with_its_full_path(self):
        r = self._check(REAL_CONFFILE + REAL_PROGRAM, conffiles={"/etc/nginx/nginx.conf"})
        self.assertEqual(r["result"], "fail")
        self.assertIn("/usr/sbin/nginx", r["detail"])
        self.assertNotIn("nginx.conf", r["detail"])

    def test_the_old_two_space_layout_is_still_understood(self):
        self.assertEqual(self._check("??5??????  c /etc/xz.conf\n")["result"], "pass")
        self.assertEqual(self._check("??5??????    /usr/bin/xz\n")["result"], "fail")


if __name__ == "__main__":
    unittest.main()
