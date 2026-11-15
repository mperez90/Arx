"""Pista Q · revisión adversaria de B77-3 (autoría auditd + rebaja «solo dpkg auténtico»), commit cb28885.

HZ#7 (high) — un .deb LOCAL con el nombre de un paquete de repositorio se adopta en silencio (rompe R3).

La rebaja de un fichero de config a «actualización de paquete» (sin alerta) la decide `guard._package_wrote`,
que usa `provenance.signed_origin(pkg)`. Por el arreglo B43, `signed_origin` devuelve «firmado» si el NOMBRE del
paquete lo sirve algún repo firmado en CUALQUIER versión, aunque la versión instalada venga de un `.deb` local
(rama «the installed version is no longer listed»). Así, un atacante con root que instala con `dpkg -i` un `.deb`
malicioso llamado como un paquete real (p. ej. `nginx`) hace que el dpkg auténtico escriba sus ficheros
(`exe=/usr/bin/dpkg`), y `integrity.drift` los adopta sin avisar. R3 dice justo lo contrario: «un .deb local
instalado a mano no rebaja nada».

Invariante correcto: si la versión instalada no la sirve hoy ningún repositorio firmado (es un .deb local),
`_package_wrote` debe ser False aunque el nombre exista en un repo. Repro de la causa:
`provenance.signed_origin` en el escenario de ataque devuelve True (ver test de caracterización).

Ejecutar:  python3 -m pytest tests/test_adv_b773.py -q
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from arx.modules import guard, integrity, pkgdb, provenance  # noqa: E402

DPKG_SIGNED = ("dpkg:\n  Installed: 1.22.6\n  Candidate: 1.22.6\n  Version table:\n"
               " *** 1.22.6 500\n        500 http://deb.debian.org/debian trixie/main amd64 Packages\n"
               "        100 /var/lib/dpkg/status\n")
# nginx: la versión instalada (99.0) SOLO está en /var/lib/dpkg/status (un .deb local); el repo sirve 1.26.
LOCAL_DEB_NAMED_AS_REPO = ("nginx:\n  Installed: 99.0\n  Candidate: 99.0\n  Version table:\n"
                           " *** 99.0 100\n        100 /var/lib/dpkg/status\n"
                           "     1.26.0-1 500\n        500 http://deb.debian.org/debian trixie/main amd64 Packages\n")
PURE_LOCAL = ("evilpkg:\n  Installed: 1.0\n  Candidate: 1.0\n  Version table:\n"
              " *** 1.0 100\n        100 /var/lib/dpkg/status\n")
FROM_REPO = ("nginx:\n  Installed: 1.26.0-1\n  Candidate: 1.26.0-1\n  Version table:\n"
             " *** 1.26.0-1 500\n        500 http://deb.debian.org/debian trixie/main amd64 Packages\n"
             "        100 /var/lib/dpkg/status\n")


def _policy_q(policies):
    """_q simulado: devuelve la política del paquete pedido (último argv)."""
    def q(argv, *a, **k):
        name = argv[-1]
        return policies.get(name)
    return q


class LocalDebNamedAsRepoMustNotDowngrade(unittest.TestCase):

    def setUp(self):
        provenance.clear_cache()
        self.addCleanup(provenance.clear_cache)

    def _package_wrote(self, owner, nginx_policy):
        policies = {"dpkg": DPKG_SIGNED, "nginx": nginx_policy, "evilpkg": nginx_policy}
        with mock.patch.object(pkgdb, "owner", return_value=owner), \
             mock.patch.object(provenance, "intact", return_value=True), \
             mock.patch.object(provenance, "_q", side_effect=_policy_q(policies)):
            provenance.clear_cache()
            return guard._package_wrote("/etc/cron.d/evil")

    def test_signed_origin_cannot_tell_local_deb_from_superseded(self):
        # caracterización de la causa (no es el fallo que hay que arreglar, explica por qué)
        with mock.patch.object(provenance, "_q", side_effect=_policy_q({"nginx": LOCAL_DEB_NAMED_AS_REPO})):
            provenance.clear_cache()
            self.assertTrue(provenance.signed_origin("nginx")[0])

    def test_local_deb_named_as_repo_pkg_is_not_a_package_update(self):
        # EL FALLO: el fichero escrito por un .deb local (nombre de repo) no debe rebajarse
        self.assertFalse(self._package_wrote("nginx", LOCAL_DEB_NAMED_AS_REPO),
                         "un .deb local con nombre de repo se adopta como actualización firmada (R3)")

    def test_pure_local_deb_is_not_a_package_update(self):  # control: ya correcto
        self.assertFalse(self._package_wrote("evilpkg", PURE_LOCAL))

    def test_genuine_repo_package_is_a_package_update(self):  # control: no romper el caso legítimo
        self.assertTrue(self._package_wrote("nginx", FROM_REPO))


if __name__ == "__main__":
    unittest.main()
