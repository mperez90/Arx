"""B75 · packaging/install.sh: apt instala el .deb y sus dependencias en un solo paso, la salida es limpia y hay un
único mensaje final. Se corre el script de verdad (`sh install.sh`) con `apt-get`, `dpkg-query`, `curl`, `systemctl`
y `arx` simulados en el PATH: sin red, sin root, sin tocar el host. Los contenedores reales (Ubuntu 24.04/22.04,
Debian 13) lo comprueban en el lab de instalación. Corre con:  python -m unittest discover -s tests
"""
import hashlib
import os
import stat
import subprocess
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..")
SCRIPT = os.environ.get("ARX_INSTALL_SH") or os.path.join(ROOT, "packaging", "install.sh")
DEB_BYTES = b"!<arch>\nfake deb\n"

STUBS = {
    "id": '#!/bin/sh\n[ "$1" = "-u" ] && echo 0 || echo root\n',
    "dpkg": "#!/bin/sh\nexit 0\n",
    # dpkg-query -W -f='${Status}' NAME → «install ok installed» solo para lo de FAKE_INSTALLED
    "dpkg-query": '#!/bin/sh\nfor a; do last="$a"; done\n'
                  'case " $FAKE_INSTALLED " in *" $last "*) printf "install ok installed";; *) exit 1;; esac\n',
    "sha256sum": '#!/bin/sh\nexec shasum -a 256 "$@"\n',
    "arx": '#!/bin/sh\necho "arx $*" >> "$FAKE_LOG"\nexit 0\n',
    "systemctl": "#!/bin/sh\nexit 0\n",
    "apt-get": r"""#!/bin/sh
echo "apt-get $*" >> "$FAKE_LOG"
case "$1" in
  update) echo "Hit:1 http://archive.ubuntu.com noble InRelease"; echo "Reading package lists... Done"; exit 0;;
esac
# install: el último argumento es el .deb; apt (usuario _apt) tiene que poder leerlo
for a; do deb="$a"; done
case "$deb" in /*) ;; *) echo "apt-get: not an absolute path: $deb" >> "$FAKE_LOG"; exit 100;; esac
[ -r "$deb" ] || { echo "apt-get: cannot read $deb" >> "$FAKE_LOG"; exit 100; }
[ "$(ls -ld "$(dirname "$deb")" | cut -c8-10)" = "r-x" ] || echo "apt-get: directory not readable by _apt" >> "$FAKE_LOG"
echo "env DEBIAN_FRONTEND=$DEBIAN_FRONTEND NEEDRESTART_MODE=$NEEDRESTART_MODE" >> "$FAKE_LOG"
echo "Reading package lists... Done"
echo "The following NEW packages will be installed: auditd arx"
if [ -n "$FAKE_APT_FAIL" ]; then
  echo "E: Unable to locate package auditd" >&2
  exit 100
fi
echo "Setting up arx (0.0.9) ..."
printf '\nArx installed. To put it on guard:\n  sudo arx setup            # language, LLM model, authorization word, license\n\n'
exit 0
""",
    "curl": r"""#!/bin/sh
echo "curl $*" >> "$FAKE_LOG"
url="$2"; out="$4"
case "$url" in
  */SHA256SUMS) printf '%s  arx_all.deb\n' "$FAKE_SUM" > "$out";;
  *) cp "$FAKE_DEB" "$out";;
esac
""",
}


class InstallShTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.bin = os.path.join(self.dir, "bin")
        os.mkdir(self.bin)
        for name, body in STUBS.items():
            path = os.path.join(self.bin, name)
            with open(path, "w") as f:
                f.write(body)
            os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
        self.deb = os.path.join(self.dir, "arx_all.deb")
        with open(self.deb, "wb") as f:
            f.write(DEB_BYTES)
        self.log = os.path.join(self.dir, "calls.log")
        open(self.log, "w").close()

    def run_install(self, installed="python3 auditd", cwd=None, **env):
        full = {"PATH": self.bin + os.pathsep + os.environ["PATH"], "FAKE_LOG": self.log,
                "FAKE_INSTALLED": installed, "FAKE_DEB": self.deb, "HOME": self.dir, "TMPDIR": self.dir, **env}
        return subprocess.run(["sh", SCRIPT], capture_output=True, text=True, env=full, cwd=cwd or self.dir)

    def calls(self):
        return open(self.log).read().splitlines()

    def apt_calls(self):
        return [c for c in self.calls() if c.startswith("apt-get ")]

    def test_one_apt_call_installs_the_package_with_its_dependencies(self):
        r = self.run_install(ARX_DEB_PATH="arx_all.deb")  # ruta relativa: apt la tomaría por un nombre de paquete
        self.assertEqual(r.returncode, 0, r.stderr)
        installs = [c for c in self.apt_calls() if " install " in c]
        self.assertEqual(len(installs), 1, self.calls())
        self.assertIn("-y", installs[0])
        self.assertNotIn("dpkg", " ".join(self.calls()))  # ya no hay dpkg -i y «apt-get install -f» detrás
        self.assertNotIn("-f ", installs[0])
        self.assertIn("DPkg::Lock::Timeout=", installs[0])  # cloud-init o unattended-upgrades pueden tener el cerrojo
        self.assertFalse([c for c in self.calls() if c.startswith("apt-get:")], self.calls())

    def test_the_output_is_clean_and_there_is_a_single_final_message(self):
        r = self.run_install(ARX_DEB_PATH=self.deb)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.count("Arx installed"), 1, r.stdout)
        for noise in ("Reading package lists", "Setting up arx", "NEW packages", "Hit:1"):
            self.assertNotIn(noise, r.stdout + r.stderr)
        self.assertTrue(r.stdout.rstrip().endswith("man arx                   # the full manual"), r.stdout)

    def test_apt_gets_a_readable_absolute_copy_and_no_questions(self):
        r = self.run_install(ARX_DEB_PATH="arx_all.deb")
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = self.calls()
        self.assertNotIn("apt-get: directory not readable by _apt", calls)
        self.assertIn("env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l", calls)

    def test_the_package_lists_are_refreshed_only_when_a_dependency_is_missing(self):
        self.run_install(installed="python3 auditd", ARX_DEB_PATH=self.deb)
        self.assertEqual([c for c in self.apt_calls() if " update" in c], [])
        open(self.log, "w").close()
        self.run_install(installed="python3", ARX_DEB_PATH=self.deb)  # falta auditd
        kinds = [c.split()[1] for c in self.apt_calls()]
        self.assertEqual(kinds, ["update", "install"])

    def test_a_failed_install_shows_apt_s_output_and_does_not_claim_success(self):
        r = self.run_install(installed="python3", ARX_DEB_PATH=self.deb, FAKE_APT_FAIL="1")
        self.assertEqual(r.returncode, 1)
        self.assertIn("E: Unable to locate package auditd", r.stderr)
        self.assertNotIn("Arx installed", r.stdout)
        self.assertEqual(self.calls().count("arx telemetry ask"), 0)

    def test_arx_deb_path_must_be_a_file(self):
        r = self.run_install(ARX_DEB_PATH=os.path.join(self.dir, "nope.deb"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("ARX_DEB_PATH", r.stdout)
        self.assertEqual(self.apt_calls(), [])

    def test_a_download_whose_hash_does_not_match_is_never_installed(self):
        r = self.run_install(ARX_DEB_URL="https://example.invalid/releases/latest/download/arx_all.deb",
                             FAKE_SUM="0" * 64)
        self.assertEqual(r.returncode, 1)
        self.assertIn("NOT installing", r.stdout)
        self.assertEqual(self.apt_calls(), [])

    def test_a_verified_download_is_installed_once(self):
        good = hashlib.sha256(DEB_BYTES).hexdigest()
        r = self.run_install(ARX_DEB_URL="https://example.invalid/releases/latest/download/arx_all.deb", FAKE_SUM=good)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(f"Integrity verified (sha256 {good})", r.stdout)
        self.assertEqual(len([c for c in self.apt_calls() if " install " in c]), 1)
        self.assertEqual(r.stdout.count("Arx installed"), 1)

    def test_the_telemetry_question_comes_before_the_final_message(self):
        r = self.run_install(ARX_DEB_PATH=self.deb)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.calls().count("arx telemetry ask"), 1)

    @unittest.skipUnless(os.path.isdir("/run/systemd/system"), "el aviso de auditd solo existe en un host con systemd")
    def test_a_stopped_auditd_gets_one_warning_and_still_one_final_message(self):
        # systemctl simulado: is-active falla (parado) y enable --now también
        with open(os.path.join(self.bin, "systemctl"), "w") as f:
            f.write("#!/bin/sh\nexit 3\n")
        r = self.run_install(ARX_DEB_PATH=self.deb)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.count("auditd is installed but not running"), 1, r.stdout)
        self.assertEqual(r.stdout.count("Arx installed"), 1, r.stdout)


if __name__ == "__main__":
    unittest.main()
