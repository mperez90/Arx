"""FP de auditd «identidad» en una actualización de paquete (piloto d13, 2026-11-22 06:27, unattended-upgrades de sudo).

`sensors.read_auditd_events` abría un high por cada escritura que auditd veía en un fichero de identidad, también
cuando la hacía el dpkg verificado desplegando un paquete firmado, o los hijos de sus scripts de mantenimiento
(`chown`/`chmod` del postinst de sudo). Con los registros REALES de ese host (`tests/data/d13-sudo-audit.log`, y el
`dpkg.log` de esa hora en `tests/data/d13-sudo-dpkg.log`): lo que escribe dpkg o un hijo suyo, DENTRO de la transacción
del paquete dueño del fichero, deja de ser un high y queda como info. Sigue siendo high: un .deb local o de un
repositorio sin firma, una escritura fuera de una transacción, un fichero que no es del paquete en curso, un dpkg o
una herramienta alterados, y cualquier escritura de una sesión de login.

Corre con: python -m unittest discover -s tests
"""
import os

os.environ["ARX_LANG"] = "es"

import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

DATA = os.path.join(os.path.dirname(__file__), "data")
AUDIT = os.path.join(DATA, "d13-sudo-audit.log")
DPKG_LOG = os.path.join(DATA, "d13-sudo-dpkg.log")
T0 = 1795328809.207   # el primer evento real de sudo
NOW = 1795328900.0    # cuando «barre» Arx: ya ha pasado el margen de los eventos recientes

OWNERS = {"/etc/sudoers": "sudo", "/etc/sudoers.d/README": "sudo", "/usr/bin/dpkg": "dpkg",
          "/usr/bin/chown": "coreutils", "/usr/bin/chmod": "coreutils", "/usr/bin/dash": "dash",
          "/etc/ssh/sshd_config": "openssh-server", "/etc/pam.d/sshd": "openssh-server"}


def _isolate():
    d = tempfile.mkdtemp()
    os.environ["ARX_CONFIG_DIR"] = os.path.join(d, "cfg")
    os.environ["ARX_STATE_DIR"] = os.path.join(d, "state")
    os.environ["ARX_POLAR_ENV"] = "sandbox"
    return d


def real_records() -> list[str]:
    with open(AUDIT, encoding="utf-8") as f:
        return f.read().splitlines()


def audit_event(serial, t, exe, names, *, syscall="268", success="yes", auid="4294967295", ses="4294967295",
                uid="0", euid=None, ppid="424688", pid="424690", nametypes=None, cwd="/", key="arx_ident"):
    """Un evento tal como lo escribe auditd (SYSCALL + CWD + PATH…), con los campos que importan a Arx."""
    a = f"msg=audit({t:.3f}:{serial})"
    comm = os.path.basename(exe)
    lines = [f'type=SYSCALL {a}: arch=c000003e syscall={syscall} success={success} exit=0 a0=ffffff9c a1=5626004da620 '
             f'a2=120 a3=120 items={len(names)} ppid={ppid} pid={pid} auid={auid} uid={uid} gid=0 euid={euid or uid} '
             f'suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses={ses} comm="{comm}" exe="{exe}" subj=unconfined '
             f'key="{key}"', f'type=CWD {a}: cwd="{cwd}"']
    for i, name in enumerate(names):
        kind = (nametypes or {}).get(name, "NORMAL")
        shown = f'"{name}"' if name != "(null)" else "(null)"
        lines.append(f"type=PATH {a}: item={i} name={shown} inode={800 + i} dev=08:01 mode=0100440 ouid=0 ogid=0 "
                     f"rdev=00:00 nametype={kind} cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0")
    lines.append(f"type=PROCTITLE {a}: proctitle=63686D6F6400343430")
    return lines


class Base(unittest.TestCase):
    """Un host simulado: un log de auditd que se va llenando, su dpkg.log, y las respuestas de dpkg/apt."""

    def setUp(self):
        d = _isolate()
        from arx.modules import pkgdb, pkgtx, provenance, sensors
        self.s, self.p, self.pkgdb, self.prov = sensors, pkgtx, pkgdb, provenance
        self.log = os.path.join(d, "audit.log")
        open(self.log, "w").close()
        self.unsigned: set = set()
        self.not_intact: set = set()
        self.owners = dict(OWNERS)
        self.dpkg_log = DPKG_LOG
        self.now = NOW
        for obj, name, value in (
                (sensors, "AUDIT_LOG", self.log), (sensors, "AUDIT_CONF", os.path.join(d, "no-auditd.conf")),
                (sensors.time, "time", lambda: self.now), (sensors.shutil, "which", lambda *a, **k: None),
                (pkgdb, "owner", lambda path: self.owners.get(path)),
                (provenance, "intact", lambda path, pkg: pkg not in self.not_intact),
                (provenance, "signed_origin",
                 lambda pkg, installed_only=False: (pkg not in self.unsigned, "repo")),
                (pkgtx, "DPKG_LOGS", (self.dpkg_log,))):
            patch = mock.patch.object(obj, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        old_tz = os.environ.get("TZ")
        os.environ["TZ"] = "UTC"  # dpkg.log va en hora local: el host del piloto estaba en UTC
        time.tzset()

        def restore():
            if old_tz is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = old_tz
            time.tzset()
        self.addCleanup(restore)
        sensors._audit_pending.clear()
        pkgtx.clear_cache()
        self.addCleanup(sensors._audit_pending.clear)
        self.addCleanup(pkgtx.clear_cache)
        sensors._audit_poll()  # fija el punto de partida: lo siguiente es lo «nuevo»

    def use_log(self, lines):
        path = os.path.join(os.path.dirname(self.log), "dpkg.log")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        self.p.DPKG_LOGS = (path,)
        self.p.clear_cache()
        return path

    def feed(self, *groups):
        with open(self.log, "a", encoding="utf-8") as f:
            for g in groups:
                f.write("".join(line + "\n" for line in g))
        return self.s.read_auditd_events()

    def high(self, got):
        return [e for e in got if e["sev"] in ("high", "crit")]

    def info(self, got):
        return [e for e in got if e["sev"] == "info"]


SUDO_TX = [
    "2026-11-22 06:26:49 startup archives unpack",
    "2026-11-22 06:26:49 upgrade sudo:amd64 1.9.16p2-3+deb13u2 1.9.16p2-3+deb13u5",
    "2026-11-22 06:26:49 status half-configured sudo:amd64 1.9.16p2-3+deb13u2",
    "2026-11-22 06:26:49 status unpacked sudo:amd64 1.9.16p2-3+deb13u2",
    "2026-11-22 06:26:49 status half-installed sudo:amd64 1.9.16p2-3+deb13u2",
    "2026-11-22 06:26:49 status unpacked sudo:amd64 1.9.16p2-3+deb13u5",
    "2026-11-22 06:26:49 startup packages configure",
    "2026-11-22 06:26:49 configure sudo:amd64 1.9.16p2-3+deb13u5 <none>",
    "2026-11-22 06:26:49 status unpacked sudo:amd64 1.9.16p2-3+deb13u5",
    "2026-11-22 06:26:49 status half-configured sudo:amd64 1.9.16p2-3+deb13u5",
    "2026-11-22 06:26:49 status installed sudo:amd64 1.9.16p2-3+deb13u5",
]


class RealD13RecordsTests(Base):
    """El caso del piloto, con los registros reales."""

    def test_the_real_records_of_the_pilot_open_no_high(self):
        """Con el dpkg.log de ese host salían nueve high (`evidencia/fp-auditd-antes.txt`). Ahora, ninguno."""
        got = self.feed(real_records())
        self.assertEqual(self.high(got), [], [e["detail"] for e in self.high(got)])

    def test_it_is_not_lost_it_stays_as_one_info_that_names_the_package(self):
        got = self.feed(real_records())
        self.assertEqual(len(self.info(got)), 1)
        f = self.info(got)[0]
        self.assertIn("sudo", f["detail"])
        self.assertIn("/etc/sudoers", f["detail"])
        self.assertEqual(f["target"]["package"], "sudo")
        self.assertIn("/etc/sudoers.d/README", f["target"]["files"])
        self.assertIn("/etc/sudoers", f["target"]["files"])
        self.assertEqual(f["fp_key"], "auditd|package|sudo|1.9.16p2-3+deb13u5")

    def test_the_info_counts_what_it_covers_and_who_wrote_it(self):
        f = self.info(self.feed(real_records()))[0]
        self.assertEqual(f["target"]["events"], 9)           # 7 de dpkg y el chown y el chmod de su postinst
        self.assertEqual(f["target"]["writers"], ["dpkg", "script"])
        self.assertEqual(f["target"]["version"], "1.9.16p2-3+deb13u5")
        self.assertIn("1.9.16p2-3+deb13u5", f["detail"])

    def test_the_records_come_in_two_sweeps_and_the_result_is_the_same(self):
        recs = real_records()
        cut = next(i for i, line in enumerate(recs) if "29635" in line)
        first = self.feed(recs[:cut])
        second = self.feed(recs[cut:])
        self.assertEqual(self.high(first) + self.high(second), [])

    def test_the_info_is_the_same_finding_when_the_transaction_spans_two_sweeps(self):
        recs = real_records()
        cut = next(i for i, line in enumerate(recs) if "29635" in line)
        a, b = self.info(self.feed(recs[:cut])), self.info(self.feed(recs[cut:]))
        self.assertEqual(a[0]["fp_key"], b[0]["fp_key"])

    def test_without_the_sudo_transaction_in_dpkg_log_everything_stays_high(self):
        with open(DPKG_LOG, encoding="utf-8") as f:
            self.use_log([line for line in f.read().splitlines() if "sudo" not in line])
        self.assertEqual(len(self.high(self.feed(real_records()))), 9)

    def test_a_dpkg_log_that_cannot_be_read_explains_nothing(self):
        self.p.DPKG_LOGS = (os.path.join(os.path.dirname(self.log), "no-existe.log"),)
        self.p.clear_cache()
        self.assertEqual(len(self.high(self.feed(real_records()))), 9)

    def test_the_transaction_a_few_seconds_later_does_not_cover_these_events(self):
        late = [l.replace("06:26:49", "06:27:30") for l in SUDO_TX]
        self.use_log(late)
        self.assertEqual(len(self.high(self.feed(real_records()))), 9)

    def test_the_transaction_before_the_events_does_not_cover_them_either(self):
        early = [l.replace("06:26:49", "06:26:40") for l in SUDO_TX]
        self.use_log(early)
        self.assertEqual(len(self.high(self.feed(real_records()))), 9)

    def test_a_local_deb_or_an_unsigned_repository_is_never_a_package_update(self):
        self.unsigned.add("sudo")
        self.assertEqual(len(self.high(self.feed(real_records()))), 9)

    def test_a_dpkg_that_is_not_intact_or_not_signed_explains_nothing_not_even_its_children(self):
        for case in ("intact", "signed"):
            self.s._audit_pending.clear()
            self.not_intact.clear()
            self.unsigned.clear()
            (self.not_intact if case == "intact" else self.unsigned).add("dpkg")
            self.p.clear_cache()
            self.assertEqual(len(self.high(self.feed(real_records()))), 9, case)

    def test_a_package_the_files_do_not_belong_to_in_progress_stays_high(self):
        """sudo está en transacción, pero /etc/pam.d/sshd es de openssh-server: no es del paquete en curso."""
        ev = audit_event(5000, T0 + 0.5, "/usr/bin/dpkg", ["/etc/pam.d/sshd"], pid="424671", ppid="424652")
        self.assertEqual(len(self.high(self.feed(ev))), 1)

    def test_a_file_no_package_owns_stays_high_even_in_a_transaction(self):
        ev = audit_event(5001, T0 + 0.5, "/usr/bin/dpkg", ["/etc/sudoers.d/evil"], pid="424671", ppid="424652")
        self.assertEqual(len(self.high(self.feed(ev))), 1)

    def test_one_foreign_file_among_the_package_ones_keeps_the_whole_event_high(self):
        ev = audit_event(5002, T0 + 0.5, "/usr/bin/dpkg", ["/etc/sudoers", "/etc/sudoers.d/evil"], syscall="82",
                         pid="424671", ppid="424652")
        self.assertEqual(len(self.high(self.feed(ev))), 1)


class ChildrenOfMaintainerScriptsTests(Base):
    """El chown/chmod del postinst: ni dpkg ni un login, un hijo suyo sin auid dentro de la transacción."""

    def child(self, serial=6000, exe="/usr/bin/chown", **kw):
        kw.setdefault("t", T0 + 0.16)
        t = kw.pop("t")
        return audit_event(serial, t, exe, kw.pop("names", ["/etc/sudoers"]), **kw)

    def test_a_stock_tool_without_a_session_inside_the_transaction_is_info(self):
        got = self.feed(self.child())
        self.assertEqual(self.high(got), [])
        self.assertEqual(len(self.info(got)), 1)

    def test_an_interactive_session_is_never_explained_by_a_package(self):
        for kw in ({"auid": "1000"}, {"ses": "4"}, {"auid": "1000", "ses": "4"}):
            self.s._audit_pending.clear()
            self.assertEqual(len(self.high(self.feed(self.child(**kw)))), 1, kw)

    def test_a_non_root_writer_is_not_explained(self):
        self.assertEqual(len(self.high(self.feed(self.child(uid="1000")))), 1)
        self.assertEqual(len(self.high(self.feed(self.child(serial=6001, uid="0", euid="1000")))), 1)

    def test_a_setuid_tool_run_by_a_user_is_not_explained(self):
        """uid real de un usuario con euid 0 (un binario setuid): no es el root de un script de mantenimiento."""
        self.assertEqual(len(self.high(self.feed(self.child(uid="1000", euid="0")))), 1)

    def test_a_tool_that_is_not_a_package_binary_is_not_explained(self):
        """Un binario en /tmp, o uno que ningún paquete trae: puede escribir en un segundo cualquiera."""
        self.assertEqual(len(self.high(self.feed(self.child(exe="/tmp/chown")))), 1)

    def test_a_tool_of_a_package_that_is_not_intact_is_not_explained(self):
        self.not_intact.add("coreutils")
        self.assertEqual(len(self.high(self.feed(self.child()))), 1)

    def test_a_tool_of_an_unsigned_package_is_not_explained(self):
        self.unsigned.add("coreutils")
        self.assertEqual(len(self.high(self.feed(self.child()))), 1)

    def test_outside_the_transaction_the_same_write_is_high(self):
        self.assertEqual(len(self.high(self.feed(self.child(t=T0 + 60)))), 1)
        self.assertEqual(len(self.high(self.feed(self.child(serial=6001, t=T0 - 600)))), 1)

    def test_the_second_after_the_last_line_of_the_transaction_still_counts_but_not_the_next(self):
        """dpkg.log va en segundos enteros: la línea de las 06:26:49 pudo escribirse en cualquier punto de ese segundo."""
        self.assertEqual(self.high(self.feed(self.child(t=1795328809.999))), [])
        self.assertEqual(len(self.high(self.feed(self.child(serial=6001, t=1795328810.0)))), 1)

    def test_a_failed_attempt_is_never_a_package_update(self):
        """Un fallo por permisos sigue contando como antes (alguien intentó escribir): no se explica."""
        self.assertEqual(len(self.high(self.feed(self.child(success="no")))), 1)


class TransactionWindowsTests(Base):
    """`dpkg.log` → cuándo está un paquete en transacción."""

    def covers(self, name, t):
        return self.p.in_transaction(name, t)

    def test_an_upgrade_runs_from_the_action_line_to_the_new_version_unpacked(self):
        self.use_log(SUDO_TX[:1] + ["2026-11-22 06:00:00 upgrade foo:amd64 1.0 2.0",
                                    "2026-11-22 06:00:00 status half-configured foo:amd64 1.0",
                                    "2026-11-22 06:00:01 status unpacked foo:amd64 1.0",     # la versión vieja: no cierra
                                    "2026-11-22 06:00:02 status half-installed foo:amd64 1.0",
                                    "2026-11-22 06:00:05 status unpacked foo:amd64 2.0"])
        t = self.p._to_epoch("2026-11-22 06:00:00")
        self.assertFalse(self.covers("foo", t - 1))
        self.assertTrue(self.covers("foo", t + 3.5))       # la versión vieja no cerró la ventana
        self.assertTrue(self.covers("foo", t + 5.999))     # el segundo de la línea final aún cuenta
        self.assertFalse(self.covers("foo", t + 6))

    def test_configure_runs_until_installed(self):
        self.use_log(["2026-11-22 06:00:10 configure foo:amd64 2.0 <none>",
                      "2026-11-22 06:00:10 status unpacked foo:amd64 2.0",
                      "2026-11-22 06:00:10 status half-configured foo:amd64 2.0",
                      "2026-11-22 06:00:30 status installed foo:amd64 2.0"])
        t = self.p._to_epoch("2026-11-22 06:00:10")
        self.assertTrue(self.covers("foo", t + 20.5))
        self.assertFalse(self.covers("foo", t + 21))

    def test_remove_and_purge_end_where_dpkg_says(self):
        self.use_log(["2026-11-22 06:00:00 remove foo:amd64 2.0 <none>",
                      "2026-11-22 06:00:00 status half-configured foo:amd64 2.0",
                      "2026-11-22 06:00:00 status half-installed foo:amd64 2.0",
                      "2026-11-22 06:00:01 status config-files foo:amd64 2.0",
                      "2026-11-22 06:10:00 purge foo:amd64 2.0 <none>",
                      "2026-11-22 06:10:02 status not-installed foo:amd64 <none>"])
        t = self.p._to_epoch("2026-11-22 06:00:00")
        self.assertTrue(self.covers("foo", t + 1.5))
        self.assertFalse(self.covers("foo", t + 60))
        self.assertTrue(self.covers("foo", t + 601))

    def test_a_transaction_without_a_closing_line_is_open_and_says_so(self):
        """Sin línea final no se sabe cuándo acaba: no hay tope de tiempo que la dé por buena, decide el que mira."""
        self.use_log(["2026-11-22 06:00:00 configure foo:amd64 2.0 <none>",
                      "2026-11-22 06:00:00 status half-configured foo:amd64 2.0"])
        t = self.p._to_epoch("2026-11-22 06:00:00")
        self.assertIsNone(self.p.transaction("foo", t - 1))
        self.assertIsNone(self.p.transaction("foo", t + 120)["t1"])
        self.assertIsNone(self.p.transaction("foo", t + 86400)["t1"])

    def test_a_closed_window_that_covers_wins_over_an_open_one(self):
        self.use_log(["2026-11-22 06:00:00 configure foo:amd64 2.0 <none>",
                      "2026-11-22 06:00:05 status installed foo:amd64 2.0",
                      "2026-11-22 06:00:30 configure foo:amd64 2.0 <none>"])  # otra, sin cerrar
        t = self.p._to_epoch("2026-11-22 06:00:00")
        self.assertIsNotNone(self.p.transaction("foo", t + 2)["t1"])
        self.assertIsNone(self.p.transaction("foo", t + 40)["t1"])

    def test_another_package_is_not_covered(self):
        self.use_log(SUDO_TX)
        t = self.p._to_epoch("2026-11-22 06:26:49")
        self.assertTrue(self.covers("sudo", t + 0.3))
        self.assertFalse(self.covers("openssh-server", t + 0.3))
        self.assertFalse(self.covers("sud", t + 0.3))

    def test_the_architecture_does_not_matter(self):
        self.use_log(SUDO_TX)
        t = self.p._to_epoch("2026-11-22 06:26:49")
        self.assertTrue(self.covers("sudo:amd64", t + 0.3))

    def test_two_transactions_of_the_same_package_are_two_windows(self):
        self.use_log(["2026-11-22 06:00:00 configure foo:amd64 1.0 <none>",
                      "2026-11-22 06:00:01 status installed foo:amd64 1.0",
                      "2026-11-22 07:00:00 configure foo:amd64 1.0 <none>",
                      "2026-11-22 07:00:01 status installed foo:amd64 1.0"])
        t = self.p._to_epoch("2026-11-22 06:00:00")
        self.assertTrue(self.covers("foo", t + 0.5))
        self.assertFalse(self.covers("foo", t + 1800))
        self.assertTrue(self.covers("foo", t + 3600.5))

    def test_a_stray_later_status_line_does_not_stretch_a_closed_window(self):
        self.use_log(["2026-11-22 06:00:00 configure foo:amd64 2.0 <none>",
                      "2026-11-22 06:00:01 status installed foo:amd64 2.0",
                      "2026-11-22 06:30:00 status installed foo:amd64 2.0"])
        t = self.p._to_epoch("2026-11-22 06:00:00")
        self.assertTrue(self.covers("foo", t + 1.5))
        self.assertFalse(self.covers("foo", t + 1200))

    def test_the_cut_of_the_tail_never_reads_half_a_line(self):
        text = "\n".join(["JUNK 2026-11-22 06:00:00 configure foo:amd64 1.0 <none>",
                          "2026-11-22 06:00:30 status installed foo:amd64 1.0"]) + "\n"
        path = self.use_log(["x"])
        with open(path, "w") as f:
            f.write(text)
        with mock.patch.object(self.p, "TAIL_BYTES", len(text) - len("JUNK ")):
            self.p.clear_cache()
            self.assertFalse(self.covers("foo", self.p._to_epoch("2026-11-22 06:00:00") + 5))

    def test_what_is_before_the_tail_of_a_huge_log_is_not_read(self):
        self.use_log(SUDO_TX + ["x" * 100] * 20)
        with mock.patch.object(self.p, "TAIL_BYTES", 1000):
            self.p.clear_cache()
            self.assertFalse(self.covers("sudo", self.p._to_epoch("2026-11-22 06:26:49") + 0.3))

    def test_garbage_lines_are_ignored(self):
        self.use_log(["", "basura", "2026-13-45 99:99:99 upgrade x 1 2", "2026-11-22 06:00:00 upgrade",
                      "2026-11-22 06:00:00 status", "\x00\x01"] + SUDO_TX)
        t = self.p._to_epoch("2026-11-22 06:26:49")
        self.assertTrue(self.covers("sudo", t + 0.3))

    def test_the_rotated_log_is_read_too(self):
        d = os.path.dirname(self.log)
        old, new = os.path.join(d, "dpkg.log.1"), os.path.join(d, "dpkg.log")
        with open(old, "w") as f:
            f.write("\n".join(SUDO_TX[:8]) + "\n")
        with open(new, "w") as f:
            f.write("\n".join(SUDO_TX[8:]) + "\n")
        self.p.DPKG_LOGS = (old, new)
        self.p.clear_cache()
        t = self.p._to_epoch("2026-11-22 06:26:49")
        self.assertTrue(self.covers("sudo", t + 0.3))

    def test_only_the_tail_of_a_huge_log_is_read(self):
        self.use_log(["x" * 100] * 10 + SUDO_TX)
        with mock.patch.object(self.p, "TAIL_BYTES", 1000):
            self.p.clear_cache()
            t = self.p._to_epoch("2026-11-22 06:26:49")
            self.assertTrue(self.covers("sudo", t + 0.3))

    def test_the_log_is_read_again_only_when_it_changes(self):
        path = self.use_log(SUDO_TX)
        opened = []
        real = open

        def counting(p, *a, **k):
            if p == path:
                opened.append(p)
            return real(p, *a, **k)
        with mock.patch("builtins.open", counting):
            for _ in range(5):
                self.p.in_transaction("sudo", 0)
        self.assertEqual(len(opened), 1)
        with open(path, "a") as f:
            f.write("2026-11-22 06:30:00 upgrade foo:amd64 1 2\n")
        with mock.patch("builtins.open", counting):
            self.p.in_transaction("sudo", 0)
        self.assertEqual(len(opened), 2)


def open_sudo_log():
    """El dpkg.log real de d13 sin las líneas que cierran las dos ventanas de sudo (unpack y configure)."""
    with open(DPKG_LOG, encoding="utf-8") as f:
        return [line for line in f.read().splitlines()
                if not ("sudo:amd64" in line and (("status unpacked" in line and "deb13u5" in line)
                                                  or "status installed" in line))]


class OpenTransactionTests(Base):
    """Si el paquete dueño sigue en transacción cuando se mira, el evento espera a su cierre (5 min como mucho); sin
    cierre, high. La ventana de un evento es solo la de SU paquete: lo que otro paquete esté haciendo no cuenta."""

    def close_log(self):
        self.use_log(open(DPKG_LOG, encoding="utf-8").read().splitlines())

    def test_events_of_an_open_transaction_wait_and_are_not_decided_early(self):
        self.use_log(open_sudo_log())
        got = self.feed(real_records())
        self.assertEqual(self.high(got), [])
        self.assertEqual(self.info(got), [])  # tampoco se da por buena antes de saber cómo acaba

    def test_once_the_transaction_closes_the_waiting_events_are_explained(self):
        self.use_log(open_sudo_log())
        self.feed(real_records())
        self.close_log()
        got = self.s.read_auditd_events()  # sin eventos nuevos: salen los que esperaban
        self.assertEqual(self.high(got), [])
        self.assertEqual(len(self.info(got)), 1)
        self.assertEqual(self.info(got)[0]["target"]["events"], 9)
        self.assertEqual(self.s.read_auditd_events(), [])  # y no vuelven

    def test_without_a_closing_line_after_five_minutes_they_are_high(self):
        self.use_log(open_sudo_log())
        self.feed(real_records())
        self.now = T0 + self.p.DEFER_MAX_S - 1
        self.assertEqual(self.s.read_auditd_events(), [])  # aún esperan
        self.now = T0 + 0.367 + self.p.DEFER_MAX_S + 1
        got = self.s.read_auditd_events()
        self.assertEqual(len(self.high(got)), 9)
        self.assertEqual(self.s.read_auditd_events(), [])  # una vez

    def test_an_event_already_older_than_the_wait_is_not_deferred(self):
        self.use_log(open_sudo_log())
        self.now = T0 + self.p.DEFER_MAX_S + 60
        self.assertEqual(len(self.high(self.feed(real_records()))), 9)

    def test_a_transaction_that_closes_before_the_event_does_not_cover_it(self):
        """La línea de cierre es de antes de lo que se escribió: ya no es de esa transacción."""
        self.use_log(open_sudo_log())
        self.feed(real_records())
        self.use_log([l.replace("06:26:49", "06:26:30") for l in open(DPKG_LOG).read().splitlines()])
        self.assertEqual(len(self.high(self.s.read_auditd_events())), 9)

    def test_waiting_events_survive_a_restart_of_arx(self):
        self.use_log(open_sudo_log())
        self.feed(real_records())
        self.p.clear_cache()  # un reinicio: la memoria se pierde, lo que esperaba está en disco
        self.close_log()
        got = self.s.read_auditd_events()
        self.assertEqual((len(self.high(got)), len(self.info(got))), (0, 1))

    def test_the_waiting_list_is_bounded_and_the_overflow_is_high_not_lost(self):
        self.use_log(open_sudo_log())
        evs = [audit_event(9300 + i, T0 + 0.30, "/usr/bin/dpkg", ["/etc/sudoers.d/README"]) for i in range(8)]
        with mock.patch.object(self.p, "MAX_DEFERRED", 5):
            got = self.feed(*evs)
        self.assertEqual(len(self.high(got)), 3)
        self.close_log()
        self.assertEqual(len(self.info(self.s.read_auditd_events())), 1)

    def test_another_package_in_transaction_does_not_cover_the_event(self):
        """sudo está abierto, pero /etc/pam.d/sshd es de openssh-server, que no está en transacción: high ya."""
        self.use_log(open_sudo_log())
        ev = audit_event(9400, T0 + 0.5, "/usr/bin/dpkg", ["/etc/pam.d/sshd"], pid="424671")
        self.assertEqual(len(self.high(self.feed(ev))), 1)

    def test_the_window_of_a_package_is_not_the_union_of_all_that_are_open(self):
        """Con openssh-server abierto, un fichero de sudo escrito fuera de las ventanas de sudo sigue siendo high."""
        self.use_log(["2026-11-22 06:26:30 configure openssh-server:amd64 1:10.0 <none>",
                      "2026-11-22 06:26:30 status half-configured openssh-server:amd64 1:10.0"] + SUDO_TX)
        ev = audit_event(9401, T0 + 20, "/usr/bin/chown", ["/etc/sudoers"])  # 06:27:09: sudo ya cerró
        self.assertEqual(len(self.high(self.feed(ev))), 1)

    def test_an_event_with_files_of_two_packages_waits_if_either_is_still_open(self):
        self.owners["/etc/pam.d/sshd"] = "openssh-server"
        self.use_log(["2026-11-22 06:26:49 configure sudo:amd64 1.9.16p2-3+deb13u5 <none>",
                      "2026-11-22 06:26:49 status half-configured sudo:amd64 1.9.16p2-3+deb13u5",
                      "2026-11-22 06:26:49 configure openssh-server:amd64 1:10.0 <none>",
                      "2026-11-22 06:26:49 status installed openssh-server:amd64 1:10.0"])
        for names in (["/etc/sudoers", "/etc/pam.d/sshd"], ["/etc/pam.d/sshd", "/etc/sudoers"]):
            self.s._audit_pending.clear()
            ev = audit_event(9500, T0 + 0.5, "/usr/bin/dpkg", names, syscall="82")
            got = self.feed(ev)
            self.assertEqual((self.high(got), self.info(got)), ([], []), names)

    def test_a_damaged_waiting_list_on_disk_is_ignored_not_trusted(self):
        import json
        path = self.p._deferred_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps([5, {"at": "x", "records": []}, {"at": 1.0, "records": "no"},
                                    {"at": 1.0, "records": [1, 2]}, {"at": 1.0, "records": ["type=SYSCALL msg=audit(1.000:1): x"],
                                                                       "inodes": ["mal", [1, 2, 3], ["a", "b", "c"]]}]))
        self.p.clear_cache()
        waiting = self.p.take_deferred()
        self.assertEqual(waiting, [["type=SYSCALL msg=audit(1.000:1): x"]])
        self.assertEqual(self.s.read_auditd_events(), [])  # y un evento que no se entiende no hace daño

    def test_the_wait_is_five_minutes_and_has_room_for_a_whole_sweep(self):
        self.assertEqual(self.p.DEFER_MAX_S, 300)
        self.assertGreaterEqual(self.p.MAX_DEFERRED, self.s.MAX_EVENTS)

    def test_the_unexplained_ones_are_not_held_back_by_the_ones_that_wait(self):
        self.use_log(open_sudo_log())
        bad = audit_event(9402, T0 + 0.2, "/usr/bin/chmod", ["/etc/passwd"])
        got = self.feed(real_records(), bad)
        self.assertEqual(len(self.high(got)), 1)
        self.assertIn("/etc/passwd", self.high(got)[0]["detail"])

    def test_a_waiting_event_that_stops_being_attributable_is_high(self):
        """Mientras esperaba, el paquete dejó de ser de un repositorio firmado."""
        self.use_log(open_sudo_log())
        self.feed(real_records())
        self.close_log()
        self.unsigned.add("sudo")
        got = self.s.read_auditd_events()
        self.assertEqual((len(self.high(got)), len(self.info(got))), (9, 0))

    def test_the_wait_is_counted_from_the_event_not_from_each_look(self):
        self.use_log(open_sudo_log())
        self.feed(real_records())
        for step in (60, 120, 200, 280):
            self.now = T0 + step
            self.assertEqual(self.s.read_auditd_events(), [], step)  # mirar muchas veces no la alarga
        self.now = T0 + 0.367 + self.p.DEFER_MAX_S + 1
        self.assertEqual(len(self.high(self.s.read_auditd_events())), 9)


class FilesOfTheEventTests(Base):
    """Qué rutas toca un evento, y cuáles se pueden atribuir."""

    def test_dpkg_temporary_names_belong_to_the_file_they_become(self):
        for suffix in (".dpkg-new", ".dpkg-tmp", ".dpkg-old", ".dpkg-dist", ".dpkg-bak"):
            self.s._audit_pending.clear()
            ev = audit_event(7000, T0 + 0.3, "/usr/bin/dpkg", ["/etc/sudoers.d/README" + suffix],
                             pid="424671", ppid="424652")
            self.assertEqual(self.high(self.feed(ev)), [], suffix)

    def test_a_temporary_name_of_a_foreign_file_does_not_become_the_package_one(self):
        ev = audit_event(7001, T0 + 0.3, "/usr/bin/dpkg", ["/etc/sudoers.d/evil.dpkg-new"], pid="424671")
        self.assertEqual(len(self.high(self.feed(ev))), 1)

    def test_a_relative_name_is_joined_to_the_working_directory(self):
        ev = audit_event(7002, T0 + 0.3, "/usr/bin/chmod", ["sudoers"], cwd="/etc")
        self.assertEqual(self.high(self.feed(ev)), [])
        ev = audit_event(7003, T0 + 0.3, "/usr/bin/chmod", ["sudoers"], cwd="/tmp")
        self.assertEqual(len(self.high(self.feed(ev))), 1)

    def test_parent_directories_do_not_count_as_files_of_the_event(self):
        ev = audit_event(7004, T0 + 0.3, "/usr/bin/dpkg", ["/etc/sudoers.d/", "/etc/sudoers.d/README.dpkg-new"],
                         nametypes={"/etc/sudoers.d/": "PARENT", "/etc/sudoers.d/README.dpkg-new": "CREATE"},
                         pid="424671")
        self.assertEqual(self.high(self.feed(ev)), [])

    def test_an_event_that_only_touches_a_parent_directory_is_not_attributable(self):
        ev = audit_event(7005, T0 + 0.3, "/usr/bin/dpkg", ["/etc/sudoers.d/"],
                         nametypes={"/etc/sudoers.d/": "PARENT"}, pid="424671")
        self.assertEqual(len(self.high(self.feed(ev))), 1)

    def test_a_write_by_descriptor_is_resolved_with_the_inode_the_same_process_created(self):
        """fchown/fchmod sobre el fd recién creado: el registro no trae nombre (`name=(null)`), solo el inodo."""
        made = audit_event(7006, T0 + 0.30, "/usr/bin/dpkg", ["/etc/sudoers.d/", "/etc/sudoers.d/README.dpkg-new"],
                           syscall="257", pid="424671", ppid="424652",
                           nametypes={"/etc/sudoers.d/": "PARENT", "/etc/sudoers.d/README.dpkg-new": "CREATE"})
        fd = audit_event(7007, T0 + 0.31, "/usr/bin/dpkg", ["(null)"], syscall="93", pid="424671", ppid="424652")
        made = [l.replace("inode=801", "inode=837") for l in made]
        fd = [l.replace("inode=800", "inode=837") for l in fd]
        got = self.feed(made, fd)
        self.assertEqual(self.high(got), [])

    def test_a_write_by_descriptor_with_an_unknown_inode_stays_high(self):
        fd = audit_event(7008, T0 + 0.31, "/usr/bin/dpkg", ["(null)"], syscall="93", pid="424671")
        self.assertEqual(len(self.high(self.feed(fd))), 1)

    def test_an_inode_resolved_across_sweeps_is_the_same_file(self):
        made = audit_event(7009, T0 + 0.30, "/usr/bin/dpkg", ["/etc/sudoers.d/", "/etc/sudoers.d/README.dpkg-new"],
                           syscall="257", pid="424671",
                           nametypes={"/etc/sudoers.d/": "PARENT", "/etc/sudoers.d/README.dpkg-new": "CREATE"})
        fd = audit_event(7010, T0 + 0.31, "/usr/bin/dpkg", ["(null)"], syscall="93", pid="424671")
        made = [l.replace("inode=801", "inode=837") for l in made]
        fd = [l.replace("inode=800", "inode=837") for l in fd]
        self.feed(made)
        self.assertEqual(self.high(self.feed(fd)), [])

    LONG_TX = ["2026-11-22 06:26:49 configure sudo:amd64 1.9.16p2-3+deb13u5 <none>",
               "2026-11-22 06:28:49 status installed sudo:amd64 1.9.16p2-3+deb13u5"]  # dos minutos: sobra ventana

    @staticmethod
    def as_inode(records, inode="837"):
        return [l.replace("inode=800", f"inode={inode}").replace("inode=801", f"inode={inode}") for l in records]

    def test_an_inode_named_long_ago_is_not_the_file_a_descriptor_writes_now(self):
        """Los inodos se reutilizan: el nombre solo vale para lo que se escribe poco después."""
        self.use_log(self.LONG_TX)
        made = audit_event(7013, T0 + 0.30, "/usr/bin/dpkg", ["/etc/sudoers.d/README.dpkg-new"], syscall="257")
        soon = audit_event(7014, T0 + 59, "/usr/bin/dpkg", ["(null)"], syscall="93")
        late = audit_event(7020, T0 + 62, "/usr/bin/dpkg", ["(null)"], syscall="93")
        got = self.feed(self.as_inode(made), self.as_inode(soon), self.as_inode(late))
        self.assertEqual(len(self.high(got)), 1)  # el de los 59 s se resuelve; el de los 62 s no

    def test_a_name_that_only_appears_later_does_not_name_an_earlier_descriptor_write(self):
        self.use_log(self.LONG_TX)
        fd = audit_event(7021, T0 + 0.30, "/usr/bin/dpkg", ["(null)"], syscall="93")
        made = audit_event(7022, T0 + 0.40, "/usr/bin/dpkg", ["/etc/sudoers.d/README.dpkg-new"], syscall="257")
        got = self.feed(self.as_inode(fd), self.as_inode(made))
        self.assertEqual(len(self.high(got)), 1)

    def test_an_inode_that_changed_name_resolves_to_the_name_it_had_at_that_moment(self):
        """837 fue README.dpkg-new y, borrado, lo reutilizó otro fichero: el fd de después es del segundo."""
        self.use_log(self.LONG_TX)
        first = audit_event(7015, T0 + 0.30, "/usr/bin/dpkg", ["/etc/sudoers.d/README.dpkg-new"], syscall="257")
        other = audit_event(7016, T0 + 0.40, "/usr/bin/dpkg", ["/etc/sudoers.d/evil"], syscall="257")
        fd = audit_event(7017, T0 + 0.45, "/usr/bin/dpkg", ["(null)"], syscall="93")
        got = self.feed(self.as_inode(first), self.as_inode(other), self.as_inode(fd))
        self.assertEqual(len(self.high(got)), 2)  # lo de /etc/sudoers.d/evil, y su fd

    def test_the_inode_of_a_parent_directory_is_not_the_name_of_a_descriptor(self):
        self.owners["/etc/sudoers.d"] = "sudo"
        parent = audit_event(7023, T0 + 0.30, "/usr/bin/dpkg", ["/etc/sudoers.d/"], syscall="82",
                             nametypes={"/etc/sudoers.d/": "PARENT"})
        fd = audit_event(7024, T0 + 0.35, "/usr/bin/dpkg", ["(null)"], syscall="93")
        got = self.feed(self.as_inode(parent), self.as_inode(fd))
        self.assertEqual(len(self.high(got)), 2)

    def test_the_name_given_before_the_cut_of_the_batch_still_resolves_the_descriptor(self):
        """El tope de eventos por barrido deja fuera los primeros: sus inodos se recuerdan igual."""
        made = audit_event(7018, T0 + 0.30, "/usr/bin/dpkg", ["/etc/sudoers.d/README.dpkg-new"], syscall="257")
        made = [l.replace("inode=800", "inode=837") for l in made]
        filler = [audit_event(7100 + i, T0 + 0.31, "/usr/bin/dpkg", ["/etc/sudoers.d/README"], syscall="90")
                  for i in range(self.s.MAX_EVENTS)]
        fd = [l.replace("inode=800", "inode=837")
              for l in audit_event(7019, T0 + 0.32, "/usr/bin/dpkg", ["(null)"], syscall="93")]
        got = self.feed(made, *filler, fd)
        self.assertEqual(self.high(got), [])

    def test_an_inode_of_a_different_device_is_not_the_same_file(self):
        made = audit_event(7011, T0 + 0.30, "/usr/bin/dpkg", ["/etc/sudoers.d/README.dpkg-new"], syscall="257")
        fd = audit_event(7012, T0 + 0.31, "/usr/bin/dpkg", ["(null)"], syscall="93")
        made = [l.replace("inode=800", "inode=837") for l in made]
        fd = [l.replace("inode=800", "inode=837").replace("dev=08:01", "dev=09:09") for l in fd]
        self.feed(made)
        self.assertEqual(len(self.high(self.feed(fd))), 1)

    def test_the_inode_memory_is_bounded(self):
        for i in range(self.p.INODES_MAX + 50):
            ev = audit_event(8000 + i, T0 + 0.3, "/usr/bin/dpkg", ["/etc/sudoers.d/README"], syscall="257")
            ev = [l.replace("inode=800", f"inode={10000 + i}") for l in ev]
            self.p.remember([ev])
        self.assertLessEqual(len(self.p._inodes), self.p.INODES_MAX)


class MixedAndShapeTests(Base):

    def test_only_the_unexplained_events_stay_high(self):
        bad = audit_event(9000, T0 + 0.2, "/usr/bin/chmod", ["/etc/passwd"], pid="1", ppid="1")
        got = self.feed(real_records(), bad)
        self.assertEqual(len(self.high(got)), 1)
        self.assertIn("/etc/passwd", self.high(got)[0]["detail"])
        self.assertEqual(len(self.info(got)), 1)

    def test_the_high_findings_keep_their_shape(self):
        ev = audit_event(9001, T0 + 60, "/usr/bin/chown", ["/etc/sudoers"])
        f = self.high(self.feed(ev))[0]
        self.assertEqual((f["kind"], f["sev"]), ("auditd", "high"))
        self.assertTrue(f["fp_key"].startswith("auditd|auditd · identidad: "))

    def test_a_failure_while_checking_never_hides_an_event(self):
        for name in ("owner", "intact", "signed_origin"):
            self.s._audit_pending.clear()
            target = self.pkgdb if name == "owner" else self.prov
            with mock.patch.object(target, name, side_effect=RuntimeError("dpkg no contesta")):
                self.p.clear_cache()
                self.assertEqual(len(self.high(self.feed(real_records()))), 9, name)

    def test_an_interactive_upgrade_is_explained_for_dpkg_itself_but_not_for_its_children(self):
        """`sudo apt upgrade` desde una sesión: el dpkg (verificado, en transacción) se explica; lo que escribe un hijo
        suyo con el auid de esa sesión no (no se distingue de un administrador tecleando en la misma sesión)."""
        dpkg = audit_event(9100, T0 + 0.3, "/usr/bin/dpkg", ["/etc/sudoers.d/README.dpkg-new"], auid="1000", ses="4",
                           pid="424671", ppid="424652")
        child = audit_event(9101, T0 + 0.36, "/usr/bin/chown", ["/etc/sudoers"], auid="1000", ses="4")
        got = self.feed(dpkg, child)
        self.assertEqual(len(self.info(got)), 1)
        self.assertEqual(len(self.high(got)), 1)
        self.assertIn("chown", self.high(got)[0]["detail"])

    def test_the_info_is_observed_and_logged_and_never_acted_on(self):
        from arx.modules import response
        f = self.info(self.feed(real_records()))[0]
        plan = response.classify(f)
        self.assertEqual(plan["tier"], 0)
        self.assertEqual(response.fingerprint(f), response.fingerprint(f))

    def test_a_package_of_another_architecture_is_the_same_package(self):
        self.owners["/etc/sudoers"] = self.owners["/etc/sudoers.d/README"] = "sudo:amd64"
        got = self.info(self.feed(real_records()))
        self.assertEqual([f["target"]["package"] for f in got], ["sudo"])

    def test_a_failure_inside_the_attribution_is_never_an_explanation(self):
        with mock.patch.object(self.p, "_judge", side_effect=RuntimeError("x")):
            self.assertIsNone(self.p.explain(real_records()[:5]))
            self.assertEqual(self.p.judge(real_records()[:5]), ("unexplained", None))

    def test_each_check_is_made_once_per_sweep_however_many_events_there_are(self):
        owner_calls, intact_calls = [], []
        evs = [audit_event(9200 + i, T0 + 0.30 + i / 100, exe, ["/etc/sudoers"])
               for i in range(3) for exe in ("/usr/bin/chown", "/usr/bin/chmod")]

        def owner(path):
            owner_calls.append(path)
            return self.owners.get(path)

        def intact(path, pkg):
            intact_calls.append(path)
            return True
        with mock.patch.object(self.pkgdb, "owner", owner), mock.patch.object(self.prov, "intact", intact):
            got = self.feed(*evs)
        self.assertEqual(self.high(got), [])
        self.assertEqual(sorted(owner_calls), sorted(set(owner_calls)), owner_calls)
        self.assertLessEqual(intact_calls.count("/usr/bin/dpkg"), 2, intact_calls)

    def test_the_package_checks_do_not_run_for_events_that_are_not_identity_ones(self):
        calls = []
        with mock.patch.object(self.pkgdb, "owner", side_effect=lambda p: calls.append(p)):
            self.feed(audit_event(9002, T0, "/usr/bin/cat", ["/root/.aws/credentials"], key="arx_canary"))
        self.assertEqual(calls, [])

    def test_the_checks_are_made_once_per_path_and_not_once_per_event(self):
        calls = []

        def owner(path):
            calls.append(path)
            return self.owners.get(path)
        with mock.patch.object(self.pkgdb, "owner", owner):
            self.feed(real_records())
        self.assertLessEqual(len(calls), 12)

    def test_guard_package_wrote_uses_the_same_criterion(self):
        """Lo que adopta `integrity.drift` y lo que rebaja el sensor se deciden con las mismas comprobaciones."""
        from arx.modules import guard
        self.assertTrue(guard._package_wrote("/etc/sudoers"))
        self.unsigned.add("sudo")
        self.assertFalse(guard._package_wrote("/etc/sudoers"))
        self.unsigned.clear()
        self.not_intact.add("dpkg")
        self.assertFalse(guard._package_wrote("/etc/sudoers"))
        self.not_intact.clear()
        self.unsigned.add("dpkg")
        self.assertFalse(guard._package_wrote("/etc/sudoers"))


if __name__ == "__main__":
    unittest.main()
