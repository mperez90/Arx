"""FP de auditd en `sudo apt upgrade` manual (d13 real, 2026-11-23 15:26:49): el chown y el chmod del postinst de sudo llevan
la sesión de login del administrador (auid=0 ses=432), y la regla «hijos sin sesión» los dejaba en high en cada actualización
a mano. Un hijo cuenta como del paquete si se demuestra su ascendencia: hijo → script de mantenimiento de P → dpkg.

La prueba sale de lo que el vigilante de procesos ve en tiempo real (`procring`, un anillo acotado solo de los `exec` cuyo
padre es dpkg y es un script de mantenimiento, y de lo que estos lancen). Sin la prueba, lo de siempre: sin sesión, ventana
y herramienta; con sesión, high.

Corre con: python -m unittest discover -s tests
"""
import os

os.environ["ARX_LANG"] = "es"

import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import test_fp_pkg_audit as base  # noqa: E402

DATA = base.DATA
SSH_AUDIT = os.path.join(DATA, "d13-sudo-ssh-audit.log")
SSH_DPKG_LOG = os.path.join(DATA, "d13-sudo-ssh-dpkg.log")
T0 = 1795447609.385        # el primer evento real de la sesión de ssh
NOW = 1795447700.0
DPKG_PID, SCRIPT_PID, CHOWN_PID, CHMOD_PID = 494306, 494307, 494308, 494309


def ssh_records():
    with open(SSH_AUDIT, encoding="utf-8") as f:
        return f.read().splitlines()


class World:
    """Los procesos del host, tal como /proc los diría: (ppid, nacimiento), ejecutable, argv y paquete del script."""

    def __init__(self):
        self.procs = {}

    def add(self, pid, ppid, exe, argv=(), start=None, env_pkg=None):
        self.procs[pid] = {"ppid": ppid, "start": start or pid * 10, "exe": exe, "argv": list(argv), "env": env_pkg}

    def install(self, test):
        from arx.modules import procring
        for name, value in (("_stat", lambda pid: (self.procs[pid]["ppid"], self.procs[pid]["start"])
                             if pid in self.procs else None),
                            ("_exe", lambda pid: self.procs.get(pid, {}).get("exe")),
                            ("_argv", lambda pid: self.procs.get(pid, {}).get("argv", [])),
                            ("_env_package", lambda pid: self.procs.get(pid, {}).get("env"))):
            patch = mock.patch.object(procring, name, value)
            patch.start()
            test.addCleanup(patch.stop)


class AncestryBase(base.Base):
    def setUp(self):
        super().setUp()
        from arx.modules import procring
        self.ring = procring
        procring.clear()
        self.addCleanup(procring.clear)
        self.now = NOW
        self.use_log(open(SSH_DPKG_LOG, encoding="utf-8").read().splitlines())
        self.world = World()
        self.world.install(self)
        self.owners["/etc/sudoers"] = "sudo"
        self.t_script = T0 + 0.215       # cuando dpkg lanza el postinst

    def dpkg_runs_the_postinst(self, pkg="sudo", script=None):
        """Lo que el vigilante vio: dpkg (494306) lanzó el postinst (494307), que luego lanzó chown y chmod."""
        self.world.add(DPKG_PID, 494247, "/usr/bin/dpkg", ["/usr/bin/dpkg", "--configure", "--pending"])
        self.world.add(SCRIPT_PID, DPKG_PID, "/usr/bin/dash",
                       ["/bin/sh", script or f"/var/lib/dpkg/info/{pkg}.postinst", "configure", "1.9.16p2-3+deb13u5"],
                       env_pkg="sudo")
        self.ring.observe_exec(SCRIPT_PID, now=self.t_script)

    def feed_ssh(self):
        return self.feed(ssh_records())

    def children(self, got):
        return [e for e in self.high(got) if "chown" in e["detail"] or "chmod" in e["detail"]]


class TheSessionCaseOfD13(AncestryBase):

    def test_without_the_proof_the_children_with_a_session_stay_high(self):
        """El estado de partida (lo que vio arx-98): lo de dpkg es info, el chown y el chmod high."""
        got = self.feed_ssh()
        self.assertEqual(len(self.children(got)), 2)
        self.assertEqual(len(self.high(got)), 2)
        self.assertEqual(len(self.info(got)), 1)

    def test_with_the_proof_of_their_ancestry_the_real_records_open_no_high(self):
        self.dpkg_runs_the_postinst()
        got = self.feed_ssh()
        self.assertEqual(self.high(got), [], [e["detail"] for e in self.high(got)])
        self.assertEqual(len(self.info(got)), 1)
        f = self.info(got)[0]
        self.assertEqual(f["target"]["events"], 9)
        self.assertEqual(f["target"]["writers"], ["dpkg", "script"])

    def test_the_proof_is_the_script_of_that_package_launched_by_dpkg(self):
        self.dpkg_runs_the_postinst()
        got = self.ring.ancestry(CHOWN_PID, SCRIPT_PID, T0 + 0.224)
        self.assertEqual(got["package"], "sudo")
        self.assertEqual(got["script"], "/var/lib/dpkg/info/sudo.postinst")

    def test_a_script_of_another_package_does_not_vouch_for_the_files_of_sudo(self):
        self.dpkg_runs_the_postinst(pkg="openssh-server")
        self.assertEqual(len(self.children(self.feed_ssh())), 2)

    def test_the_same_script_run_by_a_person_is_not_a_maintainer_script(self):
        """`sh /var/lib/dpkg/info/sudo.postinst` desde una shell: el padre no es dpkg."""
        self.world.add(DPKG_PID, 494247, "/usr/bin/bash", ["bash"])
        self.world.add(SCRIPT_PID, DPKG_PID, "/usr/bin/dash", ["/bin/sh", "/var/lib/dpkg/info/sudo.postinst", "configure"])
        self.ring.observe_exec(SCRIPT_PID, now=self.t_script)
        self.assertEqual(len(self.children(self.feed_ssh())), 2)

    def test_a_script_that_is_not_in_the_dpkg_directories_is_not_a_maintainer_script(self):
        for path in ("/tmp/sudo.postinst", "/var/lib/dpkg/info/sudo.list", "/var/lib/dpkg/info/../../../tmp/x.postinst",
                     "/var/lib/dpkg/info/sudo.postinst.evil", "/var/lib/dpkg/tmp.ci/other"):
            self.ring.clear()
            self.s._audit_pending.clear()
            self.dpkg_runs_the_postinst(script=path)
            self.assertEqual(len(self.children(self.feed_ssh())), 2, path)

    def test_a_pid_that_was_the_script_but_has_already_exited_is_not_vouched(self):
        """El número lo reutilizó otro proceso: el script murió antes de lo que se escribió."""
        self.dpkg_runs_the_postinst()
        self.ring.observe_exit(SCRIPT_PID, now=T0 - 30)
        self.assertEqual(len(self.children(self.feed_ssh())), 2)

    def test_what_was_written_before_the_script_started_is_not_its_work(self):
        self.t_script = T0 + 60
        self.dpkg_runs_the_postinst()
        self.assertEqual(len(self.children(self.feed_ssh())), 2)

    def test_a_dpkg_that_is_not_the_verified_one_vouches_for_nothing(self):
        self.dpkg_runs_the_postinst()
        self.not_intact.add("dpkg")
        self.assertEqual(len(self.high(self.feed_ssh())), 11 - 2)  # los de dpkg y los hijos, todos high (menos los ENOENT)

    def test_the_tool_still_has_to_be_a_signed_unaltered_binary(self):
        self.dpkg_runs_the_postinst()
        self.unsigned.add("coreutils")
        self.assertEqual(len(self.children(self.feed_ssh())), 2)

    def test_the_writer_still_has_to_be_root(self):
        self.dpkg_runs_the_postinst()
        recs = [l.replace("uid=0 gid=0 euid=0", "uid=1000 gid=1000 euid=1000") if 'exe="/usr/bin/chown"' in l else l
                for l in ssh_records()]
        got = self.feed(recs)
        self.assertEqual(len(self.children(got)), 1)

    def test_a_writer_that_is_not_a_child_of_the_script_is_not_vouched(self):
        """Mismo instante, mismo fichero, pero su padre es otro proceso: no hay ascendencia."""
        self.dpkg_runs_the_postinst()
        recs = [l.replace("ppid=494307", "ppid=494999") for l in ssh_records()]
        self.assertEqual(len(self.children(self.feed(recs))), 2)

    def test_a_package_file_outside_its_own_scripts_package_is_not_vouched(self):
        self.owners["/etc/sudoers"] = "openssh-server"  # el fichero es de otro paquete
        self.dpkg_runs_the_postinst()
        self.assertEqual(len(self.children(self.feed_ssh())), 2)

    def test_the_proof_does_not_replace_the_transaction_window(self):
        """Ascendencia demostrada, pero el paquete no estaba en transacción cuando se escribió."""
        self.use_log([l for l in open(SSH_DPKG_LOG, encoding="utf-8").read().splitlines() if "sudo" not in l])
        self.dpkg_runs_the_postinst()
        self.assertEqual(len(self.children(self.feed_ssh())), 2)

    def test_with_an_open_transaction_the_proven_children_wait_like_the_rest(self):
        lines = [l for l in open(SSH_DPKG_LOG, encoding="utf-8").read().splitlines()
                 if not ("status installed sudo" in l)]
        lines = [l for l in lines if not ("status unpacked sudo" in l and "deb13u5" in l)]
        self.use_log(lines)
        self.dpkg_runs_the_postinst()
        got = self.feed_ssh()
        self.assertEqual((self.high(got), self.info(got)), ([], []))

    def test_the_session_does_not_matter_and_neither_does_its_absence(self):
        self.dpkg_runs_the_postinst()
        recs = [l.replace("auid=0", "auid=4294967295").replace("ses=432", "ses=4294967295") for l in ssh_records()]
        self.assertEqual(self.high(self.feed(recs)), [])


class DescendantsAndTreeShape(AncestryBase):

    def test_a_script_executed_directly_has_its_own_path_as_argv0(self):
        self.world.add(DPKG_PID, 494247, "/usr/bin/dpkg", ["dpkg"])
        self.world.add(SCRIPT_PID, DPKG_PID, "/var/lib/dpkg/info/sudo.postinst",
                       ["/var/lib/dpkg/info/sudo.postinst", "configure"])
        self.ring.observe_exec(SCRIPT_PID, now=self.t_script)
        self.assertEqual(self.ring.ancestry(CHOWN_PID, SCRIPT_PID, T0 + 0.3)["package"], "sudo")

    def test_what_a_script_that_already_exited_launches_is_not_its_child(self):
        """El número del script es de otro proceso desde que salió: lo que cuelga de él ahora no es del script."""
        self.dpkg_runs_the_postinst()
        self.ring.observe_exit(SCRIPT_PID, now=self.t_script + 1)
        self.world.add(900001, SCRIPT_PID, "/usr/bin/cat", ["cat"])
        self.ring.observe_exec(900001, now=self.t_script + 5)
        self.assertEqual(len(self.ring._ring), 1)

    def test_the_first_exit_is_the_exit(self):
        self.dpkg_runs_the_postinst()
        self.ring.observe_exit(SCRIPT_PID, now=self.t_script + 1)
        self.ring.observe_exit(SCRIPT_PID, now=self.t_script + 500)
        self.assertIsNone(self.ring.ancestry(CHOWN_PID, SCRIPT_PID, self.t_script + 100))

    def test_when_a_pid_number_is_reused_the_latest_process_is_the_one_that_counts(self):
        self.dpkg_runs_the_postinst(pkg="openssh-server")  # y su salida se perdió (el kernel tira eventos si hay avalancha)
        self.world.add(SCRIPT_PID, DPKG_PID, "/usr/bin/dash", ["/bin/sh", "/var/lib/dpkg/info/sudo.postinst"],
                       start=999999, env_pkg="sudo")
        self.ring.observe_exec(SCRIPT_PID, now=self.t_script + 10)
        self.assertEqual(self.ring.ancestry(CHOWN_PID, SCRIPT_PID, self.t_script + 11)["package"], "sudo")

    def test_a_writer_the_ring_saw_with_another_parent_is_not_vouched(self):
        self.dpkg_runs_the_postinst()
        self.world.add(CHOWN_PID, SCRIPT_PID, "/usr/bin/chown", ["chown"])
        self.ring.observe_exec(CHOWN_PID, now=self.t_script + 0.01)
        self.world.add(494400, DPKG_PID, "/usr/bin/dash", ["/bin/sh", "/var/lib/dpkg/info/sudo.postrm"], env_pkg="sudo")
        self.ring.observe_exec(494400, now=self.t_script)  # otro script, también vivo
        self.assertIsNotNone(self.ring.ancestry(CHOWN_PID, SCRIPT_PID, T0 + 0.3))
        self.assertIsNone(self.ring.ancestry(CHOWN_PID, 494400, T0 + 0.3))  # el chown que vimos era hijo del primero

    def test_what_is_forgotten_leaves_no_trace_in_the_index(self):
        self.dpkg_runs_the_postinst()
        self.world.add(820001, DPKG_PID, "/usr/bin/dash", ["/bin/sh", "/var/lib/dpkg/info/foo.postinst"])
        self.ring.observe_exec(820001, now=self.t_script + self.ring.TTL_S + 1)
        self.assertNotIn(SCRIPT_PID, self.ring._by_pid)

    def test_a_pid_that_is_not_a_number_is_not_vouched_and_does_not_fail(self):
        from arx.modules import pkgtx
        self.assertIsNone(pkgtx._lineage({"pid": "?", "ppid": "x"}, 1.0))
        self.assertIsNone(pkgtx._lineage({}, 1.0))

    def test_a_grandchild_is_vouched_if_its_helper_was_seen(self):
        """postinst → helper → chown: el helper es descendiente del script y se recuerda."""
        self.dpkg_runs_the_postinst()
        self.world.add(500001, SCRIPT_PID, "/usr/bin/dpkg-maintscript-helper", ["dpkg-maintscript-helper", "x"])
        self.ring.observe_exec(500001, now=self.t_script + 0.01)
        got = self.ring.ancestry(500002, 500001, T0 + 0.3)
        self.assertEqual(got["package"], "sudo")

    def test_a_grandchild_whose_helper_was_not_seen_is_not_vouched(self):
        self.dpkg_runs_the_postinst()
        self.assertIsNone(self.ring.ancestry(500002, 500001, T0 + 0.3))

    def test_children_of_something_that_is_not_in_the_tree_are_never_recorded(self):
        self.dpkg_runs_the_postinst()
        self.world.add(600001, 1, "/usr/bin/bash", ["bash"])
        self.world.add(600002, 600001, "/usr/bin/cat", ["cat"])
        self.ring.observe_exec(600001, now=self.t_script)
        self.ring.observe_exec(600002, now=self.t_script)
        self.assertIsNone(self.ring.ancestry(600003, 600002, T0 + 0.3))
        self.assertEqual(len(self.ring._ring), 1)  # solo el script

    def test_the_other_children_of_dpkg_are_not_recorded(self):
        """`dpkg-deb`, `tar`, los hijos de dpkg que no son un script de mantenimiento: ni se guardan."""
        self.world.add(DPKG_PID, 494247, "/usr/bin/dpkg", ["dpkg"])
        self.world.add(700001, DPKG_PID, "/usr/bin/tar", ["tar", "-x"])
        self.ring.observe_exec(700001, now=self.t_script)
        self.assertEqual(self.ring._ring, {})

    def test_a_tmp_ci_script_takes_its_package_from_dpkg_environment(self):
        self.world.add(DPKG_PID, 494247, "/usr/bin/dpkg", ["dpkg"])
        self.world.add(SCRIPT_PID, DPKG_PID, "/usr/bin/dash", ["/bin/sh", "/var/lib/dpkg/tmp.ci/preinst", "upgrade"],
                       env_pkg="sudo")
        self.ring.observe_exec(SCRIPT_PID, now=self.t_script)
        self.assertEqual(self.ring.ancestry(CHOWN_PID, SCRIPT_PID, T0 + 0.3)["package"], "sudo")

    def test_a_tmp_ci_script_without_a_package_is_not_recorded(self):
        self.world.add(DPKG_PID, 494247, "/usr/bin/dpkg", ["dpkg"])
        self.world.add(SCRIPT_PID, DPKG_PID, "/usr/bin/dash", ["/bin/sh", "/var/lib/dpkg/tmp.ci/preinst"], env_pkg=None)
        self.ring.observe_exec(SCRIPT_PID, now=self.t_script)
        self.assertEqual(self.ring._ring, {})

    def test_the_architecture_qualifier_is_not_part_of_the_package(self):
        self.dpkg_runs_the_postinst(script="/var/lib/dpkg/info/sudo:amd64.postinst")
        self.assertEqual(self.ring.ancestry(CHOWN_PID, SCRIPT_PID, T0 + 0.3)["package"], "sudo")

    def test_a_process_that_cannot_be_read_is_ignored_without_failing(self):
        self.ring.observe_exec(424242, now=1.0)  # no existe
        self.ring.observe_exit(424242, now=1.0)
        self.assertEqual(self.ring._ring, {})

    def test_the_script_may_be_any_of_the_four(self):
        for kind in ("preinst", "postinst", "prerm", "postrm"):
            self.ring.clear()
            self.dpkg_runs_the_postinst(script=f"/var/lib/dpkg/info/sudo.{kind}")
            self.assertIsNotNone(self.ring.ancestry(CHOWN_PID, SCRIPT_PID, T0 + 0.3), kind)

    def test_the_ring_forgets_what_is_old_and_is_bounded(self):
        self.dpkg_runs_the_postinst()
        later = self.t_script + self.ring.TTL_S + 1
        self.world.add(800001, DPKG_PID, "/usr/bin/dash", ["/bin/sh", "/var/lib/dpkg/info/foo.postinst"])
        self.ring.observe_exec(800001, now=later)
        self.assertNotIn((SCRIPT_PID, self.world.procs[SCRIPT_PID]["start"]), self.ring._ring)
        with mock.patch.object(self.ring, "MAX_ENTRIES", 3):
            for i in range(10):
                self.world.add(810000 + i, DPKG_PID, "/usr/bin/dash", ["/bin/sh", f"/var/lib/dpkg/info/p{i}.postinst"])
                self.ring.observe_exec(810000 + i, now=later + i)
        self.assertLessEqual(len(self.ring._ring), 3)


class TheListenerFeedsTheRing(unittest.TestCase):

    def test_the_kernel_datagram_gives_execs_and_exits(self):
        from arx.modules import execwatch

        def msg(what, pid):
            body = (execwatch.CN_IDX_PROC.to_bytes(4, "little") + execwatch.CN_VAL_PROC.to_bytes(4, "little")
                    + bytes(12) + (0).to_bytes(0, "little"))
            body = body[:20] + what.to_bytes(4, "little") + bytes(4) + (123456).to_bytes(8, "little") \
                + pid.to_bytes(4, "little") + pid.to_bytes(4, "little") + bytes(8)
            return (len(body) + 16).to_bytes(4, "little") + bytes(12) + body
        data = msg(execwatch.PROC_EVENT_EXEC, 4242) + msg(execwatch.PROC_EVENT_EXIT, 4243)
        self.assertEqual(execwatch.parse_events(data), [(4242, 123456)])  # lo de siempre: solo execs
        self.assertEqual(execwatch.parse_all(data), [(execwatch.PROC_EVENT_EXEC, 4242, 123456),
                                                     (execwatch.PROC_EVENT_EXIT, 4243, 123456)])

    def test_an_exit_of_a_thread_that_is_not_the_leader_is_not_the_exit_of_the_process(self):
        from arx.modules import execwatch
        body = (execwatch.CN_IDX_PROC.to_bytes(4, "little") + execwatch.CN_VAL_PROC.to_bytes(4, "little") + bytes(12)
                + execwatch.PROC_EVENT_EXIT.to_bytes(4, "little") + bytes(4) + (5).to_bytes(8, "little")
                + (4243).to_bytes(4, "little") + (4000).to_bytes(4, "little") + bytes(8))  # tid 4243 del proceso 4000
        data = (len(body) + 16).to_bytes(4, "little") + bytes(12) + body
        self.assertEqual(execwatch.parse_all(data), [])

    def test_the_listener_feeds_every_event_and_only_works_on_execs(self):
        from arx.modules import execwatch
        events = [(execwatch.PROC_EVENT_EXEC, 10, 1), (execwatch.PROC_EVENT_EXIT, 11, 2)]
        observed, handled = [], []

        class Sock:
            def __init__(self):
                self.calls = 0

            def recv(self, n):
                self.calls += 1
                if self.calls > 1:
                    raise SystemExit
                return b"datagrama"
        with mock.patch.object(execwatch, "parse_all", lambda data: events), \
                mock.patch.object(execwatch, "_observe", lambda what, pid: observed.append((what, pid))), \
                mock.patch.object(execwatch, "handle_pid", lambda pid, root, enforce, ts=None: handled.append(pid)):
            with self.assertRaises(SystemExit):
                execwatch._listen(Sock(), "", lambda: False)
        self.assertEqual(observed, [(execwatch.PROC_EVENT_EXEC, 10), (execwatch.PROC_EVENT_EXIT, 11)])
        self.assertEqual(handled, [10])

    def test_each_event_reaches_the_ring_before_the_slow_work_and_a_failure_never_stops_the_loop(self):
        from arx.modules import execwatch, procring
        seen = []
        with mock.patch.object(procring, "observe_exec", lambda pid, now=None: seen.append(("exec", pid))), \
                mock.patch.object(procring, "observe_exit", lambda pid, now=None: seen.append(("exit", pid))):
            execwatch._observe(execwatch.PROC_EVENT_EXEC, 10)
            execwatch._observe(execwatch.PROC_EVENT_EXIT, 11)
            execwatch._observe(0x1, 12)  # otro tipo de evento: nada
        self.assertEqual(seen, [("exec", 10), ("exit", 11)])
        with mock.patch.object(procring, "observe_exec", side_effect=RuntimeError("x")):
            execwatch._observe(execwatch.PROC_EVENT_EXEC, 10)  # no propaga


class TheFdNameInTheText(AncestryBase):
    """«/root/(null)»: un fchown/fchmod por descriptor no trae nombre; el texto usa el del inodo cuando se sabe."""

    def test_a_descriptor_event_shows_the_file_it_belongs_to(self):
        self.unsigned.add("sudo")  # que salgan como high para leer su texto
        got = self.feed_ssh()
        texts = " ".join(e["detail"] for e in self.high(got))
        self.assertNotIn("(null)", texts)
        self.assertIn("/etc/sudoers.d/README.dpkg-new", texts)

    def test_the_text_of_a_creation_names_the_file_not_its_directory(self):
        self.unsigned.add("sudo")
        create = [l for l in ssh_records() if "32267" in l]
        got = self.feed(create)
        self.assertEqual(len(self.high(got)), 1)
        self.assertIn("README.dpkg-new", self.high(got)[0]["detail"])

    def test_an_unknown_descriptor_still_says_what_it_can(self):
        fd = base.audit_event(9990, T0 + 0.5, "/usr/bin/dpkg", ["(null)"], syscall="93", auid="0", ses="432")
        got = self.feed(fd)
        self.assertEqual(len(self.high(got)), 1)


if __name__ == "__main__":
    unittest.main()
