"""B75 + root · Un acceso nuevo de root (o de una cuenta de sistema, o de la última cuenta de administración) no se
puede responder bloqueando la cuenta: el código nunca la toca (`_lock_account`). El Tier 2 ofrecía «bloquear todos los
accesos de la cuenta», una acción que no se iba a ejecutar. Ahora propone lo que SÍ se ejecuta: bloquear el origen y
cerrar esa sesión, y nada más (ni la cuenta, ni los demás procesos de root). Corre con:
python -m unittest discover -s tests
"""
import os

os.environ["ARX_LANG"] = "es"

import signal
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

ORIGIN = "198.51.100.9"
LISTENER, SESSION, SHELL, CMD, OTHER_ROOT, ANA_SESSION, SECOND = 700, 4100, 4101, 4102, 5000, 4300, 4200


def _isolate():
    d = tempfile.mkdtemp()
    os.environ["ARX_CONFIG_DIR"] = os.path.join(d, "cfg")
    os.environ["ARX_STATE_DIR"] = os.path.join(d, "state")
    os.environ["ARX_POLAR_ENV"] = "sandbox"
    return d


class _R:
    returncode, stderr, stdout = 0, "", ""


class SessionOnly(unittest.TestCase):
    def setUp(self):
        _isolate()
        from arx.modules import recon, response
        self.r, self.recon = response, recon
        self.calls, self.kills = [], []
        self.uids = {"root": 0, "daemon": 1, "ana": 1000, "mallory": 1001}
        self.admin_is_last = False
        # procesos: pid → (uid, título, ppid)
        self.procs = {
            1: (0, "/sbin/init", 0),
            LISTENER: (0, "sshd: /usr/sbin/sshd -D [listener]", 1),
            SESSION: (0, "sshd: root@pts/0", LISTENER),
            SHELL: (0, "-bash", SESSION),
            CMD: (0, "tail -f /var/log/syslog", SHELL),
            OTHER_ROOT: (0, "/usr/sbin/cron -f", 1),
            SECOND: (0, "sshd: root@pts/1", LISTENER),   # otra sesión de root, desde otro origen
            ANA_SESSION: (1000, "sshd: ana@pts/2", LISTENER),
        }
        self.connections = [
            {"remote_ip": ORIGIN, "state": "ESTABLISHED", "pid": SESSION, "exe": "/usr/sbin/sshd"},
            {"remote_ip": "203.0.113.50", "state": "ESTABLISHED", "pid": SECOND, "exe": "/usr/sbin/sshd"},
            {"remote_ip": ORIGIN, "state": "ESTABLISHED", "pid": ANA_SESSION, "exe": "/usr/sbin/sshd"},
            {"remote_ip": "0.0.0.0", "state": "LISTEN", "pid": LISTENER, "exe": "/usr/sbin/sshd"},
            # lo que comparte origen con la sesión pero no es una sesión de sshd establecida: no se toca
            {"remote_ip": ORIGIN, "state": "CLOSE_WAIT", "pid": LISTENER, "exe": "/usr/sbin/sshd"},
            {"remote_ip": ORIGIN, "state": "ESTABLISHED", "pid": OTHER_ROOT, "exe": "/usr/sbin/cron"},
        ]

        def fake_run(argv, **kw):
            self.calls.append(argv)
            return _R()

        def fake_kill(pid, sig):
            if pid not in self.procs:
                raise ProcessLookupError(pid)
            self.kills.append((pid, sig))
            if sig == signal.SIGKILL:  # muere: ya no está ni él ni su conexión
                self.procs.pop(pid)
                self.connections[:] = [c for c in self.connections if c["pid"] != pid]

        def fake_getpwnam(name):
            if name not in self.uids:
                raise KeyError(name)
            return types.SimpleNamespace(pw_name=name, pw_uid=self.uids[name])
        for obj, name, value in [
                (response, "_is_linux_root", lambda: True), (response, "_shadow_state", lambda u: (False, "")),
                (response, "_leaves_no_admin", lambda u: self.admin_is_last),
                (response, "_never_block_ips", lambda: set()),
                (response.shutil, "which", lambda c: f"/usr/sbin/{c}" if c != "ufw" else None),
                (response.subprocess, "run", fake_run), (response.os, "kill", fake_kill),
                (response, "_proc_uid", lambda pid: self.procs[pid][0] if pid in self.procs else None),
                (response, "_proc_title", lambda pid: self.procs.get(pid, (0, "", 0))[1]),
                (response, "_ppid_map", lambda: {pid: p[2] for pid, p in self.procs.items()}),
                (response, "_pid_alive", lambda pid: pid in self.procs),
                (recon, "connection_owners", lambda: [dict(c) for c in self.connections])]:
            p = mock.patch.object(obj, name, value)
            p.start()
            self.addCleanup(p.stop)
        p = mock.patch("pwd.getpwnam", fake_getpwnam)
        p.start()
        self.addCleanup(p.stop)

    def login(self, user="root", origin=ORIGIN):
        return {"kind": "login_users", "sev": "high", "set": "login_users", "item": f"{user}@{origin}",
                "detail": f"nuevo en login_users: {user}@{origin}", "target": {"user": f"{user}@{origin}"}}

    def killed(self, sig=signal.SIGKILL):
        return sorted(pid for pid, s in self.kills if s == sig)

    def flat(self):
        return [" ".join(c) for c in self.calls]


class ThePlanOnlyOffersWhatRuns(SessionOnly):
    def test_a_new_root_login_proposes_blocking_the_origin_and_closing_that_session(self):
        plan = self.r.classify(self.login("root"))
        self.assertEqual(plan["tier"], 2)
        self.assertIn("bloquear la IP de origen y cerrar esa sesión", plan["action"])
        self.assertNotIn("bloquear todos los accesos", plan["action"])  # eso nunca se ejecutaría con root
        self.assertIn("root", plan["why"])

    def test_system_accounts_get_the_same_plan(self):
        self.assertIn("cerrar esa sesión", self.r.classify(self.login("daemon"))["action"])

    def test_the_last_administrator_gets_it_too_and_the_why_says_so(self):
        self.admin_is_last = True
        plan = self.r.classify(self.login("ana"))
        self.assertIn("cerrar esa sesión", plan["action"])
        self.assertIn("última cuenta de administración", plan["why"])

    def test_an_ordinary_account_keeps_the_lock_plan(self):
        plan = self.r.classify(self.login("mallory"))
        self.assertIn("bloquear todos los accesos", plan["action"])
        self.assertNotIn("cerrar esa sesión", plan["action"])

    def test_an_ordinary_admin_who_is_not_the_last_keeps_the_lock_plan(self):
        self.admin_is_last = False
        self.assertIn("bloquear todos los accesos", self.r.classify(self.login("ana"))["action"])

    def test_unknown_or_invalid_accounts_keep_the_old_plan_and_do_not_crash(self):
        for user in ("ghost", "-rf"):
            plan = self.r.classify({**self.login(user), "target": {"user": f"{user}@{ORIGIN}"}})
            self.assertEqual(plan["tier"], 2, user)
            self.assertNotIn("cerrar esa sesión", plan["action"], user)

    def test_other_kinds_are_untouched(self):
        for kind in ("listen_ports", "executables", "uid0_account", "suid_new", "integrity"):
            self.assertNotIn("cerrar esa sesión", self.r.classify({"kind": kind})["action"], kind)

    def test_the_last_admin_is_not_computed_off_a_linux_root_host(self):
        self.admin_is_last = True
        with mock.patch.object(self.r, "_is_linux_root", lambda: False):
            self.assertNotIn("cerrar esa sesión", self.r.classify(self.login("ana"))["action"])

    def test_the_pending_item_shows_what_will_run(self):
        out = self.r.handle(self.login("root"), enforce=True, cfg={})
        self.assertEqual(out["tier"], 2)
        pending = self.r.list_pending()
        self.assertEqual(len(pending), 1)
        self.assertIn("cerrar esa sesión", pending[0]["remediation"])


class AuthorizingClosesOnlyThatSession(SessionOnly):
    def test_it_blocks_the_origin_and_never_touches_the_account(self):
        res = self.r._execute_tier2(self.login("root"))
        self.assertTrue(any(ORIGIN in c and "block_ipv4" in c for c in self.flat()), self.flat())
        self.assertFalse(any("usermod" in c for c in self.flat()))  # root no se bloquea
        self.assertEqual(self.r._load_blocks()[0]["revert"].get("ip"), ORIGIN)
        self.assertIn("no se bloquea", res)
        self.assertIn(f"arx unblock {ORIGIN}", res)

    def test_it_closes_the_session_and_what_was_born_from_it(self):
        res = self.r._execute_tier2(self.login("root"))
        self.assertEqual(self.killed(), [SESSION, SHELL, CMD])
        self.assertEqual(self.killed(signal.SIGSTOP), [SESSION, SHELL, CMD])  # primero se congela, luego se mata
        first_kill = next(i for i, (_, sig) in enumerate(self.kills) if sig == signal.SIGKILL)
        self.assertTrue(all(sig == signal.SIGSTOP for _, sig in self.kills[:first_kill]))
        self.assertIn("sshd: root@pts/0", res)
        self.assertIn("no se puede recuperar", res)

    def test_the_rest_of_root_and_of_sshd_stays_alone(self):
        self.r._execute_tier2(self.login("root"))
        touched = {pid for pid, _ in self.kills}
        self.assertNotIn(LISTENER, touched)     # matar al que escucha dejaría el servidor sin SSH
        self.assertNotIn(1, touched)
        self.assertNotIn(OTHER_ROOT, touched)   # cron y todo lo demás de root
        self.assertNotIn(SECOND, touched)       # otra sesión de root, desde otro origen
        self.assertNotIn(ANA_SESSION, touched)  # otra cuenta, aunque venga del mismo origen

    def test_arx_and_its_parent_are_never_killed(self):
        self.procs[os.getpid()] = (0, "arx authorize", SHELL)
        self.procs[os.getppid()] = (0, "bash", SESSION)
        self.r._execute_tier2(self.login("root"))
        touched = {pid for pid, _ in self.kills}
        self.assertNotIn(os.getpid(), touched)
        self.assertNotIn(os.getppid(), touched)

    def test_a_system_account_and_the_last_admin_are_closed_the_same_way(self):
        self.r._execute_tier2(self.login("daemon", ORIGIN))
        self.assertFalse(any("usermod" in c for c in self.flat()))
        self.kills.clear()
        self.admin_is_last = True
        self.procs[ANA_SESSION] = (1000, "sshd: ana@pts/2", LISTENER)
        res = self.r._execute_tier2(self.login("ana", ORIGIN))
        self.assertEqual(self.killed(), [ANA_SESSION])
        self.assertFalse(any("usermod" in c for c in self.flat()))
        self.assertIn("última cuenta de administración", res)

    def test_the_root_monitor_of_an_ordinary_session_is_the_session_too(self):
        """Antes de autenticar y a ratos después, el monitor `sshd: ana [priv]` (de root) sostiene la conexión."""
        self.admin_is_last = True
        self.procs[ANA_SESSION] = (0, "sshd: ana [priv]", LISTENER)
        self.r._execute_tier2(self.login("ana", ORIGIN))
        self.assertEqual(self.killed(), [ANA_SESSION])

    def test_without_a_live_session_it_says_so_and_still_blocks_the_origin(self):
        self.connections.clear()
        res = self.r._execute_tier2(self.login("root"))
        self.assertEqual(self.kills, [])
        self.assertIn("No se encontró ninguna sesión", res)
        self.assertTrue(any(ORIGIN in c and "block_ipv4" in c for c in self.flat()))

    def test_a_login_with_no_ip_blocks_nothing_and_says_so(self):
        res = self.r._execute_tier2(self.login("root", origin=""))
        self.assertFalse(any("block_ipv4" in c for c in self.flat()))
        self.assertEqual(self.kills, [])
        self.assertIn("sin IP utilizable", res)

    def test_a_protected_origin_is_not_blocked_but_the_session_that_you_authorized_is_closed(self):
        with mock.patch.object(self.r, "_never_block_ips", lambda: {ORIGIN}):
            res = self.r._execute_tier2(self.login("root"))
        self.assertFalse(any("block_ipv4" in c and ORIGIN in c for c in self.flat()))
        self.assertEqual(self.killed(), [SESSION, SHELL, CMD])
        self.assertIn(f"su IP {ORIGIN} no se bloquea", res)

    def test_survivors_are_reported(self):
        with mock.patch.object(self.r, "_pid_alive", lambda pid: pid == CMD):
            res = self.r._execute_tier2(self.login("root"))
        self.assertIn("SIGUEN VIVOS", res)
        self.assertIn(str(CMD), res)

    def test_a_killed_process_that_vanishes_midway_is_not_an_error(self):
        self.procs.pop(CMD)
        self.r._execute_tier2(self.login("root"))
        self.assertEqual(self.killed(), [SESSION, SHELL])

    def test_the_incident_is_recorded_without_claiming_a_lock(self):
        import json
        self.r._execute_tier2(self.login("root"))
        events = [json.loads(line) for line in open(self.r._incidents_path())]
        kinds = [e["kind"] for e in events]
        self.assertIn("session_closed", kinds)
        self.assertNotIn("identity_contained", kinds)
        self.assertEqual(self.r.locked_accounts(), [])

    def test_an_ordinary_account_is_still_locked_and_all_its_sessions_closed(self):
        """Lo que ya funcionaba no cambia."""
        self.procs[4400] = (1001, "sshd: mallory@pts/3", LISTENER)
        self.connections.append({"remote_ip": "198.51.100.77", "state": "ESTABLISHED", "pid": 4400,
                                 "exe": "/usr/sbin/sshd"})
        with mock.patch.object(self.r, "_close_sessions", lambda uid: ([{"pid": 4400, "cmd": "sshd"}], [])):
            res = self.r._execute_tier2(self.login("mallory", "198.51.100.77"))
        self.assertTrue(any("usermod -L -e 1 mallory" in c for c in self.flat()))
        self.assertIn("bloqueada", res)

    def test_if_the_state_changed_and_it_can_be_locked_now_the_account_is_locked(self):
        """Lo que se autorizó fue el bloqueo de la cuenta: si ya se puede, es lo que se hace."""
        self.admin_is_last = False
        res = self.r._execute_tier2(self.login("ana", ORIGIN))
        self.assertTrue(any("usermod -L -e 1 ana" in c for c in self.flat()))
        self.assertIn("bloqueada", res)


class TheModelStillCannotTouchRootOrTheLastAdmin(SessionOnly):
    def _pair(self, user):
        f = self.login(user)
        fp = "abc123" + "0" * 34
        self.r._save_findings({fp: {"seen": 1, "kind": "login_users", "item": f["target"]["user"], "status": "pending"}})
        return f, {"fp": fp, "tier": 2, "status": "pending", "new": True}   # un hallazgo vivo: está en el estado

    def test_a_model_verdict_on_root_closes_nothing_and_tells_the_owner_how_to_do_it(self):
        pair = self._pair("root")
        v = {"id": pair[1]["fp"], "verdict": "threat", "confidence": 95, "reason": "r"}
        with mock.patch.object(self.r, "has_live_session", lambda u, o="": True):
            reports = self.r.apply_verdicts([pair], [v], enforce=True, cfg={})
        self.assertEqual(self.kills, [])
        self.assertFalse(any("block_ipv4" in c for c in self.flat()))
        self.assertFalse(reports[0]["locked"])
        self.assertIn("arx authorize abc123", reports[0]["summary"])
        self.assertIn("cerrar esa sesión", reports[0]["summary"])

    def test_the_last_admin_is_out_of_reach_of_the_model_too(self):
        self.admin_is_last = True
        pair = self._pair("ana")
        v = {"id": pair[1]["fp"], "verdict": "threat", "confidence": 99, "reason": "r"}
        with mock.patch.object(self.r, "has_live_session", lambda u, o="": True):
            reports = self.r.apply_verdicts([pair], [v], enforce=True, cfg={})
        self.assertEqual(self.kills, [])
        self.assertEqual(self.flat(), [])  # ni usermod ni bloqueo del origen
        self.assertFalse(reports[0]["locked"])
        self.assertIn("arx authorize abc123", reports[0]["summary"])

    def test_the_whole_flow_acts_only_with_the_human_word(self):
        """Hallazgo → Tier 2 pendiente (0 acciones, ni con --enforce) → authorize: origen bloqueado y sesión cerrada."""
        out = self.r.handle(self.login("root"), enforce=True, cfg={})
        self.assertEqual(out["tier"], 2)
        self.assertIn("pending_id", out)
        self.assertEqual(self.kills, [])
        self.assertEqual(self.flat(), [])
        self.assertEqual(self.r.locked_accounts(), [])
        done = self.r.authorize_pending(out["pending_id"])
        self.assertTrue(any(ORIGIN in c and "block_ipv4" in c for c in self.flat()))
        self.assertEqual(self.killed(), [SESSION, SHELL, CMD])
        self.assertIn("Cuenta 'root'", done["executed"])
        self.assertIn("sshd: root@pts/0", done["executed"])

    def test_an_ordinary_refusal_does_not_get_the_session_hint(self):
        pair = self._pair("mallory")
        v = {"id": pair[1]["fp"], "verdict": "benign", "confidence": 95, "reason": "r"}
        self.assertEqual(self.r.apply_verdicts([pair], [v], enforce=True, cfg={}), [])


if __name__ == "__main__":
    unittest.main()
