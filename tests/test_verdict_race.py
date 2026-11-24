"""HZ de Q sobre M5.1 (y, según arx-98, ya en 0.0.9): un `arx accept` que cae mientras el modelo piensa.

El modelo tarda hasta 180 s. Si en medio la persona hace `arx accept` de un `login_users`, `accept()` llama a `forget()`,
que borra el hallazgo sin dejar rastro; cuando llega el veredicto «threat», `apply_verdicts` ve `st.get(id) = None`,
`_verdict_refusal` no refusa y `contain_identity` cierra la sesión que la persona acababa de aceptar.

Ahora: un veredicto sobre un hallazgo que ya no está vivo (aceptado u olvidado) no actúa, y `accept()` de un `login_users` deja
constancia de que lo decidió una persona (`human_cleared`), como `unlock`: si el mismo hallazgo reaparece, el modelo tampoco
lo puede contradecir.

Corre con: python -m unittest discover -s tests
"""
import os

os.environ["ARX_LANG"] = "es"

import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def _isolate():
    d = tempfile.mkdtemp()
    os.environ["ARX_CONFIG_DIR"] = os.path.join(d, "cfg")
    os.environ["ARX_STATE_DIR"] = os.path.join(d, "state")
    os.environ["ARX_POLAR_ENV"] = "sandbox"
    return d


def _login(user="ana", origin="203.0.113.9"):
    item = f"{user}@{origin}"
    return {"sev": "high", "kind": "login_users", "detail": f"nuevo en login_users: {item}", "why": "w",
            "target": {"user": item}, "set": "login_users", "item": item,
            "fp_key": f"login_users|nuevo en login_users: {item}"}


THREAT = {"verdict": "threat", "confidence": 95, "reason": "acceso tras fuerza bruta"}


class Base(unittest.TestCase):
    def setUp(self):
        _isolate()
        from arx.modules import baseline, response
        self.r, self.b = response, baseline
        self.contained = []
        for obj, name, value in (
                (response, "has_live_session", lambda user, origin="": True),
                (response, "contain_identity", lambda f, decided, v=None, cfg=None: (
                    self.contained.append(f["target"]["user"]) or
                    {"user": "ana", "origin": "x", "locked": True, "decided_by": decided, "verdict": v,
                     "detail": f.get("detail"), "lock": "bloqueada", "closed": [], "survivors": [], "origin_block": None,
                     "summary": "cerrada"})),
                (response, "_is_linux_root", lambda: False),
                (baseline, "accept", lambda s, item: True)):
            patch = mock.patch.object(obj, name, value)
            patch.start()
            self.addCleanup(patch.stop)

    def register(self, finding):
        """El hallazgo como lo deja `handle` en el barrido: nuevo, en el estado, con su huella."""
        out = self.r.handle(finding, enforce=True, cfg={})
        return finding, out

    def verdict(self, fp, kind="threat"):
        return {"id": fp, **THREAT, "verdict": kind}

    def apply(self, pair, **kw):
        return self.r.apply_verdicts([pair], [self.verdict(pair[1]["fp"])], enforce=True, cfg=kw.get("cfg", {}))


class TheVerdictOfAFindingThatIsGone(Base):

    def test_the_red_case_of_q_an_absent_entry_is_refused(self):
        now = datetime.now(timezone.utc)
        got = self.r._verdict_refusal("ana", "203.0.113.9", None, True, {}, now)
        self.assertIsNotNone(got)
        self.assertIn("ya no está", got)

    def test_a_live_finding_is_still_acted_on(self):
        """El control: sin él, las pruebas de abajo no probarían nada."""
        pair = self.register(_login())
        reports = self.apply(pair)
        self.assertEqual(self.contained, ["ana@203.0.113.9"])
        self.assertTrue(reports[0]["locked"])

    def test_accept_while_the_model_thinks_means_the_verdict_does_not_act(self):
        pair = self.register(_login())
        self.assertIn("Aceptado", self.r.accept(pair[1]["fp"]))        # la persona, desde la CLI, mientras el modelo piensa
        reports = self.apply(pair)                                      # llega «threat»
        self.assertEqual(self.contained, [])
        self.assertFalse(reports[0]["locked"])
        self.assertIn("ya no está", reports[0]["lock"])

    def test_forgetting_it_means_the_same(self):
        pair = self.register(_login())
        self.r.forget(pair[1]["fp"])
        reports = self.apply(pair)
        self.assertEqual(self.contained, [])
        self.assertFalse(reports[0]["locked"])

    def test_the_refusal_is_recorded_and_the_owner_is_told_it_waits_for_them_no_more(self):
        pair = self.register(_login())
        self.r.accept(pair[1]["fp"])
        reports = self.apply(pair)
        incidents = [json.loads(l) for l in open(self.r._incidents_path()).read().splitlines()]
        self.assertIn("identity_refused", [i["kind"] for i in incidents])
        self.assertEqual(reports[0]["origin_block"], None)

    def test_the_other_refusals_keep_their_order_and_their_text(self):
        now = datetime.now(timezone.utc)
        entry = {"seen": 1}
        self.assertIn("observar", self.r._verdict_refusal("ana", "x", None, False, {}, now))     # modo observar, antes que nada
        self.assertIn("llm_identity_actions", self.r._verdict_refusal("ana", "x", None, True,
                                                                      {"llm_identity_actions": False}, now))
        self.assertIn("desbloqueaste", self.r._verdict_refusal("ana", "x", {"human_cleared": True}, True, {}, now))
        with mock.patch.object(self.r, "has_live_session", lambda u, o="": False):
            self.assertIn("sesión", self.r._verdict_refusal("ana", "x", entry, True, {}, now))
        self.assertIsNone(self.r._verdict_refusal("ana", "x", entry, True, {}, now))

    def test_one_verdict_of_the_batch_that_is_gone_does_not_stop_the_others(self):
        a, b = self.register(_login("ana")), self.register(_login("eva", "198.51.100.7"))
        self.r.accept(a[1]["fp"])
        reports = self.r.apply_verdicts([a, b], [self.verdict(a[1]["fp"]), self.verdict(b[1]["fp"])], enforce=True, cfg={})
        self.assertEqual(self.contained, ["eva@198.51.100.7"])
        self.assertEqual([r["locked"] for r in reports], [False, True])

    def test_a_verdict_that_waited_in_a_queue_for_minutes_is_checked_against_the_state_of_now(self):
        pair = self.register(_login())
        verdicts = [self.verdict(pair[1]["fp"])]
        self.r.accept(pair[1]["fp"])                                    # después de que el modelo contestó, antes de aplicarse
        reports = self.r.apply_verdicts([pair], verdicts, enforce=True, cfg={})
        self.assertEqual((self.contained, reports[0]["locked"]), ([], False))


class AcceptingAnIdentityIsAHumanDecision(Base):

    def cleared(self):
        path = self.r._cleared_path()
        return json.loads(open(path).read()) if os.path.exists(path) else {}

    def test_accept_of_a_login_leaves_the_mark_of_the_human(self):
        pair = self.register(_login())
        self.r.accept(pair[1]["fp"])
        self.assertIn(pair[1]["fp"], self.cleared())

    def test_if_the_same_finding_comes_back_it_is_born_cleared_and_the_model_cannot_overrule(self):
        pair = self.register(_login())
        self.r.accept(pair[1]["fp"])
        again = self.register(_login())
        entry = self.r.load_findings()[again[1]["fp"]]
        self.assertTrue(entry["human_cleared"])
        self.assertIn("solo se observa", again[1]["status"])      # «la desbloqueaste tú: solo se observa»
        reports = self.apply(again)
        self.assertEqual(self.contained, [])
        self.assertIn("desbloqueaste", reports[0]["lock"])

    def test_no_pending_authorization_is_opened_for_what_you_accepted(self):
        pair = self.register(_login())
        self.r.accept(pair[1]["fp"])
        self.register(_login())
        self.assertEqual(self.r.list_pending(), [])

    def test_accepting_other_kinds_leaves_no_mark(self):
        f = {"sev": "med", "kind": "listen_ports", "detail": "puerto", "why": "w", "target": {"port": 8080},
             "set": "listen_ports", "item": "tcp:8080"}
        out = self.r.handle(f, enforce=False, cfg={})
        self.r.accept(out["fp"])
        self.assertEqual(self.cleared(), {})

    def test_a_failed_accept_leaves_no_mark(self):
        pair = self.register(_login())
        with mock.patch.object(self.b, "accept", lambda s, item: False):
            self.r.accept(pair[1]["fp"])
        self.assertEqual(self.cleared(), {})
        self.assertIn(pair[1]["fp"], self.r.load_findings())

    def test_forgetting_without_accepting_leaves_no_mark(self):
        pair = self.register(_login())
        self.r.forget(pair[1]["fp"])
        self.assertEqual(self.cleared(), {})

    def test_the_marks_expire(self):
        pair = self.register(_login())
        self.r.accept(pair[1]["fp"])
        old = (datetime.now(timezone.utc) - timedelta(days=self.r.CLEARED_DAYS + 1)).isoformat(timespec="seconds")
        open(self.r._cleared_path(), "w").write(json.dumps({pair[1]["fp"]: old, "otro": old}))
        other = self.register(_login("eva", "198.51.100.7"))
        self.r.accept(other[1]["fp"])
        self.assertEqual(sorted(self.cleared()), [other[1]["fp"]])

    def test_the_marks_are_bounded(self):
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        open(self.r._cleared_path(), "w").write(json.dumps({f"fp{i}": now for i in range(self.r.CLEARED_MAX + 50)}))
        pair = self.register(_login())
        self.r.accept(pair[1]["fp"])
        self.assertLessEqual(len(self.cleared()), self.r.CLEARED_MAX)
        self.assertIn(pair[1]["fp"], self.cleared())

    def test_a_damaged_marks_file_does_not_break_anything(self):
        open(self.r._cleared_path(), "w").write("no es json{")
        pair = self.register(_login())
        self.r.accept(pair[1]["fp"])
        self.assertIn(pair[1]["fp"], self.cleared())

    def test_a_marks_file_that_is_valid_json_but_not_a_dictionary_is_ignored(self):
        for text in ("[1, 2]", "7", "null", '"x"'):
            open(self.r._cleared_path(), "w").write(text)
            pair = self.register(_login())
            self.r.accept(pair[1]["fp"])
            self.assertIn(pair[1]["fp"], self.cleared(), text)
            self.r.forget(pair[1]["fp"])

    def test_unlock_still_clears_what_it_cleared(self):
        pair = self.register(_login("mallory", "203.0.113.50"))
        st = self.r.load_findings()
        st[pair[1]["fp"]]["human_cleared"] = True
        self.r._save_findings(st)
        reports = self.apply(pair)
        self.assertIn("desbloqueaste", reports[0]["lock"])


if __name__ == "__main__":
    unittest.main()
