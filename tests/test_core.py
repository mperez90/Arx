"""Suite de Arx Core — sin dependencias (unittest). Corre con:  python -m unittest discover -s tests

Cada test aísla config/estado en directorios temporales por entorno.
"""
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

PRO = "e03995ef-5765-4fd7-abb9-2350f275aed8"


def _isolate():
    d = tempfile.mkdtemp()
    os.environ["ARX_CONFIG_DIR"] = os.path.join(d, "cfg")
    os.environ["ARX_STATE_DIR"] = os.path.join(d, "state")
    os.environ["ARX_POLAR_ENV"] = "sandbox"
    return d


class LicenseTests(unittest.TestCase):
    def setUp(self):
        _isolate()
        from arx import license as lic
        self.lic = lic
        lic.activate("K", "h", "o", "v", post=lambda u, p: {"id": "a1"})

    def test_four_benefits(self):
        self.assertEqual(len(self.lic._env()["benefits"]), 4)

    def test_fail_open_offline_keeps_tier(self):
        fut = (datetime.now(timezone.utc) + timedelta(days=900)).isoformat()
        self.lic.validate(post=lambda u, p: {"status": "granted", "benefit_id": PRO, "expires_at": fut})

        def boom(u, p):
            raise ConnectionError("down")

        self.lic.validate(post=boom)  # offline
        self.assertEqual(self.lic.effective_tier()[0], "pro")  # no desarma

    def test_revoked_downgrades_now(self):
        self.lic.validate(post=lambda u, p: {"status": "revoked"})
        self.assertEqual(self.lic.effective_tier()[0], "core")

    def test_expires_at_downgrades(self):
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        self.lic.validate(post=lambda u, p: {"status": "granted", "benefit_id": PRO, "expires_at": past})
        self.assertEqual(self.lic.effective_tier()[0], "core")

    def test_unknown_benefit_is_core(self):
        r = self.lic.validate(post=lambda u, p: {"status": "granted", "benefit_id": "xxx"})
        self.assertEqual(r["tier"], "core")

    def test_http_denied_is_not_offline(self):
        import urllib.error

        def deny(u, p):
            raise urllib.error.HTTPError(u, 404, "not found", {}, None)

        r = self.lic.validate(post=deny)
        self.assertFalse(r.get("offline"))  # "me dijeron que no" != "no pude preguntar"
        self.assertEqual(self.lic.effective_tier()[0], "core")

    def test_clock_backward_keeps_tier(self):
        fut = (datetime.now(timezone.utc) + timedelta(days=900)).isoformat()
        self.lic.validate(post=lambda u, p: {"status": "granted", "benefit_id": PRO, "expires_at": fut})
        past = datetime.now(timezone.utc) - timedelta(days=5)
        self.assertEqual(self.lic.effective_tier(now=past)[0], "pro")  # anomalía de reloj no desarma


class BaselineTests(unittest.TestCase):
    def setUp(self):
        _isolate()
        from arx.modules import baseline
        self.baseline = baseline

    def test_compare_detects_new_with_target(self):
        b = {"sets": {"listen_ports": {}}, "gauges": {}}
        snap = {"sets": {"listen_ports": ["tcp 0.0.0.0:4444"], "processes": [], "services": [],
                         "login_users": []}, "gauges": {}}
        f = self.baseline.compare(b, snap)
        self.assertEqual(f[0]["target"], {"proto": "tcp", "addr": "0.0.0.0", "port": 4444})
        self.assertEqual(f[0]["sev"], "high")


class CanaryTests(unittest.TestCase):
    def setUp(self):
        self.d = _isolate()
        from arx.modules import canaries
        self.canaries = canaries
        self.lab = os.path.join(self.d, "lab")
        os.makedirs(self.lab)

    def test_plant_and_detect_modification(self):
        planted = self.canaries.plant([self.lab])
        self.assertTrue(planted)
        self.assertEqual(self.canaries.check(), [])
        with open(planted[-1]["path"], "a") as fh:
            fh.write("intruso\n")
        self.assertTrue(any("MODIFICADO" in x["detail"] for x in self.canaries.check()))


class ResponseTests(unittest.TestCase):
    def setUp(self):
        _isolate()
        from arx.modules import response
        self.response = response

    def test_tier_classification(self):
        self.assertEqual(self.response.classify({"kind": "integrity"})["tier"], 2)
        self.assertEqual(self.response.classify({"kind": "listen_ports"})["tier"], 1)
        self.assertEqual(self.response.classify({"kind": "gauge"})["tier"], 0)

    def test_pending_and_authorize(self):
        self.response.handle({"kind": "integrity", "sev": "high", "detail": "passwd cambió"})
        pend = self.response.list_pending()
        self.assertEqual(len(pend), 1)
        self.assertIsNotNone(self.response.authorize_pending(pend[0]["id"]))
        self.assertEqual(self.response.list_pending(), [])

    def test_block_auto_expiry(self):
        now = datetime.now(timezone.utc)
        self.response._save_blocks([])
        self.response.register_block({"detail": "p4444"}, "ufw delete deny 4444/tcp", ttl_min=60, now=now)
        self.assertEqual(self.response.expire_blocks(now=now + timedelta(minutes=30)), [])
        self.assertEqual(len(self.response.expire_blocks(now=now + timedelta(minutes=61))), 1)
        self.assertEqual(self.response._load_blocks(), [])


class RedactTests(unittest.TestCase):
    def setUp(self):
        _isolate()
        from arx import config, redact
        self.config = config
        self.redact = redact

    def test_scrub_keeps_hashes(self):
        self.config.save_secrets({"openai": "sk-REALKEY1234567890"})
        out = self.redact.scrub("key=sk-REALKEY1234567890 hash=a1b2c3d4e5f6a7b8")
        self.assertNotIn("sk-REALKEY", out)
        self.assertIn("a1b2c3d4e5f6a7b8", out)


class ConfigTests(unittest.TestCase):
    def setUp(self):
        _isolate()
        from arx import config
        self.config = config

    def test_word_hash_roundtrip(self):
        stored = self.config.hash_word("varsovia")
        self.assertNotIn("varsovia", str(stored))  # nunca en claro
        self.assertTrue(self.config.verify_word("varsovia", stored))
        self.assertFalse(self.config.verify_word("otra", stored))


class EngineTests(unittest.TestCase):
    def setUp(self):
        _isolate()
        from arx.engine import Engine, ProviderError
        self.Engine, self.ProviderError = Engine, ProviderError
        os.environ["ARX_OPENAI_API_KEY"] = "x"
        os.environ["ARX_ANTHROPIC_API_KEY"] = "y"

    def test_fallback_on_failure(self):
        cfg = {"providers": {"openai": "m1", "anthropic": "m2"}, "fallback_order": ["openai", "anthropic"]}

        def post(url, headers, payload):
            if "openai" in url:
                raise ConnectionError("down")
            return {"content": [{"text": "ok"}]}

        ans, prov = self.Engine(cfg, post=post).ask([{"role": "user", "content": "hi"}])
        self.assertEqual((prov, ans), ("anthropic", "ok"))


class FleetTests(unittest.TestCase):
    BUS = "81882e82-5547-479a-a969-4ae6a514faed"

    def setUp(self):
        _isolate()
        from arx import license as lic
        from arx.modules import fleet
        self.lic, self.fleet = lic, fleet

    def _make_business(self):
        self.lic.activate("K", "h", "o", "v", post=lambda u, p: {"id": "a1"})
        fut = (datetime.now(timezone.utc) + timedelta(days=700)).isoformat()
        self.lic.validate(post=lambda u, p: {"status": "granted", "benefit_id": self.BUS, "expires_at": fut})

    def test_disabled_without_business(self):
        self.assertFalse(self.fleet.enabled())
        self.assertFalse(self.fleet.enroll("http://c", "tok")["ok"])

    def test_enroll_and_report_redacts(self):
        self._make_business()
        self.assertTrue(self.fleet.enabled())
        self.assertTrue(self.fleet.enroll("http://c", "tok",
                        post=lambda u, h, p: {"agent_id": "ag-1", "agent_token": "t"})["ok"])
        from arx import config
        config.save_secrets({**config.load_secrets(), "openai": "sk-SECRET1234567890"})
        cap = {}

        def post(url, headers, payload):
            cap.update(payload)
            return {}

        self.fleet.report([{"detail": "leak sk-SECRET1234567890"}], post=post)
        self.assertNotIn("sk-SECRET", str(cap))


if __name__ == "__main__":
    unittest.main()
