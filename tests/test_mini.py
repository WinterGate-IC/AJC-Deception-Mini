import json
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ajc_mini import config, deception, engine, layers, profiles, storage, verdict


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ajc-mini-t-")
        self.cfg = config.Config(data_dir=self.tmp.name)
        self.store = storage.Store(self.cfg.data_dir)
        self.eng = engine.Engine(self.cfg, self.store)

    def tearDown(self):
        self.tmp.cleanup()


class TestMini(unittest.TestCase):
    def test_layers(self):
        self.assertGreaterEqual(len(layers.LAYERS), 8)
        self.assertEqual(profiles.CHAIN[:3], [1, 4, 31])
        self.assertIn(44, profiles.CHAIN)
        self.assertIn(67, profiles.RECEIPT)

    def test_plan(self):
        p = profiles.plan(44)
        nums = [x["num"] for x in p]
        for n in (31, 34, 35, 41, 43, 44, 67):
            self.assertIn(n, nums)
        self.assertNotIn(51, nums)
        self.assertIn(51, [x["num"] for x in profiles.plan(51)])

    def test_classify_and_canary(self):
        c = deception.classify("GET", "/?q=1 UNION SELECT password", {}, "")
        self.assertIn("sql_injection", c["types"])
        c = deception.classify("GET", "/source/engine.py", {}, "")
        self.assertTrue(c["source_probe"])
        c = deception.classify("GET", "/?x=AJC-CANARY-ABCDEF0123456789ABCD", {}, "")
        self.assertTrue(c["canary_replay"])

    def test_source_probe_is_fake(self):
        cfg = config.Config(data_dir=tempfile.mkdtemp(prefix="ajc-mini-d2-"))
        s = deception.Session(ip="198.51.100.5", seed=1)
        r = deception.serve(s, cfg.get("canary_secret"), "GET", "/source/engine.py", {}, "")
        self.assertIn("Decoy module", r["body"])
        self.assertNotIn("class Engine", r["body"])

    def test_canary_escalates(self):
        cfg = config.Config(data_dir=tempfile.mkdtemp(prefix="ajc-mini-d3-"))
        s = deception.Session(ip="198.51.100.6", seed=1)
        deception.serve(s, cfg.get("canary_secret"), "GET", "/", {}, "")
        before = s.boost
        deception.serve(s, cfg.get("canary_secret"), "GET",
                        "/?x=AJC-CANARY-ABCDEF0123456789ABCD", {}, "")
        self.assertGreater(s.boost, before)
        self.assertTrue(s.terminal)


class TestEngine(Base):
    def test_engine(self):
        d = self.eng.handle_event({"ip": "203.0.113.8", "type": "sqli",
                                   "severity": "high", "method": "POST",
                                   "endpoint": "/api", "payload": "1 UNION SELECT 1"})
        self.assertIn(d["verdict"], verdict.RANK)
        self.assertIn("mirage", d["actions"])
        self.assertTrue(self.store.verify_evidence()["ok"])

    def test_reverse(self):
        d = self.eng.handle_event({"ip": "203.0.113.9", "type": "recon_scan",
                                   "severity": "medium", "method": "GET",
                                   "endpoint": "/.git/config", "reverse_engineering": True})
        self.assertTrue(d["controls"]["reverse_engineering"])
        self.assertEqual(d["controls"]["deception"], 3)


class TestServer(Base):
    def test_http(self):
        from ajc_mini import server
        httpd = server.serve(self.cfg, self.store, self.eng, bind="127.0.0.1", port=0)
        port = httpd.server_address[1]
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        base = "http://127.0.0.1:%d" % port
        try:
            with urllib.request.urlopen(base + "/health", timeout=5) as r:
                self.assertEqual(json.loads(r.read())["layers"], len(layers.LAYERS))
            try:
                urllib.request.urlopen(base + "/mini/api/status", timeout=5)
                self.fail("expected 401")
            except urllib.error.HTTPError as e:
                self.assertEqual(e.code, 401)
            with urllib.request.urlopen(base + "/admin", timeout=5) as r:
                body = r.read().decode()
                self.assertIn("AJC-CANARY-", body)
                self.assertLess(len(body), 65536)
        finally:
            httpd.shutdown()
            httpd.server_close()


class TestInstaller(unittest.TestCase):
    def test_real_install(self):
        tmp = tempfile.mkdtemp(prefix="ajc-mini-i-")
        pre = Path(tmp) / "code"
        data = Path(tmp) / "data"
        p = subprocess.run([sys.executable, str(ROOT / "installer.py"), "--yes",
                            "--no-service", "--prefix", str(pre), "--data-dir", str(data),
                            "--port", "18794"], capture_output=True, text=True, timeout=180)
        self.assertEqual(p.returncode, 0, p.stderr)
        cfg = json.loads((data / "config.json").read_text())
        self.assertEqual(cfg["version"], "1.0.0")
        self.assertTrue((pre / "bin" / "ajc-mini").exists())
        v = subprocess.run([str(pre / "bin" / "ajc-mini"), "version"],
                           capture_output=True, text=True)
        self.assertEqual(v.returncode, 0, v.stderr)
        self.assertIn("1.0.0", v.stdout)


if __name__ == "__main__":
    unittest.main()
