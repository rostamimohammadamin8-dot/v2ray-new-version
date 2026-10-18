"""Offline verifier CLI tests."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import aggregate as agg  # noqa: E402
from scripts import verify  # noqa: E402

PAYLOAD = (
    "vless://66666666-6666-6666-6666-666666666666@de.example.com:443?security=tls#DE\n"
    "trojan://pw@uk.example.com:443#UK\n"
).encode()


class VerifyCliTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        config = self.root / "sources.json"
        config.write_text(json.dumps({"version": 1, "sources": [{"id": "a", "url": "https://a.example/sub", "enabled": True}]}))
        self.data = self.root / "data"
        agg.run(config, self.data, retries=0, fetch=lambda url, *, timeout, max_bytes: PAYLOAD)

    def tearDown(self):
        self.tempdir.cleanup()

    def test_success_is_quiet(self):
        self.assertEqual(verify.main(["--data-dir", str(self.data), "--quiet"]), 0)

    def test_tamper_fails(self):
        (self.data / "subscriptions" / "global.txt").write_text("")
        self.assertEqual(verify.main(["--data-dir", str(self.data)]), 1)

    def test_missing_data_fails(self):
        self.assertEqual(verify.main(["--data-dir", str(self.root / "missing"), "--quiet"]), 1)


if __name__ == "__main__":
    unittest.main()
