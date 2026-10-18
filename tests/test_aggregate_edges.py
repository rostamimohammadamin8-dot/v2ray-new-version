"""Edge-case and CLI tests for the aggregation orchestrator."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import aggregate as agg  # noqa: E402

UID = "77777777-7777-7777-7777-777777777777"
VALID = f"vless://{UID}@de.example.com:443?security=tls#DE\n".encode()


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.path = self.root / "sources.json"

    def tearDown(self):
        self.tempdir.cleanup()

    def write(self, payload):
        self.path.write_text(payload if isinstance(payload, str) else json.dumps(payload))

    def test_missing_and_invalid_files(self):
        with self.assertRaises(agg.AggregationError):
            agg.load_sources(self.root / "missing.json")
        self.write("not json")
        with self.assertRaises(agg.AggregationError):
            agg.load_sources(self.path)

    def test_shape_errors(self):
        payloads = [
            [],
            {"version": 2, "sources": []},
            {"version": 1, "sources": "nope"},
            {"version": 1, "sources": ["nope"]},
            {"version": 1, "sources": [{"enabled": True, "url": "https://a.example"}]},
            {"version": 1, "sources": [{"id": "a", "enabled": True}]},
            {"version": 1, "sources": [{"id": "a", "url": "http://a.example", "enabled": True}]},
            {
                "version": 1,
                "sources": [
                    {"id": "a", "url": "https://a.example", "enabled": True},
                    {"id": "a", "url": "https://b.example", "enabled": True},
                ],
            },
            {"version": 1, "sources": [{"id": "a", "url": "https://a.example", "enabled": False}]},
        ]
        for payload in payloads:
            with self.subTest(payload=payload):
                self.write(payload)
                with self.assertRaises(agg.AggregationError):
                    agg.load_sources(self.path)

    def test_valid_config_and_disabled_entries(self):
        self.write(
            {
                "version": 1,
                "sources": [
                    {"id": "a", "url": "https://a.example", "enabled": True},
                    {"id": "b", "url": "https://b.example", "enabled": False},
                ],
            }
        )
        specs = agg.load_sources(self.path)
        self.assertEqual([spec.id for spec in specs], ["a"])


class PayloadEdgeTests(unittest.TestCase):
    def test_base64_failures(self):
        with self.assertRaises(agg.SourceError):
            agg.parse_payload(b"A" * 32)  # base64-looking but invalid subscription
        with self.assertRaises(agg.SourceError):
            agg.parse_payload(b"# only comments\n")

    def test_node_limit_is_enforced(self):
        payload = ("vless://%s@h.example.com:443#A\n" % UID) * 3
        with mock.patch.object(agg, "MAX_NODES", 2):
            with self.assertRaises(agg.SourceError):
                agg.parse_payload(payload.encode())

    def test_fetch_input_guards(self):
        with self.assertRaises(agg.SourceError):
            agg.fetch_source("https://", timeout=1, max_bytes=10)
        with self.assertRaises(agg.SourceError):
            agg.fetch_source("https://example.com", timeout=1, max_bytes=0)

    def test_retry_exhaustion(self):
        calls = []

        def failing(url, *, timeout, max_bytes):
            calls.append(url)
            raise agg.SourceError("down")

        with mock.patch.object(agg.time, "sleep", return_value=None):
            with self.assertRaises(agg.SourceError):
                agg._fetch_with_retries(failing, "https://a", timeout=1, max_bytes=1, retries=2)
        self.assertEqual(len(calls), 3)

    def test_legacy_probe_handles_invalid_and_socket_errors(self):
        self.assertFalse(agg._probe("not-a-node", 0.01))
        with mock.patch.object(agg.socket, "create_connection", side_effect=OSError()):
            self.assertFalse(agg._probe(f"vless://{UID}@host.example:443#A", 0.01))
        with mock.patch.object(agg.socket, "create_connection") as connect:
            self.assertTrue(agg._probe(f"vless://{UID}@host.example:443#A", 0.01))
            connect.assert_called_once()


class RunEdgeTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.config = self.root / "sources.json"
        self.config.write_text(
            json.dumps({"version": 1, "sources": [{"id": "a", "url": "https://a.example", "enabled": True}]})
        )
        self.output = self.root / "data"

    def tearDown(self):
        self.tempdir.cleanup()

    def fetch(self, payload=VALID):
        return lambda url, *, timeout, max_bytes: payload

    def test_main_exit_codes(self):
        with mock.patch.object(agg, "run", return_value={"node_count": 1}):
            self.assertEqual(agg.main(["--config", str(self.config)]), 0)
        with mock.patch.object(agg, "run", side_effect=agg.AggregationError("x")):
            self.assertEqual(agg.main(["--config", str(self.config)]), 1)
        self.assertEqual(agg.main(["--timeout", "0"]), 2)
        self.assertEqual(agg.main(["--retries", "-1"]), 2)

    def test_ai_review_failure_is_non_fatal(self):
        with mock.patch.object(agg.ai_ops, "review_manifest", side_effect=agg.ai_ops.GatewayError("down")):
            manifest = agg.run(
                self.config,
                self.output,
                retries=0,
                ai_config=agg.ai_ops.GatewayConfig(),
                ai_review=True,
                fetch=self.fetch(),
            )
        self.assertEqual(manifest["node_count"], 1)

    def test_ai_diagnosis_failure_is_non_fatal(self):
        def bad_fetch(url, *, timeout, max_bytes):
            raise agg.SourceError("bad")

        with mock.patch.object(agg.ai_ops, "diagnose_failure", side_effect=agg.ai_ops.GatewayError("down")):
            with self.assertRaises(agg.SourceError):
                agg.run(
                    self.config,
                    self.output,
                    retries=0,
                    ai_config=agg.ai_ops.GatewayConfig(),
                    ai_diagnose=True,
                    fetch=bad_fetch,
                )

    def test_telemetry_write_failure_is_non_fatal(self):
        blocker = self.root / "blocker"
        blocker.write_text("x")
        manifest = agg.run(
            self.config,
            self.output,
            retries=0,
            telemetry_path=blocker / "nested" / "telemetry.jsonl",
            fetch=self.fetch(),
        )
        self.assertEqual(manifest["node_count"], 1)

    def test_stale_health_is_removed_when_disabled(self):
        self.output.mkdir(parents=True)
        (self.output / "health.json").write_text("{}")
        agg.run(self.config, self.output, retries=0, fetch=self.fetch())
        self.assertFalse((self.output / "health.json").exists())

    def test_ai_review_stdout_path(self):
        with mock.patch.object(agg.ai_ops, "review_manifest", return_value="review"):
            with self.assertLogs("aggregate", level="INFO") as logs:
                agg.run(
                    self.config,
                    self.output,
                    retries=0,
                    ai_config=agg.ai_ops.GatewayConfig(),
                    ai_review=True,
                    fetch=self.fetch(),
                )
        self.assertTrue(any("AI review" in line for line in logs.output))


if __name__ == "__main__":
    unittest.main()


class LegacyTcpCheckRunTests(unittest.TestCase):
    def test_tcp_check_does_not_publish_health_sidecar(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "sources.json"
            config.write_text(
                json.dumps({"version": 1, "sources": [{"id": "a", "url": "https://a.example", "enabled": True}]})
            )

            def fake_probe(nodes, **kwargs):
                return [
                    agg.health.ProbeResult(
                        node.fingerprint(), node.protocol, "GLOBAL", 0, True, False, False, 1.0, 70
                    )
                    for node in nodes
                ]

            with mock.patch.object(agg.health, "probe_nodes", side_effect=fake_probe):
                manifest = agg.run(
                    config,
                    root / "data",
                    retries=0,
                    tcp_check=True,
                    fetch=lambda url, **kwargs: VALID,
                )
            self.assertNotIn("health", manifest)
            self.assertFalse((root / "data" / "health.json").exists())
            self.assertEqual(manifest["tcp_reachable"], 1)
            self.assertEqual(agg.integrity.verify_outputs(root / "data"), [])
