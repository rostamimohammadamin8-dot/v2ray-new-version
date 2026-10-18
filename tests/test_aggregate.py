"""Unit tests for scripts/aggregate.py (stdlib only)."""

from __future__ import annotations

import base64
import io
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


def vmess_uri(name: str, host: str, port: int = 443) -> str:
    data = {
        "v": "2",
        "ps": name,
        "add": host,
        "port": str(port),
        "id": "11111111-1111-1111-1111-111111111111",
        "aid": "0",
        "net": "ws",
        "type": "none",
        "host": "",
        "path": "/",
        "tls": "tls",
    }
    encoded = base64.b64encode(json.dumps(data).encode("utf-8")).decode("ascii")
    return f"vmess://{encoded}"


SAMPLE = "\n".join(
    [
        "# comment",
        "vless://00000000-0000-0000-0000-000000000001@frankfurt.example.de:443#DE%20Frankfurt",
        "vless://00000000-0000-0000-0000-000000000001@frankfurt.example.de:443#DE%20Frankfurt",
        "trojan://pw@london.example.com:8443#UK%20London",
        "hysteria2://pw@1.2.3.4:443#NL%20node",
        vmess_uri("US node", "us.example.com"),
        "ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388#Tokyo",
        "// another comment",
        "",
    ]
)


class PayloadTests(unittest.TestCase):
    def test_plain_uri_list_dedupes_and_ignores_comments(self):
        nodes = agg.parse_payload(SAMPLE.encode("utf-8"))
        self.assertEqual(len(nodes), 5)
        self.assertEqual(sum(1 for node in nodes if node.startswith("vless://")), 1)

    def test_crlf_and_bom_are_normalized(self):
        payload = "\ufeffvless://00000000-0000-0000-0000-000000000001@host.example:443#X\r\nvless://00000000-0000-0000-0000-000000000001@host.example:443#X\r\n"
        nodes = agg.parse_payload(payload.encode("utf-8"))
        self.assertEqual(nodes, ["vless://00000000-0000-0000-0000-000000000001@host.example:443#X"])

    def test_base64_subscription_is_decoded(self):
        encoded = base64.b64encode(SAMPLE.encode("utf-8"))
        self.assertEqual(agg.parse_payload(encoded), agg.parse_payload(SAMPLE.encode("utf-8")))

    def test_urlsafe_base64_without_padding(self):
        encoded = base64.urlsafe_b64encode(SAMPLE.encode("utf-8")).decode("ascii").rstrip("=")
        self.assertEqual(len(agg.parse_payload(encoded.encode("ascii"))), 5)

    def test_invalid_utf8_is_rejected(self):
        with self.assertRaises(agg.SourceError):
            agg.parse_payload(b"vless://00000000-0000-0000-0000-000000000001@host:443#\xff")

    def test_malformed_line_rejects_whole_payload(self):
        payload = SAMPLE + "\nftp://example.com/file\n"
        with self.assertRaises(agg.SourceError):
            agg.parse_payload(payload.encode("utf-8"))

    def test_empty_payload_is_rejected(self):
        with self.assertRaises(agg.SourceError):
            agg.parse_payload(b"")

    def test_unsupported_scheme_is_rejected(self):
        with self.assertRaises(ValueError):
            agg.validate_node_uri("ftp://example.com:21")


class CountryTests(unittest.TestCase):
    def test_remark_hints(self):
        cases = {
            "vless://00000000-0000-0000-0000-000000000001@a.example.com:443#Germany%20Frankfurt": "DE",
            "vless://00000000-0000-0000-0000-000000000001@a.example.com:443#US%20New%20York": "US",
            "vless://00000000-0000-0000-0000-000000000001@a.example.com:443#Amsterdam%20NL": "NL",
            "vless://00000000-0000-0000-0000-000000000001@a.example.com:443#Istanbul%20TR": "TR",
            "vless://00000000-0000-0000-0000-000000000001@a.example.com:443#France%20Paris": "FR",
            "vless://00000000-0000-0000-0000-000000000001@a.example.com:443#United%20Kingdom%20London": "UK",
            "vless://00000000-0000-0000-0000-000000000001@a.example.com:443#Toronto%20Canada": "CA",
        }
        for uri, expected in cases.items():
            with self.subTest(uri=uri):
                self.assertEqual(agg.classify_country(uri), expected)

    def test_flags_and_hostname_tld(self):
        self.assertEqual(agg.classify_country("vless://00000000-0000-0000-0000-000000000001@node.de:443#\U0001F1E9\U0001F1EA"), "DE")
        self.assertEqual(agg.classify_country("vless://00000000-0000-0000-0000-000000000001@node.example.nl:443#Fast"), "NL")

    def test_unknown_and_ambiguous_fall_back_to_global(self):
        self.assertEqual(agg.classify_country("vless://00000000-0000-0000-0000-000000000001@node.example.com:443#Mystery"), "GLOBAL")
        self.assertEqual(
            agg.classify_country("vless://00000000-0000-0000-0000-000000000001@node.example.com:443#DE%20US"),
            "GLOBAL",
        )

    def test_country_code_does_not_match_inside_words(self):
        # "speed" contains "de" but must not be treated as Germany.
        self.assertEqual(agg.classify_country("vless://00000000-0000-0000-0000-000000000001@a.example.com:443#Speed%20test"), "GLOBAL")


class EndpointTests(unittest.TestCase):
    def test_vless_and_trojan_endpoints(self):
        self.assertEqual(agg.node_endpoint("vless://00000000-0000-0000-0000-000000000001@1.2.3.4:443?x=1#n"), ("1.2.3.4", 443))
        self.assertEqual(agg.node_endpoint("trojan://pw@host.example:8443#n"), ("host.example", 8443))

    def test_vmess_endpoint_and_name(self):
        uri = vmess_uri("DE node", "de.example.com", 8080)
        self.assertEqual(agg.node_endpoint(uri), ("de.example.com", 8080))
        self.assertEqual(agg.node_name(uri), "DE node")

    def test_legacy_ss_endpoint(self):
        userinfo = base64.b64encode(b"aes-256-gcm:password").decode("ascii")
        uri = f"ss://{userinfo}@1.2.3.4:8388#Node"
        self.assertEqual(agg.node_endpoint(uri), ("1.2.3.4", 8388))

    def test_invalid_vmess_is_rejected(self):
        with self.assertRaises(ValueError):
            agg.validate_node_uri("vmess://not-base64!")

    def test_ss_without_credentials_is_rejected(self):
        with self.assertRaises(ValueError):
            agg.validate_node_uri("ss://@1.2.3.4:8388#empty")

    def test_https_redirect_handler_rejects_downgrade(self):
        handler = agg._HttpsOnlyRedirectHandler()
        with self.assertRaises(agg.urllib.error.URLError):
            handler.redirect_request(None, None, 302, "Found", {}, "http://example.com/sub")


class FakeResponse:
    def __init__(self, payload: bytes, url: str = "https://example.com/sub"):
        self._stream = io.BytesIO(payload)
        self._url = url

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def geturl(self):
        return self._url

    def read(self, size: int = -1):
        return self._stream.read(size)


class FetchTests(unittest.TestCase):
    def test_non_https_is_rejected(self):
        with self.assertRaises(agg.SourceError):
            agg.fetch_source("http://example.com/sub", timeout=1, max_bytes=1024)

    def test_size_limit_is_enforced(self):
        payload = b"a" * 2048
        with mock.patch.object(agg._HTTPS_ONLY_OPENER, "open", return_value=FakeResponse(payload)):
            with self.assertRaises(agg.SourceError):
                agg.fetch_source("https://example.com/sub", timeout=1, max_bytes=1024)

    def test_empty_payload_is_rejected(self):
        with mock.patch.object(agg._HTTPS_ONLY_OPENER, "open", return_value=FakeResponse(b"")):
            with self.assertRaises(agg.SourceError):
                agg.fetch_source("https://example.com/sub", timeout=1, max_bytes=1024)

    def test_payload_at_limit_is_accepted(self):
        payload = b"a" * 1024
        with mock.patch.object(agg._HTTPS_ONLY_OPENER, "open", return_value=FakeResponse(payload)):
            self.assertEqual(
                agg.fetch_source("https://example.com/sub", timeout=1, max_bytes=1024), payload
            )


class AggregateTests(unittest.TestCase):
    def test_sources_are_deduplicated_across_sources(self):
        specs = [agg.SourceSpec("a", "https://a.example/sub"), agg.SourceSpec("b", "https://b.example/sub")]
        payloads = {
            "https://a.example/sub": SAMPLE.encode("utf-8"),
            "https://b.example/sub": b"vless://00000000-0000-0000-0000-000000000001@frankfurt.example.de:443#DE%20Frankfurt\nvless://00000000-0000-0000-0000-000000000002@host:443#Z\n",
        }

        def fake_fetch(url, *, timeout, max_bytes):
            return payloads[url]

        result = agg.aggregate(specs, fetch=fake_fetch)
        self.assertEqual(len(result.nodes), 6)
        self.assertEqual(result.source_results[0].node_count, 5)
        self.assertEqual(result.source_results[1].node_count, 1)
        self.assertEqual(result.labels[result.nodes[-1]], "GLOBAL")

    def test_tcp_check_can_filter_unreachable_nodes(self):
        specs = [agg.SourceSpec("a", "https://a.example/sub")]

        def fake_fetch(url, *, timeout, max_bytes):
            return SAMPLE.encode("utf-8")

        def fake_probe_nodes(nodes, *, labels=None, confidences=None, settings=None, **kwargs):
            results = []
            for node in nodes:
                ok = "london" in node.name.lower()
                results.append(
                    agg.health.ProbeResult(
                        node_id=node.fingerprint(),
                        protocol=node.protocol,
                        label=(labels or {}).get(node.uri, "GLOBAL"),
                        confidence=(confidences or {}).get(node.uri, 0),
                        tcp_ok=ok,
                        tls_ok=False,
                        tls_required=False,
                        latency_ms=12.0 if ok else None,
                        score=70 if ok else 0,
                    )
                )
            return results

        with mock.patch.object(agg.health, "probe_nodes", side_effect=fake_probe_nodes):
            result = agg.aggregate(specs, fetch=fake_fetch, tcp_check=True, require_reachable=True)
        self.assertEqual(len(result.nodes), 1)
        self.assertEqual(agg.node_name(result.nodes[0]), "UK London")
        self.assertEqual(result.tcp_checked, 5)
        self.assertEqual(result.tcp_reachable, 1)

    def test_failed_source_aborts_run(self):
        specs = [agg.SourceSpec("bad", "https://bad.example/sub")]

        def fake_fetch(url, *, timeout, max_bytes):
            raise agg.SourceError("boom")

        with self.assertRaises(agg.SourceError):
            agg.aggregate(specs, fetch=fake_fetch)


class OutputTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.config = self.root / "sources.json"
        self.output = self.root / "data"

    def tearDown(self):
        self.tempdir.cleanup()

    def write_config(self, sources):
        self.config.write_text(
            json.dumps({"version": 1, "sources": sources}), encoding="utf-8"
        )

    def fake_fetch(self, payloads):
        def fetch(url, *, timeout, max_bytes):
            return payloads[url]

        return fetch

    def test_run_writes_every_feed_manifest_and_snapshot(self):
        self.write_config([{"id": "a", "url": "https://a.example/sub", "enabled": True}])
        manifest = agg.run(
            self.config,
            self.output,
            fetch=self.fake_fetch({"https://a.example/sub": SAMPLE.encode("utf-8")}),
        )

        for label in agg.FEED_LABELS:
            path = self.output / "subscriptions" / f"{label.lower()}.txt"
            self.assertTrue(path.exists(), path)
            path.read_text(encoding="utf-8")

        global_lines = (self.output / "subscriptions" / "global.txt").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(global_lines), 5)
        self.assertEqual(len(set(global_lines)), 5)
        de_lines = (self.output / "subscriptions" / "de.txt").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(de_lines), 1)
        self.assertIn("frankfurt", de_lines[0].lower())
        self.assertEqual(
            (self.output / "snapshot" / "global.txt").read_text(encoding="utf-8"),
            (self.output / "subscriptions" / "global.txt").read_text(encoding="utf-8"),
        )

        on_disk = json.loads((self.output / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(on_disk, manifest)
        self.assertEqual(on_disk["node_count"], 5)
        self.assertEqual(on_disk["source_count"], 1)
        self.assertEqual(on_disk["feeds"]["GLOBAL"], "subscriptions/global.txt")
        self.assertEqual(on_disk["counts"]["GLOBAL"], 5)
        self.assertEqual(on_disk["snapshot"], "snapshot/global.txt")
        self.assertNotIn("https://a.example/sub", json.dumps(on_disk))

    def test_failed_run_preserves_previous_outputs(self):
        self.write_config([{"id": "a", "url": "https://a.example/sub", "enabled": True}])
        agg.run(
            self.config,
            self.output,
            fetch=self.fake_fetch({"https://a.example/sub": SAMPLE.encode("utf-8")}),
        )
        before = {
            path: path.read_bytes()
            for path in self.output.rglob("*")
            if path.is_file()
        }

        self.write_config(
            [
                {"id": "a", "url": "https://a.example/sub", "enabled": True},
                {"id": "bad", "url": "https://bad.example/sub", "enabled": True},
            ]
        )

        def failing_fetch(url, *, timeout, max_bytes):
            if url == "https://bad.example/sub":
                raise agg.SourceError("unreachable")
            return SAMPLE.encode("utf-8")

        with self.assertRaises(agg.SourceError):
            agg.run(self.config, self.output, fetch=failing_fetch)

        after = {
            path: path.read_bytes()
            for path in self.output.rglob("*")
            if path.is_file()
        }
        self.assertEqual(before, after)

    def test_disabled_sources_are_skipped(self):
        self.write_config(
            [
                {"id": "a", "url": "https://a.example/sub", "enabled": False},
            ]
        )
        with self.assertRaises(agg.AggregationError):
            agg.run(self.config, self.output, fetch=self.fake_fetch({}))

    def test_non_https_config_is_rejected(self):
        self.write_config([{"id": "a", "url": "http://a.example/sub", "enabled": True}])
        with self.assertRaises(agg.AggregationError):
            agg.load_sources(self.config)


if __name__ == "__main__":
    unittest.main()


class AdvancedRunTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.config = self.root / "sources.json"
        self.output = self.root / "data"
        self.telemetry = self.root / "telemetry.jsonl"
        self.config.write_text(
            json.dumps({"version": 1, "sources": [{"id": "a", "url": "https://a.example/sub", "enabled": True}]}),
            encoding="utf-8",
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def fake_fetch(self, payload: bytes = SAMPLE.encode("utf-8")):
        return lambda url, *, timeout, max_bytes: payload

    def test_health_check_publishes_checksummed_sidecar(self):
        def fake_probe_nodes(nodes, *, labels=None, confidences=None, settings=None, **kwargs):
            return [
                agg.health.ProbeResult(
                    node_id=node.fingerprint(),
                    protocol=node.protocol,
                    label=(labels or {}).get(node.uri, "GLOBAL"),
                    confidence=(confidences or {}).get(node.uri, 0),
                    tcp_ok=True,
                    tls_ok=node.tls,
                    tls_required=node.tls,
                    latency_ms=42.0,
                    score=95,
                )
                for node in nodes
            ]

        with mock.patch.object(agg.health, "probe_nodes", side_effect=fake_probe_nodes):
            manifest = agg.run(
                self.config,
                self.output,
                retries=0,
                health_check=True,
                fetch=self.fake_fetch(),
            )
        self.assertEqual(manifest["health"]["checked"], 5)
        self.assertEqual(manifest["health"]["reachable"], 5)
        self.assertTrue((self.output / "health.json").exists())
        self.assertIn("health.json", manifest["checksums"])
        self.assertEqual(agg.integrity.verify_outputs(self.output), [])
        self.assertIn("plaintext_transport", manifest["warnings"])
        self.assertGreater(manifest["label_confidence"]["average"], 0)

    def test_transient_failure_is_retried(self):
        calls = []

        def flaky(url, *, timeout, max_bytes):
            calls.append(url)
            if len(calls) == 1:
                raise agg.SourceError("temporary")
            return SAMPLE.encode("utf-8")

        with mock.patch.object(agg.time, "sleep", return_value=None):
            manifest = agg.run(self.config, self.output, retries=1, fetch=flaky)
        self.assertEqual(len(calls), 2)
        self.assertEqual(manifest["sources"][0]["attempts"], 2)

    def test_ai_review_and_telemetry_are_optional_and_sanitized(self):
        review_path = self.root / "review.txt"
        with mock.patch.object(agg.ai_ops, "review_manifest", return_value="safe review"):
            manifest = agg.run(
                self.config,
                self.output,
                retries=0,
                ai_config=agg.ai_ops.GatewayConfig(),
                ai_review=True,
                ai_output=review_path,
                telemetry_path=self.telemetry,
                fetch=self.fake_fetch(),
            )
        self.assertEqual(review_path.read_text(), "safe review\n")
        event = json.loads(self.telemetry.read_text().splitlines()[0])
        self.assertEqual(event["event"], "aggregation_succeeded")
        self.assertEqual(event["node_count"], manifest["node_count"])
        self.assertNotIn("://", self.telemetry.read_text())

    def test_ai_diagnosis_does_not_mask_failure(self):
        diagnosis = self.root / "diagnosis.txt"

        def bad_fetch(url, *, timeout, max_bytes):
            raise agg.SourceError("upstream unavailable")

        with mock.patch.object(agg.ai_ops, "diagnose_failure", return_value="try later") as diagnose:
            with self.assertRaises(agg.SourceError):
                agg.run(
                    self.config,
                    self.output,
                    retries=0,
                    ai_config=agg.ai_ops.GatewayConfig(),
                    ai_diagnose=True,
                    ai_output=diagnosis,
                    telemetry_path=self.telemetry,
                    fetch=bad_fetch,
                )
        diagnose.assert_called_once()
        self.assertEqual(diagnosis.read_text(), "try later\n")
        self.assertEqual(json.loads(self.telemetry.read_text().splitlines()[0])["event"], "aggregation_failed")
        self.assertFalse((self.output / "manifest.json").exists())
