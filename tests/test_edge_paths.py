"""Small branch tests for defensive and telemetry paths."""

from __future__ import annotations

import argparse
import asyncio
import json
import ssl
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import aggregate as agg  # noqa: E402
from scripts import health  # noqa: E402
from scripts import proxy_uri as pu  # noqa: E402

UID = "88888888-8888-8888-8888-888888888888"
VALID = f"vless://{UID}@de.example.com:443?security=tls#DE\n".encode()


class _Response:
    def __init__(self, url="https://example.com/sub", body=b""):
        self._url = url
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def geturl(self):
        return self._url

    def read(self, size=-1):
        return self._body


class FetchBranches(unittest.TestCase):
    def test_redirect_handler_allows_https(self):
        handler = agg._HttpsOnlyRedirectHandler()
        request = urllib.request.Request("https://example.com/a")
        result = handler.redirect_request(request, None, 302, "Found", {}, "https://example.com/b")
        self.assertIsNotNone(result)

    def test_fetch_redirect_and_network_errors(self):
        with mock.patch.object(
            agg._HTTPS_ONLY_OPENER, "open", return_value=_Response("http://example.com/sub")
        ):
            with self.assertRaises(agg.SourceError):
                agg.fetch_source("https://example.com/sub", timeout=1, max_bytes=100)
        with mock.patch.object(
            agg._HTTPS_ONLY_OPENER, "open", side_effect=urllib.error.URLError("down")
        ):
            with self.assertRaises(agg.SourceError):
                agg.fetch_source("https://example.com/sub", timeout=1, max_bytes=100)
        with mock.patch.object(
            agg._HTTPS_ONLY_OPENER, "open", side_effect=agg.SourceError("inner")
        ):
            with self.assertRaises(agg.SourceError):
                agg.fetch_source("https://example.com/sub", timeout=1, max_bytes=100)

    def test_base64_edge_paths(self):
        with self.assertRaises(ValueError):
            agg._b64decode("")
        with self.assertRaises(agg.SourceError):
            agg.parse_payload(b"A" * 32)
        with self.assertRaises(agg.SourceError):
            agg.parse_payload(b"A" * 15 + b"=")

    def test_second_last_host_label_and_empty_name(self):
        self.assertEqual(agg.classify_country(f"vless://{UID}@us.de:443#"), "US")
        self.assertEqual(agg.classify_country("vless://bad@host.example:443#"), "GLOBAL")


class AggregateBranches(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)

    def tearDown(self):
        self.tempdir.cleanup()

    def spec(self, name="a"):
        return agg.SourceSpec(name, f"https://{name}.example/sub")

    def test_node_limit_across_sources(self):
        payloads = {
            "https://a.example/sub": f"vless://{UID}@a.example.com:443#A\n".encode(),
            "https://b.example/sub": f"vless://{UID}@b.example.com:443#B\n".encode(),
        }
        with mock.patch.object(agg, "MAX_NODES", 1):
            with self.assertRaises(agg.AggregationError):
                agg.aggregate(
                    [self.spec("a"), self.spec("b")],
                    fetch=lambda url, **kwargs: payloads[url],
                )

    def test_require_reachable_can_remove_everything(self):
        def fake_probe(nodes, **kwargs):
            return [
                health.ProbeResult(
                    node.fingerprint(), node.protocol, "GLOBAL", 0, False, False, False, None, 0, "refused"
                )
                for node in nodes
            ]

        with mock.patch.object(agg.health, "probe_nodes", side_effect=fake_probe):
            with self.assertRaises(agg.AggregationError):
                agg.aggregate(
                    [self.spec()],
                    tcp_check=True,
                    require_reachable=True,
                    fetch=lambda url, **kwargs: VALID,
                )

    def test_telemetry_none_and_rotation(self):
        agg._append_telemetry(None, "noop")
        path = self.root / "telemetry.jsonl"
        path.write_bytes(b"x" * (2 * 1024 * 1024 + 1))
        agg._append_telemetry(path, "rotated", value=1)
        self.assertTrue(path.with_suffix(".jsonl.1").exists())
        self.assertIn("rotated", path.read_text())

    def test_ai_text_noop_and_write_failure(self):
        agg._publish_ai_text(None, None)
        blocker = self.root / "blocker"
        blocker.write_text("x")
        agg._publish_ai_text("text", blocker / "nested" / "out.txt")

    def test_gateway_config_override(self):
        args = argparse.Namespace(ai_model="m", ai_base_url="http://localhost:9/")
        config = agg._gateway_config(args)
        self.assertEqual(config.base_url, "http://localhost:9")
        self.assertEqual(config.model, "m")

    def test_integrity_error_is_wrapped(self):
        config = self.root / "sources.json"
        config.write_text(
            json.dumps({"version": 1, "sources": [{"id": "a", "url": "https://a.example", "enabled": True}]})
        )
        with mock.patch.object(agg, "write_outputs", side_effect=agg.integrity.IntegrityError("bad")):
            with self.assertRaises(agg.AggregationError):
                agg.run(config, self.root / "data", retries=0, fetch=lambda url, **kwargs: VALID)


class HealthBranches(unittest.IsolatedAsyncioTestCase):
    async def test_tls_connector_with_fake_connection(self):
        class Writer:
            def close(self):
                pass

            async def wait_closed(self):
                pass

        async def fake_open(*args, **kwargs):
            return object(), Writer()

        with mock.patch.object(asyncio, "open_connection", side_effect=fake_open):
            latency = await health._tls_connect("example.com", 443, "example.com", 1, False)
        self.assertGreaterEqual(latency, 0)

    async def test_cancellation_propagates(self):
        async def cancelled(host, port, timeout):
            raise asyncio.CancelledError()

        node = pu.parse_node(f"vless://{UID}@host.example:443#x")
        with self.assertRaises(asyncio.CancelledError):
            await health.probe_node(node, "GLOBAL", 0, health.ProbeSettings(), tcp_connector=cancelled)

    def test_empty_summary(self):
        self.assertEqual(health.summarize([])["checked"], 0)
        self.assertIsNone(health._percentile([], 50))


class ProxyBranches(unittest.TestCase):
    def test_vmess_plaintext_warning(self):
        import base64

        data = {"add": "host.example", "port": 443, "id": UID, "ps": "x", "tls": "none"}
        uri = "vmess://" + base64.b64encode(json.dumps(data).encode()).decode()
        self.assertIn("plaintext_transport", pu.parse_node(uri).warnings)

    def test_ss_invalid_legacy_and_method(self):
        import base64

        for decoded in (b"no-at-sign", b"aes-256-gcm:pw@host:443"):
            uri = "ss://" + base64.b64encode(decoded).decode()
            if decoded == b"no-at-sign":
                with self.assertRaises(pu.NodeValidationError):
                    pu.parse_node(uri)
        with self.assertRaises(pu.NodeValidationError):
            pu.parse_node("ss://!bad!:pw@host:443#x")

    def test_generic_missing_host(self):
        with self.assertRaises(pu.NodeValidationError):
            pu.parse_node("socks5://user:pass@:1080#x")

    def test_wrapper_validation(self):
        pu.validate_node_uri(f"vless://{UID}@host.example:443#x")

    def test_node_name_never_raises_on_bad_brackets(self):
        self.assertEqual(pu.node_name("vless://[bad"), "")


if __name__ == "__main__":
    unittest.main()


class MoreBranchTests(unittest.TestCase):
    def test_host_total_length(self):
        with self.assertRaises(pu.NodeValidationError):
            pu._validate_host(".".join(["a"] * 128))

    def test_ss_extra_invalid_forms(self):
        import base64

        with self.assertRaises(pu.NodeValidationError):
            pu.parse_node("ss://!!!!")
        uri = "ss://" + base64.b64encode(b"nocolon").decode() + "@host.example:443"
        with self.assertRaises(pu.NodeValidationError):
            pu.parse_node(uri)

    def test_sanitize_fallback_object(self):
        from scripts import ai_ops

        self.assertIsInstance(ai_ops.sanitize(object()), str)

    def test_probe_waits_closed_error_is_ignored(self):
        class Writer:
            def close(self):
                pass

            async def wait_closed(self):
                raise OSError()

        async def fake_open(*args, **kwargs):
            return object(), Writer()

        async def run():
            with mock.patch.object(asyncio, "open_connection", side_effect=fake_open):
                return await health._tcp_connect("host", 443, 1)

        self.assertGreaterEqual(asyncio.run(run()), 0)

    def test_tls_cancellation_propagates(self):
        async def tcp(host, port, timeout):
            return 1.0

        async def tls(host, port, sni, timeout, verify):
            raise asyncio.CancelledError()

        async def run():
            node = pu.parse_node(f"vless://{UID}@host.example:443?security=tls#x")
            await health.probe_node(
                node, "GLOBAL", 0, health.ProbeSettings(), tcp_connector=tcp, tls_connector=tls
            )

        with self.assertRaises(asyncio.CancelledError):
            asyncio.run(run())


class FinalBranchTests(unittest.TestCase):
    def test_looks_like_base64_rejects_bad_chars(self):
        self.assertFalse(agg._looks_like_base64("=" * 16))

    def test_base64_branches(self):
        import base64

        with mock.patch.object(agg, "_looks_like_base64", return_value=True):
            with mock.patch.object(agg, "_b64decode", side_effect=ValueError("bad")):
                with self.assertRaises(agg.SourceError):
                    agg.parse_payload(b"anything")
        with self.assertRaises(agg.SourceError):
            agg.parse_payload(base64.b64encode(b"# comment\n"))

    def test_stale_health_removal_failure_is_logged(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "sources.json"
            config.write_text(
                json.dumps({"version": 1, "sources": [{"id": "a", "url": "https://a.example", "enabled": True}]})
            )
            output = root / "data"
            output.mkdir()
            (output / "health.json").mkdir()
            with self.assertLogs("aggregate", level="WARNING") as logs:
                agg.run(config, output, retries=0, fetch=lambda url, **kwargs: VALID)
            self.assertTrue(any("stale health.json" in line for line in logs.output))

    def test_verify_or_raise_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data = root / "data"
            data.mkdir()
            (data / "manifest.json").write_text("{}")
            with self.assertRaises(agg.integrity.IntegrityError):
                agg.integrity.verify_or_raise(data)

    def test_tls_wait_closed_error_is_ignored(self):
        class Writer:
            def close(self):
                pass

            async def wait_closed(self):
                raise OSError()

        async def fake_open(*args, **kwargs):
            return object(), Writer()

        async def run():
            with mock.patch.object(asyncio, "open_connection", side_effect=fake_open):
                return await health._tls_connect("host", 443, None, 1, True)

        self.assertGreaterEqual(asyncio.run(run()), 0)
