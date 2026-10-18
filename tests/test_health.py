"""Async health probe and scoring tests (no real network access)."""

from __future__ import annotations

import asyncio
import ssl
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import health  # noqa: E402
from scripts.proxy_uri import parse_node  # noqa: E402

UID = "33333333-3333-3333-3333-333333333333"
TLS_NODE = parse_node(f"vless://{UID}@de.example.com:443?security=tls#DE")
PLAIN_NODE = parse_node("hysteria2://pw@nl.example.com:443#NL")


class ScoringTests(unittest.TestCase):
    def test_settings_are_clamped(self):
        settings = health.ProbeSettings(timeout=999, concurrency=999, tls=True).normalized()
        self.assertLessEqual(settings.timeout, 30.0)
        self.assertLessEqual(settings.concurrency, health.MAX_CONCURRENCY)
        self.assertGreaterEqual(health.ProbeSettings(timeout=-1, concurrency=0).normalized().timeout, 0.1)

    def test_score_bands(self):
        self.assertEqual(health.score_result(tcp_ok=False, tls_ok=False, tls_required=True, latency_ms=None), 0)
        self.assertEqual(health.score_result(tcp_ok=True, tls_ok=True, tls_required=True, latency_ms=50), 100)
        self.assertEqual(health.score_result(tcp_ok=True, tls_ok=False, tls_required=True, latency_ms=50), 80)
        self.assertEqual(health.score_result(tcp_ok=True, tls_ok=False, tls_required=False, latency_ms=900), 63)

    def test_percentiles_and_summary(self):
        results = [
            health.ProbeResult("a", "vless", "DE", 80, True, True, True, 100.0, 100),
            health.ProbeResult("b", "vless", "US", 90, True, False, True, 300.0, 80, "tls_error"),
            health.ProbeResult("c", "ss", "GLOBAL", 0, False, False, False, None, 0, "timeout"),
        ]
        summary = health.summarize(results)
        self.assertEqual(summary["checked"], 3)
        self.assertEqual(summary["reachable"], 1)
        self.assertEqual(summary["tcp_reachable"], 2)
        self.assertEqual(summary["tls_reachable"], 1)
        self.assertEqual(summary["median_latency_ms"], 100.0)
        self.assertEqual(summary["failures"], {"timeout": 1, "tls_error": 1})
        self.assertEqual(summary["average_score"], 60.0)

    def test_document_has_no_uri(self):
        results = [health.ProbeResult("id", "vless", "DE", 50, True, True, True, 10.0, 100)]
        document = health.build_document(results, health.ProbeSettings(), generated_at="2026-01-01T00:00:00Z")
        self.assertEqual(document["version"], 1)
        self.assertNotIn("://", str(document))
        self.assertEqual(document["nodes"][0]["id"], "id")


class ProbeTests(unittest.IsolatedAsyncioTestCase):
    async def test_successful_tcp_and_tls(self):
        async def tcp(host, port, timeout):
            return 11.5

        async def tls(host, port, sni, timeout, verify):
            return 22.5

        result = await health.probe_node(
            TLS_NODE,
            "DE",
            80,
            health.ProbeSettings(tls=True),
            tcp_connector=tcp,
            tls_connector=tls,
        )
        self.assertTrue(result.tcp_ok)
        self.assertTrue(result.tls_ok)
        self.assertTrue(result.reachable)
        self.assertEqual(result.latency_ms, 22.5)
        self.assertEqual(result.score, 100)
        self.assertEqual(result.node_id, TLS_NODE.fingerprint())

    async def test_tcp_failure_is_categorized(self):
        async def tcp(host, port, timeout):
            raise ConnectionRefusedError()

        result = await health.probe_node(
            TLS_NODE, "DE", 80, health.ProbeSettings(), tcp_connector=tcp
        )
        self.assertFalse(result.tcp_ok)
        self.assertFalse(result.reachable)
        self.assertEqual(result.error, "refused")
        self.assertEqual(result.score, 0)

    async def test_tls_failure_is_categorized(self):
        async def tcp(host, port, timeout):
            return 5.0

        async def tls(host, port, sni, timeout, verify):
            raise ssl.SSLError("handshake failed")

        result = await health.probe_node(
            TLS_NODE,
            "DE",
            80,
            health.ProbeSettings(tls=True),
            tcp_connector=tcp,
            tls_connector=tls,
        )
        self.assertTrue(result.tcp_ok)
        self.assertFalse(result.tls_ok)
        self.assertFalse(result.reachable)
        self.assertEqual(result.error, "tls_error")

    async def test_timeout_and_dns_errors(self):
        async def slow(host, port, timeout):
            raise asyncio.TimeoutError()

        result = await health.probe_node(
            PLAIN_NODE, "NL", 50, health.ProbeSettings(), tcp_connector=slow
        )
        self.assertEqual(result.error, "timeout")

        async def dns(host, port, timeout):
            import socket

            raise socket.gaierror("no host")

        result = await health.probe_node(
            PLAIN_NODE, "NL", 50, health.ProbeSettings(), tcp_connector=dns
        )
        self.assertEqual(result.error, "dns_error")


class BatchTests(unittest.TestCase):
    def test_batch_preserves_order_and_bounds_concurrency(self):
        active = 0
        peak = 0

        async def tcp(host, port, timeout):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.002)
            active -= 1
            return 1.0

        nodes = [parse_node(f"vless://{UID}@h{i}.example.com:443#N{i}") for i in range(8)]
        results = health.probe_nodes(
            nodes,
            settings=health.ProbeSettings(tls=False, concurrency=2),
            tcp_connector=tcp,
        )
        self.assertEqual([item.node_id for item in results], [node.fingerprint() for node in nodes])
        self.assertLessEqual(peak, 2)

    def test_empty_batch(self):
        self.assertEqual(health.probe_nodes([]), [])


if __name__ == "__main__":
    unittest.main()


class ConnectorTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_tcp_connect_to_loopback(self):
        async def handler(reader, writer):
            writer.close()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            latency = await health._tcp_connect("127.0.0.1", port, 1.0)
            self.assertGreaterEqual(latency, 0)
        finally:
            server.close()
            await server.wait_closed()

    async def test_connector_failure_is_os_error(self):
        with self.assertRaises(OSError):
            await health._tcp_connect("127.0.0.1", 1, 0.2)


class ErrorKindTests(unittest.TestCase):
    def test_error_categories(self):
        import socket

        self.assertEqual(health._error_kind(OSError()), "network_error")
        self.assertEqual(health._error_kind(RuntimeError()), "probe_error")
        self.assertEqual(health._error_kind(socket.gaierror()), "dns_error")
        self.assertEqual(health._error_kind(ssl.SSLError()), "tls_error")

    def test_more_score_bands(self):
        self.assertEqual(health.score_result(tcp_ok=True, tls_ok=True, tls_required=True, latency_ms=200), 94)
        self.assertEqual(health.score_result(tcp_ok=True, tls_ok=True, tls_required=True, latency_ms=500), 88)
        self.assertEqual(health.score_result(tcp_ok=True, tls_ok=True, tls_required=True, latency_ms=1500), 83)
        self.assertEqual(health.score_result(tcp_ok=True, tls_ok=True, tls_required=True, latency_ms=5000), 80)
