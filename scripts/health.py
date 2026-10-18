"""Asynchronous TCP/TLS reachability and latency scoring.

A successful TCP connect only proves that an endpoint accepted a connection at
that instant; a TLS handshake only proves that a TLS peer responded. Neither
validates the proxy protocol, authentication, routing, or end-to-end integrity.
Results are therefore published as advisory telemetry, never as a guarantee.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Mapping, Sequence

from scripts.proxy_uri import ProxyNode, TLS_DEFAULT_SCHEMES

DEFAULT_TIMEOUT = 3.0
DEFAULT_CONCURRENCY = 32
MAX_CONCURRENCY = 64


@dataclass(frozen=True)
class ProbeSettings:
    timeout: float = DEFAULT_TIMEOUT
    tls: bool = True
    concurrency: int = DEFAULT_CONCURRENCY
    verify_tls: bool = False

    def normalized(self) -> "ProbeSettings":
        return ProbeSettings(
            timeout=max(0.1, min(float(self.timeout), 30.0)),
            tls=bool(self.tls),
            concurrency=max(1, min(int(self.concurrency), MAX_CONCURRENCY)),
            verify_tls=bool(self.verify_tls),
        )


@dataclass(frozen=True)
class ProbeResult:
    node_id: str
    protocol: str
    label: str
    confidence: int
    tcp_ok: bool
    tls_ok: bool
    tls_required: bool
    latency_ms: float | None
    score: int
    error: str | None = None

    @property
    def reachable(self) -> bool:
        if not self.tcp_ok:
            return False
        return self.tls_ok if self.tls_required else True

    def to_dict(self) -> dict:
        return {
            "id": self.node_id,
            "protocol": self.protocol,
            "label": self.label,
            "confidence": self.confidence,
            "tcp_ok": self.tcp_ok,
            "tls_ok": self.tls_ok,
            "tls_required": self.tls_required,
            "latency_ms": self.latency_ms,
            "score": self.score,
            "error": self.error,
        }


Connector = Callable[..., Awaitable[float]]


def _error_kind(exc: BaseException) -> str:
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return "timeout"
    if isinstance(exc, ssl.SSLError):
        return "tls_error"
    if isinstance(exc, socket.gaierror):
        return "dns_error"
    if isinstance(exc, ConnectionRefusedError):
        return "refused"
    if isinstance(exc, OSError):
        return "network_error"
    return "probe_error"


async def _tcp_connect(host: str, port: int, timeout: float) -> float:
    start = time.perf_counter()
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    elapsed = (time.perf_counter() - start) * 1000.0
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=min(timeout, 1.0))
    except (asyncio.TimeoutError, OSError):
        pass
    del reader
    return round(elapsed, 2)


async def _tls_connect(
    host: str,
    port: int,
    sni: str | None,
    timeout: float,
    verify: bool,
) -> float:
    context = ssl.create_default_context()
    if not verify:
        # Availability probe only: self-signed proxy certificates are common.
        # This deliberately does not assert certificate trust.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    server_hostname = sni or host
    start = time.perf_counter()
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=context, server_hostname=server_hostname),
        timeout=timeout,
    )
    elapsed = (time.perf_counter() - start) * 1000.0
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=min(timeout, 1.0))
    except (asyncio.TimeoutError, OSError):
        pass
    del reader
    return round(elapsed, 2)


def score_result(
    *, tcp_ok: bool, tls_ok: bool, tls_required: bool, latency_ms: float | None
) -> int:
    if not tcp_ok:
        return 0
    score = 60
    if tls_required:
        if tls_ok:
            score += 20
    else:
        score += 10 if tls_ok else 0
    if latency_ms is not None:
        if latency_ms <= 100:
            score += 20
        elif latency_ms <= 300:
            score += 14
        elif latency_ms <= 800:
            score += 8
        elif latency_ms <= 2000:
            score += 3
    return max(0, min(100, score))


async def probe_node(
    node: ProxyNode,
    label: str,
    confidence: int,
    settings: ProbeSettings,
    *,
    tcp_connector: Connector = _tcp_connect,
    tls_connector: Connector = _tls_connect,
) -> ProbeResult:
    settings = settings.normalized()
    tls_required = node.tls or node.protocol in TLS_DEFAULT_SCHEMES
    tcp_ok = False
    tls_ok = False
    latency: float | None = None
    error: str | None = None

    try:
        latency = await tcp_connector(node.host, node.port, settings.timeout)
        tcp_ok = True
    except (asyncio.CancelledError, KeyboardInterrupt):
        raise
    except Exception as exc:  # noqa: BLE001 - telemetry boundary
        error = _error_kind(exc)

    if tcp_ok and settings.tls and tls_required:
        try:
            tls_latency = await tls_connector(
                node.host, node.port, node.sni, settings.timeout, settings.verify_tls
            )
            tls_ok = True
            latency = max(latency or 0.0, tls_latency)
        except (asyncio.CancelledError, KeyboardInterrupt):
            raise
        except Exception as exc:  # noqa: BLE001 - telemetry boundary
            error = _error_kind(exc)

    return ProbeResult(
        node_id=node.fingerprint(),
        protocol=node.protocol,
        label=label,
        confidence=confidence,
        tcp_ok=tcp_ok,
        tls_ok=tls_ok,
        tls_required=tls_required,
        latency_ms=latency,
        score=score_result(
            tcp_ok=tcp_ok, tls_ok=tls_ok, tls_required=tls_required, latency_ms=latency
        ),
        error=error,
    )


async def _probe_all(
    nodes: Sequence[ProxyNode],
    labels: Mapping[str, str],
    confidences: Mapping[str, int],
    settings: ProbeSettings,
    tcp_connector: Connector,
    tls_connector: Connector,
) -> list[ProbeResult]:
    semaphore = asyncio.Semaphore(settings.concurrency)

    async def run(node: ProxyNode) -> ProbeResult:
        async with semaphore:
            return await probe_node(
                node,
                labels.get(node.uri, "GLOBAL"),
                confidences.get(node.uri, 0),
                settings,
                tcp_connector=tcp_connector,
                tls_connector=tls_connector,
            )

    return list(await asyncio.gather(*(run(node) for node in nodes)))


def probe_nodes(
    nodes: Sequence[ProxyNode],
    *,
    labels: Mapping[str, str] | None = None,
    confidences: Mapping[str, int] | None = None,
    settings: ProbeSettings | None = None,
    tcp_connector: Connector = _tcp_connect,
    tls_connector: Connector = _tls_connect,
) -> list[ProbeResult]:
    """Probe nodes concurrently and return results in input order."""

    if not nodes:
        return []
    resolved = (settings or ProbeSettings()).normalized()
    return asyncio.run(
        _probe_all(
            list(nodes),
            labels or {},
            confidences or {},
            resolved,
            tcp_connector,
            tls_connector,
        )
    )


def _percentile(values: Sequence[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((percentile / 100.0) * (len(ordered) - 1)))))
    return round(ordered[index], 2)


def summarize(results: Sequence[ProbeResult]) -> dict:
    checked = len(results)
    reachable = sum(1 for item in results if item.reachable)
    tcp_ok = sum(1 for item in results if item.tcp_ok)
    tls_ok = sum(1 for item in results if item.tls_ok)
    latencies = [item.latency_ms for item in results if item.latency_ms is not None]
    failures: dict[str, int] = {}
    for item in results:
        if item.error:
            failures[item.error] = failures.get(item.error, 0) + 1
    return {
        "checked": checked,
        "tcp_reachable": tcp_ok,
        "tls_reachable": tls_ok,
        "reachable": reachable,
        "average_score": round(sum(item.score for item in results) / checked, 1) if checked else 0,
        "median_latency_ms": _percentile(latencies, 50),
        "p95_latency_ms": _percentile(latencies, 95),
        "failures": dict(sorted(failures.items())),
    }


def build_document(
    results: Sequence[ProbeResult],
    settings: ProbeSettings,
    *,
    generated_at: str | None = None,
) -> dict:
    from datetime import datetime, timezone

    return {
        "version": 1,
        "generated_at_utc": generated_at
        or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "probe": {
            "timeout_seconds": settings.timeout,
            "tls": settings.tls,
            "verify_tls": settings.verify_tls,
            "concurrency": settings.concurrency,
        },
        "summary": summarize(results),
        "nodes": [item.to_dict() for item in results],
        "disclaimer": (
            "TCP/TLS reachability is an advisory endpoint check, not proof of a working "
            "proxy tunnel, authentication, location, or trust."
        ),
    }
