#!/usr/bin/env python3
"""Transactional multi-source proxy subscription aggregator.

Pipeline: fetch (HTTPS only, bounded) -> strict parse/validate -> deduplicate ->
label -> optional async TCP/TLS health probe -> checksummed staging -> verify ->
atomic publish. Any failure exits non-zero without touching published state.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import logging
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scripts import ai_ops, health, integrity, proxy_uri  # noqa: E402

LOGGER = logging.getLogger("aggregate")

DEFAULT_CONFIG_PATH = Path("config/sources.json")
DEFAULT_OUTPUT_DIR = Path("data")
DEFAULT_TIMEOUT = 15.0
DEFAULT_MAX_BYTES = 5 * 1024 * 1024
DEFAULT_TCP_TIMEOUT = 3.0
DEFAULT_RETRIES = 2
MAX_NODES = 10000
MANIFEST_VERSION = 1

COUNTRIES: tuple[str, ...] = ("DE", "US", "NL", "TR", "FR", "UK", "CA")
GLOBAL_LABEL = "GLOBAL"
FEED_LABELS: tuple[str, ...] = (GLOBAL_LABEL, *COUNTRIES)
SUPPORTED_SCHEMES = proxy_uri.SUPPORTED_SCHEMES  # backwards-compatible re-export

_COMMENT_PREFIXES = ("#", "//", ";")
_USER_AGENT = "v2ray-subscription-aggregator/2.0 (+https://github.com/)"


class AggregationError(Exception):
    """Raised when a run must stop without publishing new output."""


class SourceError(AggregationError):
    """Raised when an individual subscription source is unusable."""


class _HttpsOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme.lower() != "https":
            raise urllib.error.URLError("refusing non-HTTPS redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_HTTPS_ONLY_OPENER = urllib.request.build_opener(_HttpsOnlyRedirectHandler())


@dataclass(frozen=True)
class CountryHints:
    names: tuple[str, ...]
    codes: tuple[str, ...]
    cities: tuple[str, ...]
    tlds: tuple[str, ...]
    flag: str


# Heuristic hints only. Remarks win over hostname hints; ambiguity -> GLOBAL.
COUNTRY_HINTS: dict[str, CountryHints] = {
    "DE": CountryHints(("germany", "deutschland"), ("de",), ("frankfurt", "berlin", "munich", "nuremberg", "dusseldorf", "hamburg"), ("de",), "\U0001F1E9\U0001F1EA"),
    "US": CountryHints(("united states", "united states of america", "america", "usa"), ("us",), ("new york", "los angeles", "seattle", "dallas", "miami", "chicago", "ashburn", "silicon valley"), ("us",), "\U0001F1FA\U0001F1F8"),
    "NL": CountryHints(("netherlands", "the netherlands", "holland"), ("nl",), ("amsterdam", "rotterdam", "the hague", "eindhoven"), ("nl",), "\U0001F1F3\U0001F1F1"),
    "TR": CountryHints(("turkey", "turkiye", "t\u00fcrkiye"), ("tr",), ("istanbul", "ankara", "izmir", "bursa"), ("tr",), "\U0001F1F9\U0001F1F7"),
    "FR": CountryHints(("france",), ("fr",), ("paris", "marseille", "lyon", "toulouse"), ("fr",), "\U0001F1EB\U0001F1F7"),
    "UK": CountryHints(("united kingdom", "great britain", "britain", "england", "scotland", "wales"), ("uk", "gb"), ("london", "manchester", "birmingham", "edinburgh", "glasgow"), ("uk",), "\U0001F1EC\U0001F1E7"),
    "CA": CountryHints(("canada",), ("ca",), ("toronto", "montreal", "vancouver", "calgary", "ottawa"), ("ca",), "\U0001F1E8\U0001F1E6"),
}

_HOST_LABEL_RE = re.compile(r"[a-z0-9-]+")


def _keyword_pattern(keyword: str) -> re.Pattern[str]:
    return re.compile(rf"(?<![a-z0-9]){re.escape(keyword.lower())}(?![a-z])", re.IGNORECASE)


_COMPILED_HINTS: dict[str, tuple[tuple[re.Pattern[str], int], ...]] = {}
for _country, _hints in COUNTRY_HINTS.items():
    _patterns: list[tuple[re.Pattern[str], int]] = []
    _patterns.extend((_keyword_pattern(name), 5) for name in _hints.names)
    _patterns.extend((_keyword_pattern(city), 2) for city in _hints.cities)
    _patterns.extend((_keyword_pattern(code), 3) for code in _hints.codes)
    _COMPILED_HINTS[_country] = tuple(_patterns)


@dataclass
class SourceSpec:
    id: str
    url: str


@dataclass
class SourceResult:
    id: str
    node_count: int
    fetched_bytes: int
    attempts: int = 1


@dataclass
class AggregationResult:
    nodes: list[str]
    labels: dict[str, str]
    confidences: dict[str, int] = field(default_factory=dict)
    label_sources: dict[str, str] = field(default_factory=dict)
    source_results: list[SourceResult] = field(default_factory=list)
    tcp_checked: int = 0
    tcp_reachable: int = 0
    health_summary: dict | None = None
    probes: list = field(default_factory=list)
    probe_settings: health.ProbeSettings | None = None
    warnings: dict[str, int] = field(default_factory=dict)


def _normalize_text(raw: bytes, context: str) -> str:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise SourceError(f"{context}: payload is not valid UTF-8") from exc
    if text.startswith("\ufeff"):
        text = text[1:]
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _is_comment(line: str) -> bool:
    return line.startswith(_COMMENT_PREFIXES)


def _b64decode(value: str) -> bytes:
    candidate = re.sub(r"\s+", "", value or "")
    if not candidate:
        raise ValueError("empty base64 value")
    candidate = candidate.replace("-", "+").replace("_", "/")
    candidate += "=" * ((-len(candidate)) % 4)
    return base64.b64decode(candidate, validate=True)


def _looks_like_base64(text: str) -> bool:
    compact = re.sub(r"\s+", "", text)
    if len(compact) < 16 or not re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
        return False
    try:
        _b64decode(compact)
    except (ValueError, binascii.Error):
        return False
    return True


def _parse_uri_lines(text: str, context: str) -> list[str]:
    nodes: list[str] = []
    for line_number, raw_line in enumerate(text.split("\n"), start=1):
        line = raw_line.strip()
        if not line or _is_comment(line):
            continue
        try:
            proxy_uri.parse_node(line)
        except proxy_uri.NodeValidationError as exc:
            raise SourceError(f"{context}: invalid node on line {line_number} ({exc.reason})") from exc
        nodes.append(line)
        if len(nodes) > MAX_NODES:
            raise SourceError(f"{context}: too many nodes")
    return nodes


def parse_payload(raw: bytes, context: str = "source") -> list[str]:
    """Decode a payload into validated, de-duplicated node URIs."""

    text = _normalize_text(raw, context)
    if _looks_like_base64(text):
        try:
            decoded_text = _normalize_text(_b64decode(text), f"{context} (base64)")
        except (SourceError, ValueError, binascii.Error) as exc:
            raise SourceError(f"{context}: invalid base64 subscription") from exc
        nodes = _parse_uri_lines(decoded_text, context)
        if not nodes:
            raise SourceError(f"{context}: base64 subscription contains no nodes")
    else:
        nodes = _parse_uri_lines(text, context)
        if not nodes:
            raise SourceError(f"{context}: payload is neither a URI list nor a base64 subscription")
    return _dedupe(nodes)


def _dedupe(nodes: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for node in nodes:
        if node not in seen:
            seen.add(node)
            unique.append(node)
    return unique


def validate_node_uri(uri: str) -> None:
    proxy_uri.parse_node(uri)


def node_endpoint(uri: str) -> tuple[str, int] | None:
    return proxy_uri.node_endpoint(uri)


def node_name(uri: str) -> str:
    return proxy_uri.node_name(uri)


def _score_text(text: str) -> dict[str, int]:
    scores: dict[str, int] = {}
    if not text:
        return scores
    lowered = text.lower()
    for country, hints in COUNTRY_HINTS.items():
        score = 0
        if hints.flag and hints.flag in text:
            score += 6
        for pattern, weight in _COMPILED_HINTS[country]:
            if pattern.search(lowered):
                score += weight
        if score:
            scores[country] = score
    return scores


def classify_country_detail(uri: str, name: str | None = None) -> tuple[str, int, str]:
    """Return (label, confidence 0-100, source) for a node."""

    parsed = proxy_uri.try_parse_node(uri)
    resolved_name = name if name is not None else (parsed.name if parsed else proxy_uri.node_name(uri))
    name_scores = _score_text(resolved_name)
    scores = dict(name_scores)
    source = "remark" if name_scores else "none"
    if parsed is not None:
        labels = _HOST_LABEL_RE.findall(parsed.host)
        for label in labels:
            for country, hints in COUNTRY_HINTS.items():
                if label in hints.tlds:
                    scores[country] = scores.get(country, 0) + 2
                    source = "remark" if source == "remark" else "host"
        if len(labels) >= 2:
            for country, hints in COUNTRY_HINTS.items():
                if labels[-2] in hints.codes:
                    scores[country] = scores.get(country, 0) + 1
                    source = "remark" if source == "remark" else "host"
    if not scores:
        return GLOBAL_LABEL, 0, "none"
    best = max(scores.values())
    winners = [country for country, score in scores.items() if score == best]
    if len(winners) != 1:
        return GLOBAL_LABEL, 0, source
    total = sum(scores.values())
    confidence = max(1, min(100, round(100 * best / total)))
    return winners[0], confidence, source


def classify_country(uri: str, name: str | None = None) -> str:
    return classify_country_detail(uri, name)[0]


def fetch_source(url: str, *, timeout: float, max_bytes: int) -> bytes:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme.lower() != "https":
        raise SourceError("source URL must use HTTPS")
    if not parsed.hostname:
        raise SourceError("source URL has no host")
    if max_bytes <= 0:
        raise SourceError("max_bytes must be positive")
    request = urllib.request.Request(
        url,
        headers={"User-Agent": _USER_AGENT, "Accept": "text/plain, */*;q=0.5"},
        method="GET",
    )
    try:
        with _HTTPS_ONLY_OPENER.open(request, timeout=timeout) as response:
            if urllib.parse.urlsplit(response.geturl()).scheme.lower() != "https":
                raise SourceError("source redirected away from HTTPS")
            chunks: list[bytes] = []
            remaining = max_bytes + 1
            while remaining > 0:
                chunk = response.read(min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
    except SourceError:
        raise
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise SourceError(f"failed to fetch source: {exc.__class__.__name__}") from exc
    if not payload:
        raise SourceError("source returned an empty payload")
    if len(payload) > max_bytes:
        raise SourceError(f"source exceeds the {max_bytes} byte limit")
    return payload


def _fetch_with_retries(fetch, url: str, *, timeout: float, max_bytes: int, retries: int) -> tuple[bytes, int]:
    attempts = max(0, int(retries)) + 1
    last: SourceError | None = None
    for attempt in range(1, attempts + 1):
        try:
            return fetch(url, timeout=timeout, max_bytes=max_bytes), attempt
        except SourceError as exc:
            last = exc
            if attempt < attempts:
                time.sleep(min(2.0, 0.25 * (2 ** (attempt - 1))))
    assert last is not None
    raise last


def load_sources(config_path: Path) -> list[SourceSpec]:
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise AggregationError(f"cannot read config {config_path}: {exc}") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AggregationError(f"config {config_path} is not valid JSON") from exc
    if not isinstance(data, dict) or data.get("version") != 1:
        raise AggregationError("config must be an object with version = 1")
    raw_sources = data.get("sources")
    if not isinstance(raw_sources, list):
        raise AggregationError("config.sources must be a list")
    specs: list[SourceSpec] = []
    seen_ids: set[str] = set()
    for index, entry in enumerate(raw_sources):
        if not isinstance(entry, dict):
            raise AggregationError(f"config.sources[{index}] must be an object")
        if not entry.get("enabled", False):
            continue
        source_id = entry.get("id")
        source_url = entry.get("url")
        if not isinstance(source_id, str) or not source_id.strip():
            raise AggregationError(f"config.sources[{index}].id is required")
        if source_id in seen_ids:
            raise AggregationError(f"duplicate source id: {source_id}")
        if not isinstance(source_url, str) or not source_url.strip():
            raise AggregationError(f"config.sources[{index}].url is required")
        if urllib.parse.urlsplit(source_url).scheme.lower() != "https":
            raise AggregationError(f"source {source_id} must use HTTPS")
        seen_ids.add(source_id)
        specs.append(SourceSpec(id=source_id.strip(), url=source_url.strip()))
    if not specs:
        raise AggregationError("config has no enabled sources")
    return specs


def _probe(node: str, timeout: float) -> bool:
    """Legacy single TCP probe retained for compatibility."""

    endpoint = proxy_uri.node_endpoint(node)
    if endpoint is None:
        return False
    try:
        with socket.create_connection(endpoint, timeout=timeout):
            return True
    except OSError:
        return False


def _label_nodes(nodes: Sequence[str]) -> tuple[dict[str, str], dict[str, int], dict[str, str], dict[str, int]]:
    labels: dict[str, str] = {}
    confidences: dict[str, int] = {}
    sources: dict[str, str] = {}
    warnings: dict[str, int] = {}
    for node in nodes:
        label, confidence, source = classify_country_detail(node)
        labels[node] = label
        confidences[node] = confidence
        sources[node] = source
        parsed = proxy_uri.parse_node(node)
        for warning in parsed.warnings:
            warnings[warning] = warnings.get(warning, 0) + 1
    return labels, confidences, sources, warnings


def aggregate(
    specs: Sequence[SourceSpec],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_bytes: int = DEFAULT_MAX_BYTES,
    tcp_check: bool = False,
    tcp_timeout: float = DEFAULT_TCP_TIMEOUT,
    require_reachable: bool = False,
    retries: int = 0,
    health_check: bool = False,
    health_tls: bool = True,
    health_concurrency: int = health.DEFAULT_CONCURRENCY,
    verify_tls: bool = False,
    fetch=fetch_source,
) -> AggregationResult:
    all_nodes: list[str] = []
    seen: set[str] = set()
    source_results: list[SourceResult] = []
    for spec in specs:
        payload, attempts = _fetch_with_retries(
            fetch, spec.url, timeout=timeout, max_bytes=max_bytes, retries=retries
        )
        nodes = parse_payload(payload, context=f"source {spec.id}")
        added = 0
        for node in nodes:
            if node in seen:
                continue
            seen.add(node)
            all_nodes.append(node)
            added += 1
        source_results.append(
            SourceResult(id=spec.id, node_count=added, fetched_bytes=len(payload), attempts=attempts)
        )
        if len(all_nodes) > MAX_NODES:
            raise AggregationError(f"node limit exceeded ({MAX_NODES})")

    labels, confidences, label_sources, warnings = _label_nodes(all_nodes)
    tcp_checked = 0
    tcp_reachable = 0
    probes: list = []
    probe_settings: health.ProbeSettings | None = None
    health_summary: dict | None = None

    if health_check or tcp_check:
        probe_settings = health.ProbeSettings(
            timeout=tcp_timeout,
            tls=health_tls if health_check else False,
            concurrency=health_concurrency,
            verify_tls=verify_tls,
        ).normalized()
        parsed_nodes = [proxy_uri.parse_node(node) for node in all_nodes]
        probes = health.probe_nodes(
            parsed_nodes,
            labels=labels,
            confidences=confidences,
            settings=probe_settings,
        )
        health_summary = health.summarize(probes)
        tcp_checked = health_summary["checked"]
        tcp_reachable = health_summary["tcp_reachable"]
        if require_reachable:
            reachable = {item.node_id for item in probes if item.reachable}
            all_nodes = [node for node in all_nodes if proxy_uri.fingerprint(node) in reachable]
            if not all_nodes:
                raise AggregationError("health check removed every node")

    return AggregationResult(
        nodes=all_nodes,
        labels={node: labels[node] for node in all_nodes},
        confidences={node: confidences[node] for node in all_nodes},
        label_sources={node: label_sources[node] for node in all_nodes},
        source_results=source_results,
        tcp_checked=tcp_checked,
        tcp_reachable=tcp_reachable,
        health_summary=health_summary,
        probes=probes,
        probe_settings=probe_settings,
        warnings=warnings,
    )


def _feed_files(result: AggregationResult) -> dict[str, str]:
    buckets: dict[str, list[str]] = {label: [] for label in COUNTRIES}
    for node in result.nodes:
        label = result.labels.get(node, GLOBAL_LABEL)
        if label in buckets:
            buckets[label].append(node)
    files = {f"subscriptions/{GLOBAL_LABEL.lower()}.txt": "".join(f"{n}\n" for n in result.nodes)}
    for label in COUNTRIES:
        files[f"subscriptions/{label.lower()}.txt"] = "".join(f"{n}\n" for n in buckets[label])
    return files


def _label_confidence(result: AggregationResult) -> dict:
    values = [
        confidence
        for node, confidence in result.confidences.items()
        if result.labels.get(node) != GLOBAL_LABEL
    ]
    sources: dict[str, int] = {}
    for source in result.label_sources.values():
        sources[source] = sources.get(source, 0) + 1
    return {
        "average": round(sum(values) / len(values), 1) if values else 0,
        "classified": len(values),
        "sources": dict(sorted(sources.items())),
    }


def write_outputs(
    result: AggregationResult,
    *,
    output_dir: Path,
    source_count: int,
    generated_at: str | None = None,
    publish_health: bool = False,
) -> dict:
    feeds = _feed_files(result)
    counts = {label: 0 for label in FEED_LABELS}
    for node in result.nodes:
        counts[GLOBAL_LABEL] += 1
        label = result.labels.get(node, GLOBAL_LABEL)
        if label != GLOBAL_LABEL:
            counts[label] = counts.get(label, 0) + 1

    checksums = {relative: integrity.sha256_bytes(text.encode("utf-8")) for relative, text in feeds.items()}
    checksums["snapshot/global.txt"] = checksums[f"subscriptions/{GLOBAL_LABEL.lower()}.txt"]

    health_document = None
    if publish_health and result.probes and result.probe_settings is not None:
        health_document = health.build_document(
            result.probes, result.probe_settings, generated_at=generated_at
        )
        checksums["health.json"] = integrity.sha256_bytes(
            (json.dumps(health_document, indent=2, sort_keys=True) + "\n").encode("utf-8")
        )

    manifest = {
        "version": MANIFEST_VERSION,
        "generated_at_utc": generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_count": source_count,
        "node_count": len(result.nodes),
        "feeds": {label: f"subscriptions/{label.lower()}.txt" for label in FEED_LABELS},
        "counts": counts,
        "snapshot": "snapshot/global.txt",
        "sources": [
            {
                "id": item.id,
                "node_count": item.node_count,
                "fetched_bytes": item.fetched_bytes,
                "attempts": item.attempts,
            }
            for item in result.source_results
        ],
        "warnings": dict(sorted(result.warnings.items())),
        "label_confidence": _label_confidence(result),
        "checksums": dict(sorted(checksums.items())),
        "tcp_checked": result.tcp_checked,
        "tcp_reachable": result.tcp_reachable,
    }
    if publish_health and result.health_summary is not None:
        manifest["health"] = {**result.health_summary, "published": len(result.nodes)}

    manifest_text = json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    files: dict[str, str] = {relative: text for relative, text in feeds.items()}
    files["snapshot/global.txt"] = feeds[f"subscriptions/{GLOBAL_LABEL.lower()}.txt"]
    if health_document is not None:
        files["health.json"] = json.dumps(health_document, indent=2, sort_keys=True) + "\n"
    files["manifest.json"] = manifest_text
    files[integrity.CHECKSUMS_NAME] = integrity.format_checksums(
        {**checksums, "manifest.json": integrity.sha256_bytes(manifest_text.encode("utf-8"))}
    )
    integrity.publish_atomic(output_dir, files, verify=True)
    if not publish_health:
        stale = output_dir / "health.json"
        try:
            stale.unlink(missing_ok=True)
        except OSError as exc:
            LOGGER.warning("could not remove stale health.json: %s", exc.__class__.__name__)
    return manifest


def _append_telemetry(path: Path | None, event: str, **fields) -> None:
    if path is None:
        return
    payload = ai_ops.sanitize(
        {"ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "event": event, **fields}
    )
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.stat().st_size > 2 * 1024 * 1024:
            path.replace(path.with_suffix(path.suffix + ".1"))
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
    except OSError as exc:
        LOGGER.warning("telemetry write failed: %s", exc.__class__.__name__)


def _publish_ai_text(text: str | None, path: Path | None) -> None:
    if not text:
        return
    if path is None:
        LOGGER.info("AI review: %s", text[:1500])
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")
    except OSError as exc:
        LOGGER.warning("AI output write failed: %s", exc.__class__.__name__)


def run(
    config_path: Path = DEFAULT_CONFIG_PATH,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_bytes: int = DEFAULT_MAX_BYTES,
    tcp_check: bool = False,
    tcp_timeout: float = DEFAULT_TCP_TIMEOUT,
    require_reachable: bool = False,
    retries: int = DEFAULT_RETRIES,
    health_check: bool = False,
    health_tls: bool = True,
    health_concurrency: int = health.DEFAULT_CONCURRENCY,
    verify_tls: bool = False,
    ai_config: ai_ops.GatewayConfig | None = None,
    ai_review: bool = False,
    ai_diagnose: bool = False,
    ai_output: Path | None = None,
    telemetry_path: Path | None = None,
    fetch=fetch_source,
) -> dict:
    specs = load_sources(config_path)
    try:
        result = aggregate(
            specs,
            timeout=timeout,
            max_bytes=max_bytes,
            tcp_check=tcp_check,
            tcp_timeout=tcp_timeout,
            require_reachable=require_reachable,
            retries=retries,
            health_check=health_check,
            health_tls=health_tls,
            health_concurrency=health_concurrency,
            verify_tls=verify_tls,
            fetch=fetch,
        )
        manifest = write_outputs(
            result, output_dir=output_dir, source_count=len(specs), publish_health=health_check
        )
        integrity.verify_or_raise(output_dir)
    except Exception as exc:
        if not isinstance(exc, AggregationError):
            exc = AggregationError(f"integrity check failed: {exc}")
        _append_telemetry(
            telemetry_path,
            "aggregation_failed",
            error=str(exc),
            sources=[spec.id for spec in specs],
        )
        if ai_diagnose:
            try:
                text = ai_ops.diagnose_failure(
                    str(exc), {"sources": [spec.id for spec in specs]}, config=ai_config
                )
                _publish_ai_text(text, ai_output)
            except ai_ops.GatewayError as gateway_exc:
                LOGGER.warning("AI diagnosis unavailable: %s", gateway_exc)
        raise exc

    _append_telemetry(
        telemetry_path,
        "aggregation_succeeded",
        node_count=manifest["node_count"],
        source_count=manifest["source_count"],
        counts=manifest["counts"],
        health=manifest.get("health"),
        warnings=manifest.get("warnings"),
    )
    LOGGER.info(
        "Published %d nodes from %d source(s) to %s",
        manifest["node_count"],
        manifest["source_count"],
        output_dir,
    )
    if ai_review:
        try:
            _publish_ai_text(ai_ops.review_manifest(manifest, config=ai_config), ai_output)
        except ai_ops.GatewayError as exc:
            LOGGER.warning("AI review unavailable: %s", exc)
    return manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES, help="retries for transient source failures")
    parser.add_argument("--tcp-check", action="store_true", help="advisory TCP-only probe")
    parser.add_argument("--health-check", action="store_true", help="async TCP+TLS probe and health.json")
    parser.add_argument("--no-tls-probe", action="store_true", help="skip TLS handshakes during health checks")
    parser.add_argument("--verify-tls", action="store_true", help="verify certificates during TLS probes")
    parser.add_argument("--health-concurrency", type=int, default=health.DEFAULT_CONCURRENCY)
    parser.add_argument("--tcp-timeout", type=float, default=DEFAULT_TCP_TIMEOUT)
    parser.add_argument("--require-reachable", action="store_true", help="drop nodes that fail the probe")
    parser.add_argument("--ai-review", action="store_true", help="request a sanitized gateway review")
    parser.add_argument("--ai-diagnose", action="store_true", help="request gateway diagnosis on failure")
    parser.add_argument("--ai-model", default=None)
    parser.add_argument("--ai-base-url", default=None)
    parser.add_argument("--ai-output", type=Path, default=None)
    parser.add_argument("--telemetry", type=Path, default=None)
    parser.add_argument("--verbose", action="store_true")
    return parser


def _gateway_config(args: argparse.Namespace) -> ai_ops.GatewayConfig:
    config = ai_ops.GatewayConfig.from_env(model=args.ai_model)
    if args.ai_base_url:
        config = ai_ops.GatewayConfig(
            base_url=args.ai_base_url.rstrip("/"),
            api_key=config.api_key,
            model=config.model,
            timeout=config.timeout,
        )
    return config


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )
    if args.timeout <= 0 or args.max_bytes <= 0 or args.retries < 0:
        LOGGER.error("timeout/max-bytes must be positive and retries >= 0")
        return 2
    try:
        run(
            config_path=args.config,
            output_dir=args.output_dir,
            timeout=args.timeout,
            max_bytes=args.max_bytes,
            tcp_check=args.tcp_check or args.require_reachable,
            tcp_timeout=args.tcp_timeout,
            require_reachable=args.require_reachable,
            retries=args.retries,
            health_check=args.health_check,
            health_tls=not args.no_tls_probe,
            health_concurrency=args.health_concurrency,
            verify_tls=args.verify_tls,
            ai_config=_gateway_config(args) if (args.ai_review or args.ai_diagnose) else None,
            ai_review=args.ai_review,
            ai_diagnose=args.ai_diagnose,
            ai_output=args.ai_output,
            telemetry_path=args.telemetry,
        )
    except AggregationError as exc:
        LOGGER.error("aggregation failed: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
