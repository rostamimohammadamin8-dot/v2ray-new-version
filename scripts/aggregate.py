#!/usr/bin/env python3
"""Aggregate public subscription sources into v2rayN-compatible text feeds.

The pipeline is intentionally strict and transactional:

* sources are fetched over HTTPS only, with bounded time and size limits;
* payloads must be strict UTF-8 and decode either to newline-separated proxy
  URIs or to a Base64 subscription containing such URIs;
* every URI in a payload must be structurally valid, otherwise the whole run
  fails so that a truncated/malformed feed can never replace working output;
* feeds and the manifest are staged in temporary files and moved into place
  only after the complete run succeeded;
* a last-known-good copy of ``global.txt`` is kept for offline use.

Only the Python standard library is required (Python 3.12 is the target).
"""

from __future__ import annotations

import argparse
import base64
import binascii
import concurrent.futures
import json
import logging
import os
import re
import shutil
import socket
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence

LOGGER = logging.getLogger("aggregate")

DEFAULT_CONFIG_PATH = Path("config/sources.json")
DEFAULT_OUTPUT_DIR = Path("data")
DEFAULT_TIMEOUT = 15.0
DEFAULT_MAX_BYTES = 5 * 1024 * 1024
DEFAULT_TCP_TIMEOUT = 3.0
MANIFEST_VERSION = 1

COUNTRIES: tuple[str, ...] = ("DE", "US", "NL", "TR", "FR", "UK", "CA")
GLOBAL_LABEL = "GLOBAL"
FEED_LABELS: tuple[str, ...] = (GLOBAL_LABEL, *COUNTRIES)

SUPPORTED_SCHEMES = frozenset(
    {
        "vmess",
        "vless",
        "trojan",
        "ss",
        "socks",
        "socks5",
        "http",
        "https",
        "hysteria",
        "hysteria2",
        "hy2",
        "tuic",
        "wireguard",
        "ssh",
    }
)

_COMMENT_PREFIXES = ("#", "//", ";")
_USER_AGENT = "v2ray-subscription-aggregator/1.0 (+https://github.com/)"


class _HttpsOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse redirects that would leave HTTPS at any hop."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme.lower() != "https":
            raise urllib.error.URLError("refusing non-HTTPS redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_HTTPS_ONLY_OPENER = urllib.request.build_opener(_HttpsOnlyRedirectHandler())


class AggregationError(Exception):
    """Raised when a run must stop without publishing new output."""


class SourceError(AggregationError):
    """Raised when an individual subscription source is unusable."""


@dataclass(frozen=True)
class CountryHints:
    names: tuple[str, ...]
    codes: tuple[str, ...]
    cities: tuple[str, ...]
    tlds: tuple[str, ...]
    flag: str


# Heuristic hints only. Remarks win over hostname hints, and an ambiguous result
# falls back to GLOBAL. This is not geolocation.
COUNTRY_HINTS: dict[str, CountryHints] = {
    "DE": CountryHints(
        names=("germany", "deutschland"),
        codes=("de",),
        cities=("frankfurt", "berlin", "munich", "nuremberg", "dusseldorf", "hamburg"),
        tlds=("de",),
        flag="\U0001F1E9\U0001F1EA",
    ),
    "US": CountryHints(
        names=("united states", "united states of america", "america", "usa"),
        codes=("us",),
        cities=("new york", "los angeles", "seattle", "dallas", "miami", "chicago", "ashburn", "silicon valley"),
        tlds=("us",),
        flag="\U0001F1FA\U0001F1F8",
    ),
    "NL": CountryHints(
        names=("netherlands", "the netherlands", "holland"),
        codes=("nl",),
        cities=("amsterdam", "rotterdam", "the hague", "eindhoven"),
        tlds=("nl",),
        flag="\U0001F1F3\U0001F1F1",
    ),
    "TR": CountryHints(
        names=("turkey", "turkiye", "t\u00fcrkiye"),
        codes=("tr",),
        cities=("istanbul", "ankara", "izmir", "bursa"),
        tlds=("tr",),
        flag="\U0001F1F9\U0001F1F7",
    ),
    "FR": CountryHints(
        names=("france",),
        codes=("fr",),
        cities=("paris", "marseille", "lyon", "toulouse"),
        tlds=("fr",),
        flag="\U0001F1EB\U0001F1F7",
    ),
    "UK": CountryHints(
        names=("united kingdom", "great britain", "britain", "england", "scotland", "wales"),
        codes=("uk", "gb"),
        cities=("london", "manchester", "birmingham", "edinburgh", "glasgow"),
        tlds=("uk",),
        flag="\U0001F1EC\U0001F1E7",
    ),
    "CA": CountryHints(
        names=("canada",),
        codes=("ca",),
        cities=("toronto", "montreal", "vancouver", "calgary", "ottawa"),
        tlds=("ca",),
        flag="\U0001F1E8\U0001F1E6",
    ),
}

_HOST_LABEL_RE = re.compile(r"[a-z0-9-]+")

@dataclass
class SourceSpec:
    id: str
    url: str


@dataclass
class SourceResult:
    id: str
    node_count: int
    fetched_bytes: int


@dataclass
class AggregationResult:
    nodes: list[str]
    labels: dict[str, str]
    source_results: list[SourceResult] = field(default_factory=list)
    tcp_checked: int = 0
    tcp_reachable: int = 0


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
    candidate = re.sub(r"\s+", "", value)
    if not candidate:
        raise ValueError("empty base64 value")
    candidate = candidate.replace("-", "+").replace("_", "/")
    padding = (-len(candidate)) % 4
    candidate += "=" * padding
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


def _parse_vmess_json(uri: str) -> dict:
    payload = uri[len("vmess://") :].split("#", 1)[0].strip()
    try:
        decoded = _b64decode(payload)
        data = json.loads(decoded.decode("utf-8", errors="strict"))
    except (ValueError, binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid vmess payload") from exc
    if not isinstance(data, dict):
        raise ValueError("invalid vmess payload")
    host = data.get("add")
    port = data.get("port")
    if not isinstance(host, str) or not host.strip():
        raise ValueError("vmess payload has no address")
    try:
        port_number = int(str(port).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError("vmess payload has an invalid port") from exc
    if not 1 <= port_number <= 65535:
        raise ValueError("vmess payload has an invalid port")
    return data


def _split_host_port(hostport: str) -> tuple[str, int]:
    hostport = hostport.strip()
    if not hostport:
        raise ValueError("missing host")
    parsed = urllib.parse.urlsplit(f"//{hostport}")
    host = parsed.hostname
    port = parsed.port
    if not host or port is None:
        raise ValueError("missing host or port")
    if not 1 <= port <= 65535:
        raise ValueError("invalid port")
    return host, port


def node_endpoint(uri: str) -> tuple[str, int] | None:
    """Return ``(host, port)`` for a node URI, or ``None`` if it is unknown."""

    scheme = uri.split("://", 1)[0].lower()
    try:
        if scheme == "vmess":
            data = _parse_vmess_json(uri)
            return str(data["add"]).strip(), int(str(data["port"]).strip())
        if scheme == "ss":
            body = uri[len("ss://") :].split("#", 1)[0].split("?", 1)[0]
            if "@" in body:
                userinfo, hostport = body.rsplit("@", 1)
                if not userinfo.strip():
                    raise ValueError("ss payload has no credentials")
                return _split_host_port(hostport)
            decoded = _b64decode(body).decode("utf-8", errors="strict")
            if "@" not in decoded:
                raise ValueError("invalid ss payload")
            userinfo, hostport = decoded.rsplit("@", 1)
            if not userinfo.strip() or ":" not in userinfo:
                raise ValueError("invalid ss credentials")
            return _split_host_port(hostport)
        parsed = urllib.parse.urlsplit(uri)
        host = parsed.hostname
        port = parsed.port
        if host and port is not None:
            return host, port
    except (ValueError, binascii.Error, UnicodeDecodeError, KeyError):
        return None
    return None


def validate_node_uri(uri: str) -> None:
    if not uri or any(char.isspace() for char in uri):
        raise ValueError("URI contains whitespace")
    if "://" not in uri:
        raise ValueError("URI has no scheme")
    scheme = uri.split("://", 1)[0].lower()
    if scheme not in SUPPORTED_SCHEMES:
        raise ValueError(f"unsupported scheme: {scheme}")
    if scheme == "vmess":
        _parse_vmess_json(uri)
        return
    endpoint = node_endpoint(uri)
    if endpoint is None:
        raise ValueError(f"invalid {scheme} URI")
    host, port = endpoint
    if not host or not (1 <= port <= 65535):
        raise ValueError(f"invalid {scheme} endpoint")


def node_name(uri: str) -> str:
    scheme = uri.split("://", 1)[0].lower()
    if scheme == "vmess":
        try:
            name = _parse_vmess_json(uri).get("ps", "")
        except ValueError:
            return ""
        return str(name).strip() if name is not None else ""
    fragment = urllib.parse.urlsplit(uri).fragment
    if not fragment:
        return ""
    return urllib.parse.unquote(fragment).strip()


def _parse_uri_lines(text: str, context: str) -> list[str]:
    nodes: list[str] = []
    for line_number, raw_line in enumerate(text.split("\n"), start=1):
        line = raw_line.strip()
        if not line or _is_comment(line):
            continue
        try:
            validate_node_uri(line)
        except ValueError as exc:
            raise SourceError(f"{context}: invalid node on line {line_number} ({exc})") from exc
        nodes.append(line)
    return nodes


def parse_payload(raw: bytes, context: str = "source") -> list[str]:
    """Decode a subscription payload into validated, de-duplicated node URIs."""

    text = _normalize_text(raw, context)

    # A Base64 subscription is one opaque token (possibly line-wrapped), so it
    # is detected before line-level URI validation. Plain URI lists always
    # contain ``://`` and therefore cannot match this pattern.
    if _looks_like_base64(text):
        try:
            decoded = _b64decode(text)
            decoded_text = _normalize_text(decoded, f"{context} (base64)")
        except (SourceError, ValueError, binascii.Error) as exc:
            raise SourceError(f"{context}: invalid base64 subscription") from exc
        nodes = _parse_uri_lines(decoded_text, context)
        if nodes:
            return _dedupe(nodes)
        raise SourceError(f"{context}: base64 subscription contains no nodes")

    nodes = _parse_uri_lines(text, context)
    if nodes:
        return _dedupe(nodes)
    raise SourceError(f"{context}: payload is neither a URI list nor a base64 subscription")


def _dedupe(nodes: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for node in nodes:
        if node in seen:
            continue
        seen.add(node)
        unique.append(node)
    return unique


def _keyword_pattern(keyword: str) -> re.Pattern[str]:
    escaped = re.escape(keyword.lower())
    return re.compile(rf"(?<![a-z0-9]){escaped}(?![a-z])", re.IGNORECASE)


_COMPILED_HINTS: dict[str, tuple[tuple[re.Pattern[str], int], ...]] = {}
for _country, _hints in COUNTRY_HINTS.items():
    _patterns: list[tuple[re.Pattern[str], int]] = []
    _patterns.extend((_keyword_pattern(name), 5) for name in _hints.names)
    _patterns.extend((_keyword_pattern(city), 2) for city in _hints.cities)
    _patterns.extend((_keyword_pattern(code), 3) for code in _hints.codes)
    _COMPILED_HINTS[_country] = tuple(_patterns)


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


def classify_country(uri: str, name: str | None = None) -> str:
    """Best-effort country label; returns GLOBAL when ambiguous or unknown."""

    resolved_name = name if name is not None else node_name(uri)
    scores = _score_text(resolved_name)

    endpoint = node_endpoint(uri)
    if endpoint:
        host = endpoint[0].lower().rstrip(".")
        labels = _HOST_LABEL_RE.findall(host)
        for label in labels:
            for country, hints in COUNTRY_HINTS.items():
                if label in hints.tlds:
                    scores[country] = scores.get(country, 0) + 2
        # The last label is the TLD; the second-to-last label is usually the
        # registrable domain and is only useful when it is a country token.
        if len(labels) >= 2:
            for country, hints in COUNTRY_HINTS.items():
                if labels[-2] in hints.codes:
                    scores[country] = scores.get(country, 0) + 1

    if not scores:
        return GLOBAL_LABEL
    best = max(scores.values())
    winners = [country for country, score in scores.items() if score == best]
    if len(winners) != 1:
        return GLOBAL_LABEL
    return winners[0]


def fetch_source(url: str, *, timeout: float, max_bytes: int) -> bytes:
    """Fetch a source over HTTPS with bounded time and response size."""

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
            final_url = response.geturl()
            if urllib.parse.urlsplit(final_url).scheme.lower() != "https":
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
    except (urllib.error.URLError, TimeoutError, socket.timeout, OSError) as exc:
        raise SourceError(f"failed to fetch source: {exc}") from exc

    if not payload:
        raise SourceError("source returned an empty payload")
    if len(payload) > max_bytes:
        raise SourceError(f"source exceeds the {max_bytes} byte limit")
    return payload


def load_sources(config_path: Path) -> list[SourceSpec]:
    try:
        raw = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise AggregationError(f"cannot read config {config_path}: {exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
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
    endpoint = node_endpoint(node)
    if endpoint is None:
        return False
    host, port = endpoint
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def aggregate(
    specs: Sequence[SourceSpec],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_bytes: int = DEFAULT_MAX_BYTES,
    tcp_check: bool = False,
    tcp_timeout: float = DEFAULT_TCP_TIMEOUT,
    require_reachable: bool = False,
    fetch=fetch_source,
) -> AggregationResult:
    all_nodes: list[str] = []
    seen: set[str] = set()
    source_results: list[SourceResult] = []

    for spec in specs:
        payload = fetch(spec.url, timeout=timeout, max_bytes=max_bytes)
        nodes = parse_payload(payload, context=f"source {spec.id}")
        if not nodes:
            raise SourceError(f"source {spec.id} contains no usable nodes")
        added = 0
        for node in nodes:
            if node in seen:
                continue
            seen.add(node)
            all_nodes.append(node)
            added += 1
        source_results.append(SourceResult(id=spec.id, node_count=added, fetched_bytes=len(payload)))

    if not all_nodes:
        raise AggregationError("no nodes were collected")

    tcp_checked = 0
    tcp_reachable = 0
    if tcp_check:
        tcp_checked = len(all_nodes)
        reachable: dict[str, bool] = {}
        workers = min(32, max(1, len(all_nodes)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            future_map = {pool.submit(_probe, node, tcp_timeout): node for node in all_nodes}
            for future in concurrent.futures.as_completed(future_map):
                node = future_map[future]
                try:
                    reachable[node] = bool(future.result())
                except Exception:  # pragma: no cover - defensive
                    reachable[node] = False
        tcp_reachable = sum(1 for value in reachable.values() if value)
        if require_reachable:
            all_nodes = [node for node in all_nodes if reachable.get(node)]
            if not all_nodes:
                raise AggregationError("TCP check removed every node")

    labels = {node: classify_country(node) for node in all_nodes}
    return AggregationResult(
        nodes=all_nodes,
        labels=labels,
        source_results=source_results,
        tcp_checked=tcp_checked,
        tcp_reachable=tcp_reachable,
    )


def _feed_files(result: AggregationResult) -> dict[str, str]:
    buckets: dict[str, list[str]] = {label: [] for label in COUNTRIES}
    for node in result.nodes:
        label = result.labels.get(node, GLOBAL_LABEL)
        if label in buckets:
            buckets[label].append(node)
    files: dict[str, str] = {}
    files[f"subscriptions/{GLOBAL_LABEL.lower()}.txt"] = "".join(
        f"{line}\n" for line in result.nodes
    )
    for label in COUNTRIES:
        files[f"subscriptions/{label.lower()}.txt"] = "".join(
            f"{line}\n" for line in buckets[label]
        )
    return files


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def write_outputs(
    result: AggregationResult,
    *,
    output_dir: Path,
    source_count: int,
    generated_at: str | None = None,
) -> dict:
    output_dir = output_dir.resolve()
    feeds = _feed_files(result)
    counts = {label: 0 for label in FEED_LABELS}
    for node in result.nodes:
        counts[GLOBAL_LABEL] += 1
        label = result.labels.get(node, GLOBAL_LABEL)
        if label != GLOBAL_LABEL:
            counts[label] = counts.get(label, 0) + 1

    manifest = {
        "version": MANIFEST_VERSION,
        "generated_at_utc": generated_at
        or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
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
            }
            for item in result.source_results
        ],
        "tcp_checked": result.tcp_checked,
        "tcp_reachable": result.tcp_reachable,
    }
    manifest_text = json.dumps(manifest, indent=2, sort_keys=False, ensure_ascii=False) + "\n"

    output_dir.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".aggregate-", dir=str(output_dir.parent)))
    try:
        staged: list[tuple[Path, Path]] = []
        for relative, text in feeds.items():
            source = staging / relative
            _write_text(source, text)
            staged.append((source, output_dir / relative))
        snapshot_source = staging / "snapshot" / "global.txt"
        _write_text(snapshot_source, feeds[f"subscriptions/{GLOBAL_LABEL.lower()}.txt"])
        staged.append((snapshot_source, output_dir / "snapshot" / "global.txt"))
        manifest_source = staging / "manifest.json"
        _write_text(manifest_source, manifest_text)
        staged.append((manifest_source, output_dir / "manifest.json"))

        # Everything was staged successfully; publish feeds, snapshot, then manifest.
        for source, destination in staged:
            destination.parent.mkdir(parents=True, exist_ok=True)
            os.replace(source, destination)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return manifest


def run(
    config_path: Path = DEFAULT_CONFIG_PATH,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_bytes: int = DEFAULT_MAX_BYTES,
    tcp_check: bool = False,
    tcp_timeout: float = DEFAULT_TCP_TIMEOUT,
    require_reachable: bool = False,
    fetch=fetch_source,
) -> dict:
    specs = load_sources(config_path)
    result = aggregate(
        specs,
        timeout=timeout,
        max_bytes=max_bytes,
        tcp_check=tcp_check,
        tcp_timeout=tcp_timeout,
        require_reachable=require_reachable,
        fetch=fetch,
    )
    manifest = write_outputs(result, output_dir=output_dir, source_count=len(specs))
    LOGGER.info(
        "Published %d nodes from %d source(s) to %s",
        manifest["node_count"],
        manifest["source_count"],
        output_dir,
    )
    return manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    parser.add_argument("--tcp-check", action="store_true", help="probe node endpoints")
    parser.add_argument("--tcp-timeout", type=float, default=DEFAULT_TCP_TIMEOUT)
    parser.add_argument(
        "--require-reachable",
        action="store_true",
        help="drop nodes whose TCP probe failed (implies --tcp-check)",
    )
    parser.add_argument("--verbose", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )
    if args.timeout <= 0 or args.max_bytes <= 0:
        LOGGER.error("timeout and max-bytes must be positive")
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
        )
    except AggregationError as exc:
        LOGGER.error("aggregation failed: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
