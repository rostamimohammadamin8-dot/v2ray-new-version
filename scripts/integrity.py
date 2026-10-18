"""Atomic publication, SHA256 checksums, and production-state verification.

The publisher writes every artifact into a private staging directory, then
moves files into place individually (feeds -> snapshot -> manifest -> sums).
A failed aggregation never calls the publisher, so the previous known-good
state remains intact. ``verify_outputs`` re-validates that state offline.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Mapping

from scripts.proxy_uri import NodeValidationError, parse_node

CHECKSUMS_NAME = "SHA256SUMS"
MANIFEST_NAME = "manifest.json"
FEED_LABELS = ("GLOBAL", "DE", "US", "NL", "TR", "FR", "UK", "CA")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class IntegrityError(Exception):
    """Raised when published data does not satisfy the integrity contract."""



def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _as_bytes(value: bytes | str) -> bytes:
    return value if isinstance(value, bytes) else value.encode("utf-8")


def checksums_text(files: Mapping[str, bytes | str]) -> str:
    lines = [f"{sha256_bytes(_as_bytes(value))}  {name}" for name, value in files.items()]
    return "\n".join(sorted(lines)) + "\n"


def format_checksums(hashes: Mapping[str, str]) -> str:
    """Format already-computed SHA256 digests in ``sha256sum`` format."""

    return "\n".join(f"{digest}  {name}" for name, digest in sorted(hashes.items())) + "\n"


def publish_atomic(
    output_dir: Path, files: Mapping[str, bytes | str], *, verify: bool = False
) -> None:
    """Stage all files first, then publish with manifest/checksums last.

    When ``verify`` is true the staged tree is validated before any file is
    moved into the production directory, so a corrupt build cannot replace a
    known-good state.
    """

    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".publish-", dir=str(output_dir.parent)))
    try:
        staged: list[tuple[Path, Path]] = []
        for relative, value in files.items():
            source = staging / relative
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_bytes(_as_bytes(value))
            staged.append((source, output_dir / relative))

        if verify:
            errors = verify_outputs(staging)
            if errors:
                raise IntegrityError("; ".join(errors))

        def priority(item: tuple[Path, Path]) -> tuple[int, str]:
            name = item[1].name
            order = 2 if name == MANIFEST_NAME else 3 if name == CHECKSUMS_NAME else 1
            return order, str(item[1])

        for source, destination in sorted(staged, key=priority):
            destination.parent.mkdir(parents=True, exist_ok=True)
            os.replace(source, destination)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _read_feed(path: Path, relative: str, errors: list[str]) -> list[str]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        errors.append(f"{relative}: cannot read ({exc.__class__.__name__})")
        return []
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        errors.append(f"{relative}: not valid UTF-8")
        return []
    if "\r" in text:
        errors.append(f"{relative}: contains CR line endings")
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if any(not line.strip() for line in lines):
        errors.append(f"{relative}: contains blank lines")
    if len(lines) != len(set(lines)):
        errors.append(f"{relative}: contains duplicate URI lines")
    for number, line in enumerate(lines, start=1):
        try:
            parse_node(line)
        except NodeValidationError as exc:
            errors.append(f"{relative}:{number}: invalid node ({exc.reason})")
    return lines


def _verify_manifest_shape(manifest: object, errors: list[str]) -> dict:
    if not isinstance(manifest, dict):
        errors.append("manifest.json: root must be an object")
        return {}
    required = {"version", "generated_at_utc", "source_count", "node_count", "feeds", "counts", "snapshot"}
    missing = sorted(required - set(manifest))
    if missing:
        errors.append(f"manifest.json: missing keys {missing}")
    if manifest.get("version") != 1:
        errors.append("manifest.json: unsupported version")
    timestamp = manifest.get("generated_at_utc")
    if not isinstance(timestamp, str) or not _TIMESTAMP_RE.match(timestamp):
        errors.append("manifest.json: invalid generated_at_utc")
    for key in ("source_count", "node_count"):
        value = manifest.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            errors.append(f"manifest.json: {key} must be a non-negative integer")
    if manifest.get("source_count", 0) < 1:
        errors.append("manifest.json: source_count must be at least 1")
    if manifest.get("node_count", 0) < 1:
        errors.append("manifest.json: node_count must be at least 1")
    if "://" in json.dumps(manifest):
        errors.append("manifest.json: contains a URL or node URI")
    return manifest


def verify_outputs(data_dir: Path) -> list[str]:
    """Return a list of integrity errors; an empty list means valid state."""

    data_dir = data_dir.resolve()
    errors: list[str] = []
    manifest_path = data_dir / MANIFEST_NAME
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return ["manifest.json: missing or invalid JSON"]
    manifest = _verify_manifest_shape(manifest, errors)
    if not manifest:
        return errors

    feeds = manifest.get("feeds")
    if not isinstance(feeds, dict) or "GLOBAL" not in feeds:
        errors.append("manifest.json: feeds map with GLOBAL is required")
        return errors
    for required in FEED_LABELS:
        if required not in feeds:
            errors.append(f"manifest.json: feed {required} is missing")

    loaded: dict[str, list[str]] = {}
    for label, relative in feeds.items():
        if not isinstance(relative, str) or relative.startswith("/") or ".." in Path(relative).parts:
            errors.append(f"manifest.json: unsafe feed path for {label}")
            continue
        loaded[label] = _read_feed(data_dir / relative, relative, errors)

    node_count = manifest.get("node_count")
    if isinstance(node_count, int) and "GLOBAL" in loaded and len(loaded["GLOBAL"]) != node_count:
        errors.append("manifest.json: node_count does not match GLOBAL line count")

    counts = manifest.get("counts")
    if isinstance(counts, dict):
        for label, lines in loaded.items():
            if isinstance(counts.get(label), int) and counts[label] != len(lines):
                errors.append(f"manifest.json: counts[{label}] does not match feed")

    global_set = set(loaded.get("GLOBAL", []))
    for label, lines in loaded.items():
        if label == "GLOBAL":
            continue
        extra = set(lines) - global_set
        if extra:
            errors.append(f"manifest.json: {label} contains nodes missing from GLOBAL")

    snapshot = manifest.get("snapshot")
    if isinstance(snapshot, str):
        try:
            if (data_dir / snapshot).read_bytes() != (data_dir / feeds["GLOBAL"]).read_bytes():
                errors.append("snapshot does not match GLOBAL feed")
        except OSError:
            errors.append("snapshot is missing")
    else:
        errors.append("manifest.json: snapshot path is invalid")

    _verify_checksums(data_dir, manifest, loaded, errors)
    return errors


def _verify_checksums(
    data_dir: Path, manifest: dict, loaded: Mapping[str, list[str]], errors: list[str]
) -> None:
    declared = manifest.get("checksums")
    if not isinstance(declared, dict) or not declared:
        errors.append("manifest.json: checksums map is missing")
    else:
        feeds = manifest.get("feeds") if isinstance(manifest.get("feeds"), dict) else {}
        required = [feeds.get(label) for label in FEED_LABELS]
        required.append(manifest.get("snapshot"))
        for relative in required:
            if isinstance(relative, str) and relative not in declared:
                errors.append(f"manifest.json: checksum for {relative} is missing")
        for relative, expected in declared.items():
            if not isinstance(relative, str) or not isinstance(expected, str):
                errors.append("manifest.json: invalid checksum entry")
                continue
            try:
                actual = sha256_file(data_dir / relative)
            except OSError:
                errors.append(f"{relative}: listed in checksums but missing")
                continue
            if actual != expected:
                errors.append(f"{relative}: checksum mismatch")

    sums_path = data_dir / CHECKSUMS_NAME
    try:
        lines = sums_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        errors.append("SHA256SUMS: missing or unreadable")
        return
    if not lines:
        errors.append("SHA256SUMS: empty")
        return
    listed: dict[str, str] = {}
    for line in lines:
        parts = line.split("  ", 1)
        if len(parts) != 2 or len(parts[0]) != 64:
            errors.append("SHA256SUMS: malformed entry")
            continue
        listed[parts[1]] = parts[0]
    if MANIFEST_NAME not in listed:
        errors.append("SHA256SUMS: manifest.json is not listed")
    for relative, expected in listed.items():
        try:
            actual = sha256_file(data_dir / relative)
        except OSError:
            errors.append(f"SHA256SUMS: {relative} is missing")
            continue
        if actual != expected:
            errors.append(f"SHA256SUMS: {relative} checksum mismatch")

    health = manifest.get("health")
    if isinstance(health, dict):
        if "health.json" not in declared:
            errors.append("manifest.json: checksum for health.json is missing")
        try:
            document = json.loads((data_dir / "health.json").read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            errors.append("health.json: missing or invalid JSON")
            return
        if "://" in json.dumps(document):
            errors.append("health.json: contains a URL or node URI")
        if document.get("version") != 1:
            errors.append("health.json: unsupported version")
        nodes = document.get("nodes")
        if not isinstance(nodes, list):
            errors.append("health.json: nodes must be a list")
        elif any("uri" in node for node in nodes if isinstance(node, dict)):
            errors.append("health.json: per-node URI must not be published")


def verify_or_raise(data_dir: Path) -> None:
    errors = verify_outputs(data_dir)
    if errors:
        raise IntegrityError("; ".join(errors))
