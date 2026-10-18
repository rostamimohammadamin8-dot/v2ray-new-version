"""Checksum, staging, and production-state verification tests."""

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
from scripts import integrity  # noqa: E402

UID = "44444444-4444-4444-4444-444444444444"
PAYLOAD = (
    f"vless://{UID}@de.example.com:443?security=tls#DE%20node\n"
    f"vless://{UID}@us.example.com:443?security=tls#US%20node\n"
    "hysteria2://pw@nl.example.com:443#NL%20node\n"
)


def build_state(root: Path) -> Path:
    config = root / "sources.json"
    config.write_text(
        json.dumps({"version": 1, "sources": [{"id": "fixture", "url": "https://fixture.example/sub", "enabled": True}]}),
        encoding="utf-8",
    )
    data = root / "data"
    agg.run(
        config,
        data,
        retries=0,
        fetch=lambda url, *, timeout, max_bytes: PAYLOAD.encode("utf-8"),
    )
    return data


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.data = build_state(self.root)

    def tearDown(self):
        self.tempdir.cleanup()

    def test_clean_state_verifies(self):
        self.assertEqual(integrity.verify_outputs(self.data), [])
        integrity.verify_or_raise(self.data)

    def test_manifest_shape_and_counts(self):
        manifest = json.loads((self.data / "manifest.json").read_text())
        self.assertEqual(manifest["node_count"], 3)
        self.assertEqual(manifest["counts"]["DE"], 1)
        self.assertIn("manifest.json", (self.data / "SHA256SUMS").read_text())
        self.assertNotIn("://", json.dumps(manifest))

    def test_tampered_feed_is_detected(self):
        feed = self.data / "subscriptions" / "global.txt"
        feed.write_text(feed.read_text() + f"vless://{UID}@evil.example.com:443#X\n")
        errors = integrity.verify_outputs(self.data)
        self.assertTrue(any("checksum" in error for error in errors), errors)
        self.assertTrue(any("node_count" in error for error in errors), errors)

    def test_snapshot_mismatch_is_detected(self):
        snapshot = self.data / "snapshot" / "global.txt"
        snapshot.write_text("")
        errors = integrity.verify_outputs(self.data)
        self.assertTrue(any("snapshot" in error for error in errors), errors)

    def test_manifest_checksum_missing_is_detected(self):
        path = self.data / "manifest.json"
        manifest = json.loads(path.read_text())
        del manifest["checksums"]["subscriptions/de.txt"]
        path.write_text(json.dumps(manifest))
        errors = integrity.verify_outputs(self.data)
        self.assertTrue(any("checksum for subscriptions/de.txt" in error for error in errors), errors)

    def test_duplicate_and_invalid_lines_are_detected(self):
        feed = self.data / "subscriptions" / "de.txt"
        feed.write_text("not-a-node\nnot-a-node\n")
        errors = integrity.verify_outputs(self.data)
        self.assertTrue(any("duplicate" in error for error in errors), errors)
        self.assertTrue(any("invalid node" in error for error in errors), errors)

    def test_missing_manifest(self):
        (self.data / "manifest.json").unlink()
        self.assertEqual(integrity.verify_outputs(self.data), ["manifest.json: missing or invalid JSON"])

    def test_unsafe_feed_path_is_detected(self):
        path = self.data / "manifest.json"
        manifest = json.loads(path.read_text())
        manifest["feeds"]["DE"] = "../escape.txt"
        path.write_text(json.dumps(manifest))
        errors = integrity.verify_outputs(self.data)
        self.assertTrue(any("unsafe feed path" in error for error in errors), errors)


class PublishTests(unittest.TestCase):
    def test_verify_failure_preserves_existing_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "data"
            output.mkdir()
            sentinel = output / "manifest.json"
            sentinel.write_text("known-good")
            with self.assertRaises(integrity.IntegrityError):
                integrity.publish_atomic(
                    output,
                    {"manifest.json": "{}", "SHA256SUMS": "bogus\n"},
                    verify=True,
                )
            self.assertEqual(sentinel.read_text(), "known-good")

    def test_checksum_helpers(self):
        self.assertEqual(
            integrity.sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )
        text = integrity.format_checksums({"b": "2", "a": "1"})
        self.assertEqual(text, "1  a\n2  b\n")
        self.assertEqual(
            integrity.checksums_text({"b": "2", "a": "1"}),
            f"{integrity.sha256_bytes(b'1')}  a\n{integrity.sha256_bytes(b'2')}  b\n",
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "file"
            path.write_bytes(b"abc")
            self.assertEqual(integrity.sha256_file(path), integrity.sha256_bytes(b"abc"))


if __name__ == "__main__":
    unittest.main()


class IntegrityEdgeTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.data = build_state(self.root)
        self.manifest_path = self.data / "manifest.json"

    def tearDown(self):
        self.tempdir.cleanup()

    def mutate(self, callback):
        manifest = json.loads(self.manifest_path.read_text())
        callback(manifest)
        self.manifest_path.write_text(json.dumps(manifest))
        return integrity.verify_outputs(self.data)

    def test_non_object_manifest(self):
        self.manifest_path.write_text("[]")
        self.assertIn("manifest.json: root must be an object", integrity.verify_outputs(self.data))

    def test_url_leak_in_manifest(self):
        errors = self.mutate(lambda m: m.update({"note": "https://example.com/sub"}))
        self.assertTrue(any("URL or node URI" in error for error in errors), errors)

    def test_missing_feed_label(self):
        errors = self.mutate(lambda m: m["feeds"].pop("DE"))
        self.assertTrue(any("feed DE is missing" in error for error in errors), errors)

    def test_missing_checksums_map(self):
        errors = self.mutate(lambda m: m.pop("checksums"))
        self.assertTrue(any("checksums map is missing" in error for error in errors), errors)

    def test_snapshot_missing_and_invalid(self):
        (self.data / "snapshot" / "global.txt").unlink()
        errors = integrity.verify_outputs(self.data)
        self.assertTrue(any("snapshot" in error for error in errors), errors)
        errors = self.mutate(lambda m: m.update({"snapshot": 42}))
        self.assertTrue(any("snapshot path is invalid" in error for error in errors), errors)

    def test_checksum_entry_missing_file(self):
        errors = self.mutate(lambda m: m["checksums"].update({"ghost.txt": "0" * 64}))
        self.assertTrue(any("ghost.txt" in error and "missing" in error for error in errors), errors)

    def test_bad_sum_files(self):
        (self.data / "SHA256SUMS").write_text("malformed\n")
        errors = integrity.verify_outputs(self.data)
        self.assertTrue(any("SHA256SUMS: malformed" in error for error in errors), errors)
        self.assertTrue(any("manifest.json is not listed" in error for error in errors), errors)
        (self.data / "SHA256SUMS").write_text("")
        self.assertIn("SHA256SUMS: empty", integrity.verify_outputs(self.data))

    def test_health_metadata_errors(self):
        errors = self.mutate(lambda m: m.update({"health": {"checked": 1}}))
        self.assertTrue(any("health.json" in error for error in errors), errors)
        self.mutate(lambda m: m["checksums"].update({"health.json": "0" * 64}))
        (self.data / "health.json").write_text("not json")
        errors = integrity.verify_outputs(self.data)
        self.assertTrue(any("health.json: missing or invalid JSON" in error for error in errors), errors)

    def test_health_document_url_and_version(self):
        self.mutate(lambda m: m.update({"health": {"checked": 1}}))
        health_path = self.data / "health.json"
        health_path.write_text(json.dumps({"version": 2, "nodes": [], "url": "https://x"}))
        errors = integrity.verify_outputs(self.data)
        self.assertTrue(any("health.json: contains a URL" in error for error in errors), errors)
        self.assertTrue(any("health.json: unsupported version" in error for error in errors), errors)
        health_path.write_text(json.dumps({"version": 1, "nodes": "nope"}))
        errors = integrity.verify_outputs(self.data)
        self.assertTrue(any("health.json: nodes must be a list" in error for error in errors), errors)
        health_path.write_text(json.dumps({"version": 1, "nodes": [{"uri": "x"}]}))
        errors = integrity.verify_outputs(self.data)
        self.assertTrue(any("per-node URI" in error for error in errors), errors)


class IntegrityMoreTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.data = build_state(self.root)

    def tearDown(self):
        self.tempdir.cleanup()

    def test_feed_encoding_cr_and_blank_errors(self):
        feed = self.data / "subscriptions" / "de.txt"
        feed.write_bytes(b"\xff\xfe")
        errors = integrity.verify_outputs(self.data)
        self.assertTrue(any("not valid UTF-8" in error for error in errors), errors)
        feed.write_bytes(b"line1\r\n")
        errors = integrity.verify_outputs(self.data)
        self.assertTrue(any("CR line endings" in error for error in errors), errors)
        feed.write_bytes(b"\n")
        errors = integrity.verify_outputs(self.data)
        self.assertTrue(any("blank lines" in error for error in errors), errors)

    def test_missing_feed_file(self):
        (self.data / "subscriptions" / "de.txt").unlink()
        errors = integrity.verify_outputs(self.data)
        self.assertTrue(any("cannot read" in error for error in errors), errors)

    def test_feeds_without_global(self):
        path = self.data / "manifest.json"
        manifest = json.loads(path.read_text())
        manifest["feeds"] = {"DE": "subscriptions/de.txt"}
        path.write_text(json.dumps(manifest))
        self.assertIn("manifest.json: feeds map with GLOBAL is required", integrity.verify_outputs(self.data))

    def test_invalid_checksum_entry_type(self):
        path = self.data / "manifest.json"
        manifest = json.loads(path.read_text())
        manifest["checksums"]["bad"] = 42
        path.write_text(json.dumps(manifest))
        errors = integrity.verify_outputs(self.data)
        self.assertTrue(any("invalid checksum entry" in error for error in errors), errors)

    def test_missing_sha_file(self):
        (self.data / "SHA256SUMS").unlink()
        self.assertIn("SHA256SUMS: missing or unreadable", integrity.verify_outputs(self.data))

    def test_verify_success_prints(self):
        from scripts import verify

        self.assertEqual(verify.main(["--data-dir", str(self.data)]), 0)
