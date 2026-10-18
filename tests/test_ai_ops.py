"""Gateway client, sanitization, and graceful-degradation tests."""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import ai_ops  # noqa: E402


class FakeResponse:
    def __init__(self, payload: bytes):
        self._stream = io.BytesIO(payload)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, size=-1):
        return self._stream.read(size)


class SanitizeTests(unittest.TestCase):
    def test_secrets_and_uris_are_removed(self):
        payload = {
            "uri": "vless://uuid@host:443#name",
            "password": "hunter2",
            "api_key": "sk-abcdefghijk",
            "note": "failed vless://uuid@host:443 and sk-abcdefghijk Bearer abcdefghijkl",
            "checksum": "a" * 64,
        }
        clean = ai_ops.sanitize(payload)
        serialized = json.dumps(clean)
        self.assertNotIn("vless://", serialized)
        self.assertNotIn("hunter2", serialized)
        self.assertNotIn("sk-abcdefghijk", serialized)
        self.assertEqual(clean["uri"], "<redacted>")
        self.assertEqual(clean["password"], "<redacted>")

    def test_bounds_depth_and_size(self):
        deep = {"a": {"b": {"c": {"d": {"e": {"f": {"g": "too deep"}}}}}}}
        self.assertIn("truncated", json.dumps(ai_ops.sanitize(deep)))
        self.assertLessEqual(len(ai_ops.sanitize({"k": [1] * 100})["k"]), 50)
        self.assertLessEqual(len(ai_ops.sanitize("x" * 5000)), 500)

    def test_primitives_pass_through(self):
        self.assertEqual(ai_ops.sanitize(None), None)
        self.assertEqual(ai_ops.sanitize(True), True)
        self.assertEqual(ai_ops.sanitize(7), 7)


class ConfigTests(unittest.TestCase):
    def test_gateway_url_validation(self):
        self.assertEqual(ai_ops._validate_base_url("https://ai.example.com/", "key"), "https://ai.example.com")
        with self.assertRaises(ai_ops.GatewayError):
            ai_ops._validate_base_url("ftp://example.com", None)
        with self.assertRaises(ai_ops.GatewayError):
            ai_ops._validate_base_url("http://example.com", "secret")
        self.assertEqual(ai_ops._validate_base_url("http://localhost:20128", "secret"), "http://localhost:20128")

    def test_env_timeout_is_safe(self):
        with mock.patch.dict(os.environ, {"NINEROUTER_TIMEOUT": "not-a-number"}, clear=False):
            self.assertEqual(ai_ops.GatewayConfig.from_env().timeout, ai_ops.DEFAULT_TIMEOUT)
        with mock.patch.dict(os.environ, {"NINEROUTER_TIMEOUT": "9999"}, clear=False):
            self.assertEqual(ai_ops.GatewayConfig.from_env().timeout, ai_ops.DEFAULT_TIMEOUT)


class RequestTests(unittest.TestCase):
    def test_request_json_parses_and_bounds(self):
        response = FakeResponse(b'{"ok":true}')
        with mock.patch.object(ai_ops.urllib.request, "urlopen", return_value=response):
            result = ai_ops._request_json(ai_ops.GatewayConfig(), "GET", "/api/health")
        self.assertEqual(result, {"ok": True})

    def test_request_json_rejects_bad_payloads(self):
        cases = [b"not-json", b"[]", b'{"error":{"message":"nope"}}', b"\xff"]
        for payload in cases:
            with self.subTest(payload=payload):
                with mock.patch.object(
                    ai_ops.urllib.request, "urlopen", return_value=FakeResponse(payload)
                ):
                    with self.assertRaises(ai_ops.GatewayError):
                        ai_ops._request_json(ai_ops.GatewayConfig(), "GET", "/v1/models")

    def test_request_json_handles_network_failure(self):
        with mock.patch.object(ai_ops.urllib.request, "urlopen", side_effect=OSError("down")):
            with self.assertRaises(ai_ops.GatewayError):
                ai_ops._request_json(ai_ops.GatewayConfig(), "GET", "/api/health")


class GatewayApiTests(unittest.TestCase):
    def test_health(self):
        with mock.patch.object(ai_ops, "_request_json", return_value={"ok": True}):
            self.assertTrue(ai_ops.health())
        with mock.patch.object(ai_ops, "_request_json", side_effect=ai_ops.GatewayError("x")):
            self.assertFalse(ai_ops.health())

    def test_models(self):
        payload = {"data": [{"id": "a/b"}, {"id": "c/d"}, {"bad": True}]}
        with mock.patch.object(ai_ops, "_request_json", return_value=payload):
            self.assertEqual(ai_ops.list_models(), ["a/b", "c/d"])
        with mock.patch.object(ai_ops, "_request_json", return_value={"data": "nope"}):
            with self.assertRaises(ai_ops.GatewayError):
                ai_ops.list_models()

    def test_chat_success_and_errors(self):
        payload = {"choices": [{"message": {"content": " review text "}}]}
        with mock.patch.object(ai_ops, "_request_json", return_value=payload) as request:
            self.assertEqual(ai_ops.chat([{"role": "user", "content": "hi"}]), "review text")
            body = request.call_args.args[3]
            self.assertFalse(body["stream"])
            self.assertEqual(body["model"], ai_ops.DEFAULT_MODEL)
        for bad in ({"choices": []}, {"choices": [{"message": {"content": ""}}]}):
            with mock.patch.object(ai_ops, "_request_json", return_value=bad):
                with self.assertRaises(ai_ops.GatewayError):
                    ai_ops.chat([{"role": "user", "content": "hi"}])
        with self.assertRaises(ai_ops.GatewayError):
            ai_ops.chat([])

    def test_review_and_diagnose_redact(self):
        captured = {}

        def fake_chat(messages, **kwargs):
            captured["messages"] = messages
            return "ok"

        with mock.patch.object(ai_ops, "chat", side_effect=fake_chat):
            self.assertEqual(ai_ops.review_manifest({"uri": "vless://x@host:443"}), "ok")
            self.assertNotIn("vless://", json.dumps(captured["messages"]))
            self.assertEqual(
                ai_ops.diagnose_failure("boom vless://x@host:443", {"sources": ["a"]}), "ok"
            )
            self.assertNotIn("vless://", json.dumps(captured["messages"]))


class CliTests(unittest.TestCase):
    def test_models_cli(self):
        with mock.patch.object(ai_ops, "list_models", return_value=["a/b"]):
            self.assertEqual(ai_ops.main(["models"]), 0)

    def test_health_cli_failure(self):
        with mock.patch.object(ai_ops, "health", return_value=False):
            self.assertEqual(ai_ops.main(["health"]), 1)

    def test_review_cli_writes_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            summary = Path(temporary) / "summary.json"
            output = Path(temporary) / "review.txt"
            summary.write_text('{"node_count": 1}')
            with mock.patch.object(ai_ops, "review_manifest", return_value="review"):
                self.assertEqual(ai_ops.main(["review", "--summary", str(summary), "--output", str(output)]), 0)
            self.assertEqual(output.read_text(), "review\n")

    def test_cli_gateway_error_exits_one(self):
        with mock.patch.object(ai_ops, "health", side_effect=ai_ops.GatewayError("down")):
            self.assertEqual(ai_ops.main(["health"]), 1)


if __name__ == "__main__":
    unittest.main()


class MoreRequestTests(unittest.TestCase):
    def test_post_headers_and_oversize(self):
        captured = {}

        def fake_urlopen(request, timeout):
            captured["headers"] = dict(request.header_items())
            captured["method"] = request.get_method()
            return FakeResponse(b'{"ok":true}')

        with mock.patch.object(ai_ops.urllib.request, "urlopen", side_effect=fake_urlopen):
            ai_ops._request_json(ai_ops.GatewayConfig(api_key="secret"), "POST", "/v1/chat", {"a": 1})
        self.assertEqual(captured["method"], "POST")
        self.assertIn("Authorization", captured["headers"])
        self.assertIn("Content-type", captured["headers"])

        huge = FakeResponse(b"x" * (ai_ops.MAX_RESPONSE_BYTES + 10))
        with mock.patch.object(ai_ops.urllib.request, "urlopen", return_value=huge):
            with self.assertRaises(ai_ops.GatewayError):
                ai_ops._request_json(ai_ops.GatewayConfig(), "GET", "/v1/models")

    def test_sanitize_mapping_limit(self):
        clean = ai_ops.sanitize({str(i): i for i in range(80)})
        self.assertLessEqual(len(clean), 51)
        self.assertTrue(clean["<truncated>"])

    def test_chat_retries_wider_after_in_progress(self):
        responses = [
            {"choices": [{"message": {"content": ""}, "finish_reason": "in_progress"}]},
            {"choices": [{"message": {"content": "done"}, "finish_reason": "stop"}]},
        ]
        with mock.patch.object(ai_ops, "_request_json", side_effect=responses) as request:
            self.assertEqual(ai_ops.chat([{"role": "user", "content": "x"}], max_tokens=100), "done")
        self.assertEqual(request.call_args_list[0].args[3]["max_tokens"], 100)
        self.assertEqual(request.call_args_list[1].args[3]["max_tokens"], 2000)

    def test_summary_loader_errors(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "summary.json"
            with self.assertRaises(ai_ops.GatewayError):
                ai_ops._load_summary(path)
            path.write_text("not json")
            with self.assertRaises(ai_ops.GatewayError):
                ai_ops._load_summary(path)
            path.write_text("[]")
            with self.assertRaises(ai_ops.GatewayError):
                ai_ops._load_summary(path)


class MoreCliTests(unittest.TestCase):
    def test_health_ok_and_base_url(self):
        with mock.patch.object(ai_ops, "health", return_value=True):
            self.assertEqual(ai_ops.main(["--base-url", "http://localhost:9", "health"]), 0)

    def test_review_stdout_and_diagnose(self):
        with tempfile.TemporaryDirectory() as temporary:
            summary = Path(temporary) / "summary.json"
            summary.write_text('{"node_count": 1}')
            with mock.patch.object(ai_ops, "review_manifest", return_value="review"):
                self.assertEqual(ai_ops.main(["review", "--summary", str(summary)]), 0)
            with mock.patch.object(ai_ops, "diagnose_failure", return_value="diagnosis"):
                self.assertEqual(
                    ai_ops.main(["diagnose", "--summary", str(summary), "--error", "boom"]), 0
                )
