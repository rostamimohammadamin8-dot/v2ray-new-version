"""Strict protocol parser tests."""

from __future__ import annotations

import base64
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import proxy_uri as pu  # noqa: E402

UID = "11111111-1111-1111-1111-111111111111"
UID2 = "22222222-2222-2222-2222-222222222222"


def vmess(name="node", host="example.com", port=443, **overrides):
    data = {
        "v": "2",
        "ps": name,
        "add": host,
        "port": str(port),
        "id": UID,
        "aid": "0",
        "net": "ws",
        "type": "none",
        "host": "cdn.example.com",
        "path": "/ws",
        "tls": "tls",
    }
    data.update(overrides)
    return "vmess://" + base64.b64encode(json.dumps(data).encode()).decode()


class ValidParserTests(unittest.TestCase):
    def test_vless_tls_fields(self):
        node = pu.parse_node(
            f"vless://{UID}@de.example.com:443?security=reality&sni=edge.example.com&type=grpc#DE"
        )
        self.assertEqual(node.protocol, "vless")
        self.assertEqual(node.endpoint, ("de.example.com", 443))
        self.assertEqual(node.uuid, UID)
        self.assertTrue(node.tls)
        self.assertEqual(node.security, "reality")
        self.assertEqual(node.sni, "edge.example.com")
        self.assertEqual(node.transport, "grpc")

    def test_vmess_json_fields(self):
        node = pu.parse_node(vmess("US node", "us.example.com", 8443))
        self.assertEqual(node.protocol, "vmess")
        self.assertEqual(node.name, "US node")
        self.assertEqual(node.endpoint, ("us.example.com", 8443))
        self.assertTrue(node.tls)
        self.assertEqual(node.transport, "ws")

    def test_trojan_requires_password(self):
        node = pu.parse_node("trojan://secret@uk.example.com:443?sni=uk.example.com#UK")
        self.assertEqual(node.password, "secret")
        self.assertTrue(node.tls)
        self.assertEqual(node.sni, "uk.example.com")

    def test_ss_sip002_base64_userinfo(self):
        userinfo = base64.b64encode(b"aes-256-gcm:pa:ss").decode()
        node = pu.parse_node(f"ss://{userinfo}@1.2.3.4:8388#Tokyo")
        self.assertEqual(node.method, "aes-256-gcm")
        self.assertEqual(node.password, "pa:ss")

    def test_ss_plain_userinfo_and_legacy_payload(self):
        plain = pu.parse_node("ss://chacha20-ietf-poly1305:pw@host.example:443#N")
        self.assertEqual(plain.password, "pw")
        legacy = base64.b64encode(b"aes-128-gcm:legacy@legacy.example:8388").decode()
        node = pu.parse_node(f"ss://{legacy}#Old")
        self.assertEqual(node.endpoint, ("legacy.example", 8388))
        self.assertEqual(node.password, "legacy")

    def test_hysteria2_and_tuic(self):
        hy = pu.parse_node("hysteria2://auth@1.2.3.4:443?sni=edge.example#NL")
        self.assertEqual(hy.protocol, "hysteria2")
        self.assertEqual(hy.password, "auth")
        self.assertTrue(hy.tls)
        tuic = pu.parse_node(f"tuic://{UID}:secret@1.2.3.4:443#FR")
        self.assertEqual(tuic.uuid, UID)
        self.assertEqual(tuic.password, "secret")
        self.assertTrue(tuic.tls)

    def test_generic_proxies(self):
        socks = pu.parse_node("socks5://user:pass@host.example:1080#S")
        self.assertEqual(socks.password, "pass")
        ssh = pu.parse_node("ssh://root@host.example:22#SSH")
        self.assertEqual(ssh.protocol, "ssh")
        wg = pu.parse_node("wireguard://key@host.example:51820#WG")
        self.assertEqual(wg.port, 51820)

    def test_ipv6_host_and_insecure_warning(self):
        node = pu.parse_node("vless://%s@[2001:db8::1]:443?security=tls&allowInsecure=1#v6" % UID)
        self.assertEqual(node.host, "2001:db8::1")
        self.assertIn("insecure_tls", node.warnings)

    def test_weak_cipher_warning(self):
        node = pu.parse_node("ss://none:pw@host.example:8388#weak")
        self.assertIn("weak_cipher", node.warnings)

    def test_redaction_and_fingerprint(self):
        uri = f"vless://{UID}@host.example:443#Secret%20Name"
        node = pu.parse_node(uri)
        self.assertEqual(node.fingerprint(), pu.fingerprint(uri))
        self.assertNotIn(UID, repr(node))
        self.assertNotIn("Secret", pu.redact_uri(uri))
        self.assertIn("<redacted>", pu.redact_uri(uri))


class RejectionTests(unittest.TestCase):
    def assert_rejected(self, uri, reason=None):
        with self.assertRaises(pu.NodeValidationError) as caught:
            pu.parse_node(uri)
        if reason:
            self.assertEqual(caught.exception.reason, reason)

    def test_empty_and_malformed(self):
        for uri in ("", "   ", "not-a-uri", "ftp://host:21#x", "vless://"):
            with self.subTest(uri=uri):
                self.assert_rejected(uri)

    def test_control_characters_and_length(self):
        self.assert_rejected(f"vless://{UID}@host:443#bad name")
        self.assert_rejected(f"vless://{UID}@host:443#bad\x00name")
        self.assert_rejected(f"vless://{UID}@host:443#" + "a" * pu.MAX_URI_LENGTH)

    def test_credentials_are_mandatory(self):
        self.assert_rejected("vless://@host:443#n", "missing UUID")
        self.assert_rejected("vless://not-a-uuid@host:443#n", "invalid UUID")
        self.assert_rejected("trojan://@host:443#n", "trojan requires a password")
        self.assert_rejected("hysteria2://@host:443#n", "hysteria2 requires credentials")
        self.assert_rejected(f"tuic://{UID}@host:443#n", "tuic requires a password")
        self.assert_rejected("ss://@host:443#n")
        self.assert_rejected("ss://aes-256-gcm:@host:443#n", "ss requires a password")

    def test_invalid_ports_and_hosts(self):
        self.assert_rejected(f"vless://{UID}@host:0#n", "invalid port")
        self.assert_rejected(f"vless://{UID}@host:70000#n", "invalid port")
        self.assert_rejected(f"vless://{UID}@bad_host:443#n", "invalid host")
        self.assert_rejected("trojan://pw@host#n")

    def test_bad_vmess_payload(self):
        self.assert_rejected("vmess://not-base64!", "invalid base64 value")
        broken = base64.b64encode(b"{not json}").decode()
        self.assert_rejected(f"vmess://{broken}", "invalid vmess payload")
        no_uuid = base64.b64encode(json.dumps({"add": "host", "port": 443}).encode()).decode()
        self.assert_rejected(f"vmess://{no_uuid}", "missing UUID")

    def test_generic_credentials_must_be_paired(self):
        self.assert_rejected("socks5://user@host:1080#n")
        self.assert_rejected("http://:pass@host:8080#n")

    def test_warning_flags(self):
        plain = pu.parse_node(f"vless://{UID}@host:443?security=none#plain")
        self.assertIn("plaintext_transport", plain.warnings)
        downgraded = pu.parse_node("trojan://pw@host:443?security=none#down")
        self.assertIn("tls_downgrade", downgraded.warnings)
        insecure = pu.parse_node("trojan://pw@host:443?allowInsecure=1#insecure")
        self.assertIn("insecure_tls", insecure.warnings)


if __name__ == "__main__":
    unittest.main()


class MoreEdgeTests(unittest.TestCase):
    def test_invalid_host_and_port_helpers(self):
        with self.assertRaises(pu.NodeValidationError):
            pu._validate_host("a" * 300)
        with self.assertRaises(pu.NodeValidationError):
            pu._validate_port("not-a-port")
        with self.assertRaises(pu.NodeValidationError):
            pu._split_host_port("host")

    def test_vmess_requires_object_and_address(self):
        for payload in ([], {"add": "", "port": 443, "id": UID}, {"add": "host", "port": 443}):
            encoded = base64.b64encode(json.dumps(payload).encode()).decode()
            with self.assertRaises(pu.NodeValidationError):
                pu.parse_node(f"vmess://{encoded}")

    def test_ss_malformed_legacy_payloads(self):
        no_at = base64.b64encode(b"aes-256-gcm:pw").decode()
        with self.assertRaises(pu.NodeValidationError):
            pu.parse_node(f"ss://{no_at}")
        no_colon = base64.b64encode(b"pw@host:443").decode()
        with self.assertRaises(pu.NodeValidationError):
            pu.parse_node(f"ss://{no_colon}")
        bad_b64 = pu._b64decode(base64.b64encode(b"x@y:1").decode())  # sanity
        self.assertIsInstance(bad_b64, bytes)

    def test_missing_endpoints_for_special_protocols(self):
        for uri in (
            "hysteria2://pw@#x",
            f"tuic://{UID}:pw@#x",
            "trojan://pw@#x",
        ):
            with self.subTest(uri=uri):
                with self.assertRaises(pu.NodeValidationError):
                    pu.parse_node(uri)

    def test_generic_warnings(self):
        self.assertIn("missing_ssh_user", pu.parse_node("ssh://host.example:22#x").warnings)
        self.assertIn("missing_wireguard_key", pu.parse_node("wireguard://host.example:51820#x").warnings)

    def test_helpers_tolerate_invalid_input(self):
        self.assertIsNone(pu.try_parse_node("bad"))
        self.assertIsNone(pu.node_endpoint("bad"))
        self.assertEqual(pu.node_name("vless://bad@host:443#Fallback"), "Fallback")
        self.assertEqual(pu.redact_uri("bad"), "<invalid-node>")
