"""Strict, dependency-free parsers for proxy node URIs.

Every parser returns an immutable :class:`ProxyNode` whose credential fields are
hidden from ``repr()`` so that accidental logging cannot leak secrets. Unknown
schemes, empty credentials, malformed UUIDs, invalid ports, and control
characters are rejected instead of being passed through to the publisher.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import re
import urllib.parse
import uuid as uuid_module
from dataclasses import dataclass, field

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

TLS_SECURITY_VALUES = frozenset({"tls", "reality", "xtls", "xtls-rprx-vision"})
UUID_SCHEMES = frozenset({"vmess", "vless", "tuic"})
TLS_DEFAULT_SCHEMES = frozenset({"trojan", "hysteria", "hysteria2", "hy2", "tuic", "https"})
WEAK_SS_METHODS = frozenset({"none", "plain", "rc4-md5", "table", "des-cfb"})
MAX_URI_LENGTH = 8192

_DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_METHOD_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


class NodeValidationError(ValueError):
    """A node URI failed strict validation. Message never contains credentials."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class ProxyNode:
    uri: str = field(repr=False)
    protocol: str
    host: str
    port: int
    name: str = ""
    uuid: str | None = field(default=None, repr=False)
    password: str | None = field(default=None, repr=False)
    method: str | None = None
    tls: bool = False
    security: str | None = None
    sni: str | None = None
    transport: str | None = None
    warnings: tuple[str, ...] = ()

    @property
    def endpoint(self) -> tuple[str, int]:
        return self.host, self.port

    def fingerprint(self) -> str:
        return hashlib.sha256(self.uri.encode("utf-8")).hexdigest()[:16]


def _b64decode(value: str) -> bytes:
    compact = re.sub(r"\s+", "", value or "")
    if not compact:
        raise NodeValidationError("empty base64 value")
    compact = compact.replace("-", "+").replace("_", "/")
    compact += "=" * ((-len(compact)) % 4)
    try:
        return base64.b64decode(compact, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise NodeValidationError("invalid base64 value") from exc


def _unquote(value: str | None) -> str:
    return urllib.parse.unquote(value or "").strip()


def _validate_host(value: str) -> str:
    host = (value or "").strip().strip("[]").rstrip(".").lower()
    if not host or _CONTROL_RE.search(host):
        raise NodeValidationError("invalid host")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise NodeValidationError("invalid host") from exc
    if len(host) > 253:
        raise NodeValidationError("host is too long")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    labels = host.split(".")
    if any(not _DNS_LABEL_RE.match(label) for label in labels):
        raise NodeValidationError("invalid host")
    return host


def _validate_port(value: object) -> int:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise NodeValidationError("invalid port") from exc
    if not 1 <= port <= 65535:
        raise NodeValidationError("invalid port")
    return port


def _validate_uuid(value: str | None) -> str:
    candidate = (value or "").strip().strip("{}")
    if not candidate:
        raise NodeValidationError("missing UUID")
    try:
        return str(uuid_module.UUID(candidate))
    except (ValueError, AttributeError) as exc:
        raise NodeValidationError("invalid UUID") from exc


def _split_host_port(hostport: str) -> tuple[str, int]:
    parsed = urllib.parse.urlsplit("//" + (hostport or "").strip())
    if not parsed.hostname or parsed.port is None:
        raise NodeValidationError("missing host or port")
    return _validate_host(parsed.hostname), _validate_port(parsed.port)


def _query(parsed: urllib.parse.SplitResult) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, values in urllib.parse.parse_qs(parsed.query, keep_blank_values=True).items():
        result[key.lower()] = values[-1].strip() if values else ""
    return result


def _tls_fields(
    query: dict[str, str], *, default_tls: bool = False
) -> tuple[bool, str | None, str | None, list[str]]:
    security = (query.get("security") or "").lower()
    if not security:
        security = "tls" if default_tls else "none"
    tls = security in TLS_SECURITY_VALUES or query.get("tls") in {"1", "true"}
    sni = query.get("sni") or query.get("peer") or query.get("servername") or query.get("host") or None
    warnings: list[str] = []
    if query.get("allowinsecure") in {"1", "true"} or query.get("insecure") in {"1", "true"}:
        warnings.append("insecure_tls")
    if security == "none" and default_tls:
        warnings.append("tls_downgrade")
    return tls, security, sni, warnings


def _fragment_name(uri: str) -> str:
    return _unquote(urllib.parse.urlsplit(uri).fragment)


def _naming(name: str, *warnings: str) -> tuple[str, tuple[str, ...]]:
    return name.strip(), tuple(dict.fromkeys(w for w in warnings if w))


def _parse_vmess(uri: str) -> ProxyNode:
    payload = uri[len("vmess://") :].split("#", 1)[0].strip()
    try:
        data = json.loads(_b64decode(payload).decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NodeValidationError("invalid vmess payload") from exc
    if not isinstance(data, dict):
        raise NodeValidationError("invalid vmess payload")
    host = _validate_host(str(data.get("add", "")))
    port = _validate_port(data.get("port"))
    node_uuid = _validate_uuid(str(data.get("id", "")))
    raw_security = str(data.get("tls") or data.get("security") or "none").lower()
    tls = raw_security in TLS_SECURITY_VALUES
    sni = str(data.get("sni") or data.get("host") or "").strip() or None
    transport = str(data.get("net") or "").strip() or None
    warnings: list[str] = []
    if raw_security == "none":
        warnings.append("plaintext_transport")
    name, warning_tuple = _naming(str(data.get("ps") or ""), *warnings)
    return ProxyNode(
        uri=uri,
        protocol="vmess",
        host=host,
        port=port,
        name=name,
        uuid=node_uuid,
        tls=tls,
        security=raw_security,
        sni=sni,
        transport=transport,
        warnings=warning_tuple,
    )


def _parse_vless(uri: str) -> ProxyNode:
    parsed = urllib.parse.urlsplit(uri)
    if not parsed.hostname or parsed.port is None:
        raise NodeValidationError("missing host or port")
    node_uuid = _validate_uuid(_unquote(parsed.username))
    query = _query(parsed)
    tls, security, sni, warnings = _tls_fields(query)
    if security == "none":
        warnings.append("plaintext_transport")
    return ProxyNode(
        uri=uri,
        protocol="vless",
        host=_validate_host(parsed.hostname),
        port=_validate_port(parsed.port),
        name=_fragment_name(uri),
        uuid=node_uuid,
        tls=tls,
        security=security,
        sni=sni,
        transport=query.get("type") or None,
        warnings=tuple(warnings),
    )


def _parse_trojan(uri: str) -> ProxyNode:
    parsed = urllib.parse.urlsplit(uri)
    if not parsed.hostname or parsed.port is None:
        raise NodeValidationError("missing host or port")
    password = _unquote(parsed.username)
    if not password:
        raise NodeValidationError("trojan requires a password")
    query = _query(parsed)
    tls, security, sni, warnings = _tls_fields(query, default_tls=True)
    return ProxyNode(
        uri=uri,
        protocol="trojan",
        host=_validate_host(parsed.hostname),
        port=_validate_port(parsed.port),
        name=_fragment_name(uri),
        password=password,
        tls=tls,
        security=security,
        sni=sni,
        transport=query.get("type") or None,
        warnings=tuple(warnings),
    )


def _parse_ss(uri: str) -> ProxyNode:
    body = uri[len("ss://") :]
    name = ""
    if "#" in body:
        body, fragment = body.split("#", 1)
        name = _unquote(fragment)
    body = body.split("?", 1)[0]
    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
    else:
        try:
            legacy = _b64decode(body).decode("utf-8", errors="strict")
        except (NodeValidationError, UnicodeDecodeError) as exc:
            raise NodeValidationError("invalid ss payload") from exc
        if "@" not in legacy:
            raise NodeValidationError("invalid ss payload")
        userinfo, hostport = legacy.rsplit("@", 1)
    userinfo = _unquote(userinfo)
    if ":" not in userinfo:
        try:
            userinfo = _b64decode(userinfo).decode("utf-8", errors="strict")
        except (NodeValidationError, UnicodeDecodeError) as exc:
            raise NodeValidationError("invalid ss credentials") from exc
    if ":" not in userinfo:
        raise NodeValidationError("invalid ss credentials")
    method, password = userinfo.split(":", 1)
    method = method.strip().lower()
    password = password.strip()
    if not method or not _METHOD_RE.match(method):
        raise NodeValidationError("invalid ss method")
    if not password:
        raise NodeValidationError("ss requires a password")
    host, port = _split_host_port(hostport)
    warnings = ("weak_cipher",) if method in WEAK_SS_METHODS else ()
    return ProxyNode(
        uri=uri,
        protocol="ss",
        host=host,
        port=port,
        name=name,
        password=password,
        method=method,
        warnings=warnings,
    )


def _require_auth(value: str | None, protocol: str) -> str:
    auth = _unquote(value)
    if not auth:
        raise NodeValidationError(f"{protocol} requires credentials")
    return auth


def _parse_hysteria(uri: str, protocol: str) -> ProxyNode:
    parsed = urllib.parse.urlsplit(uri)
    if not parsed.hostname or parsed.port is None:
        raise NodeValidationError("missing host or port")
    query = _query(parsed)
    auth = _unquote(parsed.username) or _unquote(parsed.password) or query.get("auth", "")
    auth = _require_auth(auth, protocol)
    tls, security, sni, warnings = _tls_fields(query, default_tls=True)
    return ProxyNode(
        uri=uri,
        protocol=protocol,
        host=_validate_host(parsed.hostname),
        port=_validate_port(parsed.port),
        name=_fragment_name(uri),
        password=auth,
        tls=tls,
        security=security,
        sni=sni,
        warnings=tuple(warnings),
    )


def _parse_tuic(uri: str) -> ProxyNode:
    parsed = urllib.parse.urlsplit(uri)
    if not parsed.hostname or parsed.port is None:
        raise NodeValidationError("missing host or port")
    node_uuid = _validate_uuid(_unquote(parsed.username))
    password = _unquote(parsed.password)
    if not password:
        raise NodeValidationError("tuic requires a password")
    query = _query(parsed)
    _tls, _security, sni, warnings = _tls_fields(query, default_tls=True)
    return ProxyNode(
        uri=uri,
        protocol="tuic",
        host=_validate_host(parsed.hostname),
        port=_validate_port(parsed.port),
        name=_fragment_name(uri),
        uuid=node_uuid,
        password=password,
        tls=True,
        security="tls",
        sni=sni,
        warnings=tuple(warnings),
    )


def _parse_generic(uri: str, protocol: str) -> ProxyNode:
    parsed = urllib.parse.urlsplit(uri)
    if not parsed.hostname or parsed.port is None:
        raise NodeValidationError("missing host or port")
    username = _unquote(parsed.username)
    password = _unquote(parsed.password)
    warnings: list[str] = []
    if protocol in {"socks", "socks5", "http", "https"}:
        if username and not password:
            raise NodeValidationError(f"{protocol} credentials require a password")
        if password and not username:
            raise NodeValidationError(f"{protocol} credentials require a username")
    if protocol == "ssh" and not username:
        warnings.append("missing_ssh_user")
    if protocol == "wireguard" and not (username or password or _query(parsed).get("privatekey")):
        warnings.append("missing_wireguard_key")
    return ProxyNode(
        uri=uri,
        protocol=protocol,
        host=_validate_host(parsed.hostname),
        port=_validate_port(parsed.port),
        name=_fragment_name(uri),
        password=password or None,
        tls=protocol == "https",
        security="tls" if protocol == "https" else None,
        warnings=tuple(warnings),
    )

_PARSERS = {
    "vmess": _parse_vmess,
    "vless": _parse_vless,
    "trojan": _parse_trojan,
    "ss": _parse_ss,
    "hysteria": lambda uri: _parse_hysteria(uri, "hysteria"),
    "hysteria2": lambda uri: _parse_hysteria(uri, "hysteria2"),
    "hy2": lambda uri: _parse_hysteria(uri, "hy2"),
    "tuic": _parse_tuic,
}


def parse_node(uri: str) -> ProxyNode:
    """Parse one URI into a validated :class:`ProxyNode`."""

    if not isinstance(uri, str) or not uri.strip():
        raise NodeValidationError("empty URI")
    uri = uri.strip()
    if len(uri) > MAX_URI_LENGTH:
        raise NodeValidationError("URI is too long")
    if _CONTROL_RE.search(uri) or any(char.isspace() for char in uri):
        raise NodeValidationError("URI contains whitespace or control characters")
    if "://" not in uri:
        raise NodeValidationError("URI has no scheme")
    scheme = uri.split("://", 1)[0].lower()
    if scheme not in SUPPORTED_SCHEMES:
        raise NodeValidationError(f"unsupported scheme: {scheme}")
    parser = _PARSERS.get(scheme)
    try:
        if parser is not None:
            return parser(uri)
        return _parse_generic(uri, scheme)
    except NodeValidationError:
        raise
    except ValueError as exc:
        reason = "invalid port" if "port" in str(exc).lower() else "invalid URI"
        raise NodeValidationError(reason) from exc


def try_parse_node(uri: str) -> ProxyNode | None:
    try:
        return parse_node(uri)
    except NodeValidationError:
        return None


def validate_node_uri(uri: str) -> None:
    parse_node(uri)


def node_endpoint(uri: str) -> tuple[str, int] | None:
    node = try_parse_node(uri)
    return node.endpoint if node else None


def node_name(uri: str) -> str:
    node = try_parse_node(uri)
    if node is not None:
        return node.name
    # Read-only convenience for diagnostics/classification: an invalid node can
    # still expose a display name, but it is never published or trusted.
    try:
        return _unquote(urllib.parse.urlsplit(uri).fragment)
    except ValueError:
        return ""


def fingerprint(uri: str) -> str:
    return hashlib.sha256(uri.encode("utf-8")).hexdigest()[:16]


def redact_uri(uri: str) -> str:
    """Return a log-safe descriptor (never includes credentials or names)."""

    node = try_parse_node(uri)
    if node is None:
        return "<invalid-node>"
    return f"{node.protocol}://<redacted>@{node.host}:{node.port}"
