# Architecture: Self-Healing Proxy Feed Orchestrator

This document describes the production architecture behind `scripts/aggregate.py`.
The core is dependency-free (Python 3.12 standard library) and every external
service is optional; a gateway outage cannot block or corrupt publication.

## 1. Trust boundaries and invariants

```text
 untrusted upstream feeds
          |  HTTPS only, 15s/attempt, 5 MiB, redirect downgrade denied
          v
 +---------------------+     strict UTF-8 / Base64 / URI / credential checks
 | aggregate.py        |--------------------------------------------------+
 |  fetch -> parse     |                                                  |
 |  dedupe -> label    |      +----------------------+                    |
 |  optional probe     |----->| health.py            | async TCP/TLS      |
 |  build manifest     |      | advisory scores only |                    |
 +----------+----------+      +----------------------+                    |
            |                                                             |
            v                                                             v
 +---------------------+      checksum + schema + feed validation before swap
 | integrity.py        |---------------------------------------------------+
 |  stage -> verify    |
 |  atomic publish     |      feeds -> snapshot -> manifest -> SHA256SUMS
 +----------+----------+
            |
            +--> optional, sanitized telemetry --> ai_ops.py --> 9Router
```

Non-negotiable invariants:

1. **No partial publication.** Parsing, validation, probing, manifest creation,
   checksums, and staged verification all complete before the first file is
   moved. Any exception leaves the previous `data/` tree byte-identical.
2. **No credential leakage.** Credentials live only inside `ProxyNode` fields
   excluded from `repr()`. Manifest, checksums, and health documents contain no
   URI, host, credential, or source URL.
3. **No silent downgrade.** Non-HTTPS source URLs and non-HTTPS redirect hops are
   rejected. TLS-related warnings (`tls_downgrade`, `insecure_tls`) are surfaced
   in the manifest instead of being discarded.
4. **No unverified handoff.** `publish_atomic(..., verify=True)` verifies the
   staged tree (schema, UTF-8, dedupe, URI validity, counts, checksums, snapshot)
   before swapping files into production.
5. **Exit-code integrity.** Success is `0`; fetch/parse/integrity/validation
   failure is `1`; usage/configuration errors are `2`.

## 2. Module responsibilities

| Module | Responsibility | Never does |
|---|---|---|
| `scripts/proxy_uri.py` | Per-protocol parsers, credential/UUID/port/host validation, warnings, redaction, fingerprints | Network I/O, file I/O |
| `scripts/aggregate.py` | Source config, HTTPS fetch + retry, payload decode, dedupe, labels, orchestration, manifest | Trust upstream input |
| `scripts/health.py` | Bounded async TCP/TLS probes, latency percentiles, 0-100 advisory score | Claim a proxy tunnel works |
| `scripts/integrity.py` | SHA256 helpers, staged atomic publisher, offline verifier | Publish unverified files |
| `scripts/ai_ops.py` | Optional 9Router health/models/chat client, sanitization, review/diagnosis | Block a run or receive secrets |
| `scripts/verify.py` | Operator/CI CLI for the offline verifier | Modify state |

## 3. Protocol layer

`proxy_uri.parse_node()` dispatches to dedicated parsers:

- **VLESS**: UUID (canonicalized), host/port, `security` (`tls`, `reality`,
  `xtls`, `none`), SNI, transport.
- **VMess**: strict Base64 JSON, UUID, address/port, TLS/net/SNI, display name.
- **Trojan**: non-empty password, default TLS, downgrade/insecure warnings.
- **Shadowsocks**: SIP002 plain/Base64 userinfo and legacy whole-payload form;
  method syntax, non-empty password, weak-cipher warning.
- **Hysteria/Hysteria2**: non-empty auth, TLS/SNI, insecure warning.
- **TUIC**: canonical UUID + non-empty password, TLS/SNI.
- **SOCKS/HTTP(S)/SSH/WireGuard**: host/port, paired username/password policy,
  protocol-specific warnings.

Rejected inputs never reach the publisher: empty credentials, malformed UUIDs,
ports outside 1-65535, control characters, whitespace inside a URI, invalid DNS
labels/IPs, malformed Base64/JSON, and unsupported schemes.

## 4. Health and scoring

Probes are async with a semaphore (default 32, capped 64). Each node gets:

- `tcp_ok`, `tls_ok` (handshake only unless `--verify-tls`), latency, error class;
- score: 60 reachable + 20 required-TLS handshake + up to 20 latency credit;
- `tls_required` derived from the URI, not guessed from the score;
- per-node identity is a truncated SHA256 fingerprint, never the URI.

`health.json` is advisory. A TCP accept or TLS hello is **not** proof of a
working proxy, authentication, location, or trust. `--require-reachable` is the
only mode that filters nodes, and it fails closed if none survive.

## 5. Labels and confidence

Country labels (`DE`, `US`, `NL`, `TR`, `FR`, `UK`, `CA`, `GLOBAL`) are heuristic:
remarks/flags score 5-6, country codes 3, cities 2, hostname TLD hints 1-2. Ties
and unknown nodes fall back to `GLOBAL`. `label_confidence` reports the average
confidence of classified nodes and the evidence source counts; it is not
geolocation.

## 6. State integrity contract

Published tree:

```text
data/
├── manifest.json          # counts, feeds, sources, warnings, hashes
├── SHA256SUMS             # sha256sum-compatible, includes manifest
├── health.json            # optional, checksummed sidecar
├── snapshot/global.txt    # last-known-good offline copy
└── subscriptions/*.txt    # GLOBAL + country feeds
```

`manifest.checksums` covers every feed, the snapshot, and optional health data.
`SHA256SUMS` additionally covers `manifest.json`. The verifier rejects missing
files, checksum mismatches, duplicate/blank/invalid lines, non-UTF-8 data, count
mismatches, country feeds outside GLOBAL, stale snapshots, unsafe paths, and
URLs/URIs leaking into metadata.

## 7. AI telemetry and self-healing

`ai_ops.py` is opt-in (`--ai-review`, `--ai-diagnose`, or the CLI). It:

- requires HTTPS or loopback HTTP before sending an API key;
- strips URIs, bearer tokens, keys, long tokens, and sensitive keys;
- bounds depth, collection size, string length, response size, and token output;
- instructs the model never to disable validation/TLS/checksums/atomicity;
- treats gateway failure as a warning, never as a publication failure.

Self-healing is deliberately conservative: transient fetches retry with bounded
exponential backoff, failed runs preserve the last-known-good tree, and AI output
is advisory (diagnosis/review), never an automatic mutation of trusted state.

## 8. CI/CD

The workflow runs tests, aggregation, and `verify.py`, uploads the verified tree,
and commits only when `data/` changed. Scheduled runs are unprivileged except for
`contents: write`; health and AI review are manual dispatch options. Workflow
files must be added by a principal with the GitHub `workflows` permission (see
`ci/update-subscriptions.yml`).

## 9. Test and coverage strategy

`python -m unittest discover -s tests -v` runs 163 tests, including real loopback
TCP connectors, mocked TLS peers, gateway mocks, checksum tampering, malformed
payloads, and CLI exit codes. A stdlib `trace` run reports 100% coverage of module
logic in `proxy_uri.py`, `health.py`, `integrity.py`, and `aggregate.py`; the only
uncovered lines are the `if __name__ == "__main__"` guards and the direct-run
`sys.path` bootstrap. No third-party test runner or coverage package is required.

## 10. Extension points

- Add a protocol: implement `_parse_<scheme>` in `proxy_uri.py`, register it in
  `_PARSERS`, add valid/invalid/warning tests.
- Add a feed: extend `COUNTRIES`/`FEED_LABELS`; the verifier and manifest follow.
- Add a probe: implement an async connector with the
  `(host, port, ...) -> latency_ms` contract in `health.py`.
- Add an AI provider: keep `GatewayConfig`; preserve sanitization and bounds.
