# Implementations, sibling suites and references

Who validates against this suite, the sibling conformance suites, and the
specifications and issues it builds on.

## Implementations that validate against this suite

| Implementation | Verifier | Status |
|---|---|---|
| `opena2a-standards/aip-conformance/verifiers/go` (this repo) | Go, Ed25519 (standard library) | 11 / 11 PASS |
| `opena2a-standards/aip-conformance/verifiers/python` (this repo) | Python, Ed25519 (`cryptography`) | 11 / 11 PASS |

Independent second-party implementations and cosigners are tracked in
[`COSIGNERS.md`](../COSIGNERS.md) and on the sibling issue
[`a2aproject/A2A#1885`](https://github.com/a2aproject/A2A/issues/1885).

## Sibling repositories

| Repo | Spec | Status |
|---|---|---|
| [`atx-conformance`](https://github.com/opena2a-standards/atx-conformance) | ATX v1.0 credential schema | Go and Python verifiers, `MANIFEST.sha256` pinned; its README reports the fixture count |
| [`atp-conformance`](https://github.com/opena2a-standards/atp-conformance) | ATP v1.0.0-rc1 protocol | Go and Python verifiers, `MANIFEST.sha256` pinned; its README reports the fixture count |
| `aip-conformance` (this repo) | AIP v1.0.0-draft identity protocol | v0.3: 8 §5.1 challenge-response fixtures and 3 §6.1 trust-score composition fixtures, 2 verifiers, `MANIFEST.sha256` pinned; §6.4 covered transitively via `atx-conformance` cross-link |

## References

- [AIP-SPEC.md](https://github.com/opena2a-org/agent-identity-protocol/blob/main/AIP-SPEC.md) — the spec under test
- [AIP §5.1 Challenge-Response Protocol](https://github.com/opena2a-org/agent-identity-protocol/blob/main/AIP-SPEC.md#51-challenge-response-protocol) — the protocol surface this suite covers
- [`a2aproject/A2A#1885`](https://github.com/a2aproject/A2A/issues/1885) — the public maturity-bar claim this work delivers against
- [`atx-conformance`](https://github.com/opena2a-standards/atx-conformance) — covers AIP §6.4 (VC `AgentTrustCredential`) transitively; same `issuer-primary` keypair as this suite
- [`atp-conformance`](https://github.com/opena2a-standards/atp-conformance) — covers ATP wire protocol; the closest structural pattern this suite mirrors
- [`opena2a-standards/did-method-opena2a`](https://github.com/opena2a-standards/did-method-opena2a) (Apache-2.0), the formal specification of the `did:opena2a:<type>:<id>` DID method used by this suite's challenge and response fixtures; filed for W3C DID Extensions registry inclusion on [`w3c/did-extensions#717`](https://github.com/w3c/did-extensions/pull/717)
