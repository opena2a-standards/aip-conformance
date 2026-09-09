# aip-conformance

Conformance fixtures and reference verifiers for the
[Agent Identity Protocol (AIP) v1.0.0-draft](https://github.com/opena2a-org/agent-identity-protocol).

**Status: v0.2 — AIP §5.1 challenge-response transcript fixtures shipped
(4 fixtures, 2 verifiers, `MANIFEST.sha256` pinned). AIP §6.4 (VC
`AgentTrustCredential`) conformance is covered transitively via
[`atx-conformance`](https://github.com/opena2a-standards/atx-conformance).**

Each §5.1 fixture is a byte-stable JSON file that bundles an IdP-issued
challenge AND the agent's signed response with verifier configuration and
an expected outcome (ACCEPT or REJECT). Two SDK-independent reference
verifiers (Go and Python) walk the fixture set and report PASS or FAIL
per vector. Fixture bytes are pinned in
[`MANIFEST.sha256`](./MANIFEST.sha256).

This suite mirrors the pattern set by
[`atx-conformance`](https://github.com/opena2a-standards/atx-conformance)
(covers the ATX credential schema) and
[`atp-conformance`](https://github.com/opena2a-standards/atp-conformance)
(covers the ATP wire protocol). It closes the AIP-side of criterion (c)
on the OpenA2A maturity bar tracked in
[`a2aproject/A2A#1885`](https://github.com/a2aproject/A2A/issues/1885):
"peer-cosigned conformance fixtures for AIP, ATP, or ATX comparable to
the `aim-did-rfc9421/*` set."

License: Apache 2.0. All keypairs, seeds, and identifiers in this
repository are TEST-ONLY.

## Why AIP fixtures look different from ATX and ATP

The A2A coordination map issue
[`a2aproject/A2A#1885`](https://github.com/a2aproject/A2A/issues/1885)
publicly named the gap: criterion (c) on the OpenA2A maturity bar asks
for peer-cosigned conformance fixtures comparable to A2A-IDF's
`aim-did-rfc9421/*` set. ATX and ATP have natural byte-stable artifacts
(credentials, signed proofs, STH); AIP mostly does not.

Most of AIP is RUNTIME behavior: fine-grained authorization enforcement,
capability grants, audit-log emission, drift detection,
challenge-response verification. Only one of those surfaces — §5.1
challenge-response — produces a byte-stable artifact (a transcript) that
a second-party verifier can walk offline.

Four candidate AIP artifacts surfaced during scoping. Of these, three
collapse onto existing fixture suites and one is genuinely novel:

| Candidate | AIP section | Verdict |
|---|---|---|
| W3C Verifiable Credential `AgentTrustCredential` | §6.4 | **Overlaps ATX v1.0.** ATX is the agent-specific VC that ATP §4.6 carves out. §6.4 conformance is covered by cross-linking `atx-conformance`. |
| Signed `/authorize` response | §5 | **Collapses onto ATP trust proof.** Same canonical signing form, same Ed25519/hybrid path. Covered by `atp-conformance/fixtures/trust-proof-*`. |
| Trust score certificate over the 9-factor breakdown | §6 | **Collapses onto ATX `trustScore` field.** The 9-factor computation is already cited in `atx-conformance/README.md` and the value is already in every ATX credential. |
| Signed capability grant artifact | §4 | **Partially novel.** Underspecified canonical form in v1.0.0-draft; would need spec work before fixtures can pin a wire format. |
| Challenge-response transcript | §5.1 | **Novel — shipped at v0.2.** Challenge + response are deterministic given a fixed clock + fixed nonce + fixed keypair. Not covered by ATX or ATP. This suite is the AIP-native conformance surface. |

## Resolution (Decision 3, 2026-05-27)

**Chosen path: 3-C (cross-link + new §5.1 fixtures).** Both halves are
live as of v0.2 (2026-05-28):

| Option | Shape | Outcome |
|---|---|---|
| 3-A | Cross-link `atx-conformance` for §6.4; no new fixtures in this repo. | Rejected as standalone — too weak for the AIP-native §5.1 surface. |
| 3-B | Ship AIP §5.1 challenge-response fixtures only; no §6.4 cross-link. | Strictly dominated by 3-C — same fixture-build cost, missing one README paragraph. |
| 3-C | Cross-link `atx-conformance` for §6.4 AND ship a §5.1 challenge-response fixture suite. | **Selected and shipped at v0.2.** §6.4 reuses the ATX fixtures without duplication; §5.1 has its own dedicated suite as the AIP-native protocol surface. |

The maturity-bar (c) claim on
[`a2aproject/A2A#1885`](https://github.com/a2aproject/A2A/issues/1885)
is not treated as closed for AIP until at least one independent
(non-OpenA2A) Sigstore cosignature lands against this suite's
[`MANIFEST.sha256`](./MANIFEST.sha256). Self-cosigned baseline only at
v0.2.

## Honest scope notes

This is the section that future reviewers, second-implementation authors,
and A2A coordination-map readers should read before forming judgments.

### Canonicalization: 5 signed fields, not the full JSON

AIP §5.1 underspecifies what the agent signs ("Sign this challenge with
your private key"). This conformance suite pins the canonical signing
form as a 5-field pipe-delimited string, mirroring the ATX 11-field and
ATP 7-field precedent:

```
challenge | agentDid | nonce | issuedAt | expiresAt
```

Fields in the response body that are NOT covered by the signature include
`publicKey`, `keyId`, `signedAt`, `algorithm`. A consequence is that an
attacker who can write to a stored response could rewrite `signedAt`
without breaking signature verification. This is a known shape of the
pinned canonical form and is documented here so reviewers do not have to
discover it from the code. JCS-canonical JSON signing (RFC 8785) is a
candidate hardening for a future revision.

The 5-field signing prevents cross-RP replay: a signature over Alice's
challenge cannot be replayed at Bob's relying party because the agentDid
and IdP-issued nonce are part of the signed payload, and Bob's IdP would
issue different bytes.

### Challenge and response wire-format pinning (beyond AIP-SPEC §5.1)

AIP-SPEC §5.1 step 2 names only `{challenge, expiresAt}` on the IdP →
RP message; step 4 names only `{signature, publicKey}` on the agent → RP
message. This suite pins additional fields needed for byte-stable
conformance and unambiguous replay-prevention:

- Challenge body: `{challenge, agentDid, nonce, issuedAt, expiresAt, issuerDid}`
- Response body: `{agentDid, challenge, nonce, issuedAt, expiresAt, signature, publicKey, keyId, signedAt, algorithm}`

These pins are conformance-suite contracts, not spec changes. AIP-SPEC
v1.0.0-final may formalize them, narrow them, or replace them with
JCS-canonical JSON.

### Replay detection in a stateless verifier

AIP §5.1 mentions "Nonce not reused" but the spec is silent on how a
relying party tracks nonces. This conformance verifier is stateless by
default — each fixture is verified independently. To exercise the
NONCE_REPLAY path, the fixture self-declares the verifier's prior state
via `verifierState.seenNonces` (a list of base64-no-padding nonces the
verifier should treat as already-consumed). The replay fixture lists its
own nonce in that array.

### Trusted-issuer DID and keypair reuse with atx / atp conformance

The `issuer-primary` Ed25519 keypair in
[`vectors/issuer-primary.json`](./vectors/issuer-primary.json) is the
SAME bytes as
[`atx-conformance/vectors/issuer-primary.json`](https://github.com/opena2a-standards/atx-conformance/blob/main/vectors/issuer-primary.json)
and [`atp-conformance/vectors/issuer-primary.json`](https://github.com/opena2a-standards/atp-conformance/blob/main/vectors/issuer-primary.json):
RFC 8032 §7.1 Test 1 seed, `did:opena2a:authority:opena2a.org` issuer
DID. A peer cosigner who has already audited atx-conformance or
atp-conformance vectors can rely on the same audit for this suite. The
agent-bound and agent-unbound keypairs are RFC 8032 §7.1 Test 2 and Test
3 respectively. All three vector files are TEST-ONLY; the seeds are
publicly known and MUST NOT be used in production.

## Fixtures

All fixtures use:

- Trusted issuer DID: `did:opena2a:authority:opena2a.org` (the IdP that issued the challenge)
- Test agent DID: `did:opena2a:agent:agent_conformance_test_001`
- Pinned verifier clock: `2026-05-28T00:00:00Z`
- Agent-bound Ed25519 keypair source: [RFC 8032 §7.1 Test 2](https://datatracker.ietf.org/doc/html/rfc8032#section-7.1)
- Agent-unbound Ed25519 keypair source (wrong-key fixture): [RFC 8032 §7.1 Test 3](https://datatracker.ietf.org/doc/html/rfc8032#section-7.1)

| Fixture | Expected | Exercises |
|---|---|---|
| `fixtures/challenge-response-valid.json` | ACCEPT | Agent signs the canonical 5-field payload with its bound key; the response `publicKey` matches the agentDid's bound key in `verifierState.agentBindings`; the nonce is unseen; the challenge has not expired against the pinned verifier clock. The MUST-implement baseline. |
| `fixtures/challenge-response-wrong-key.json` | REJECT (UNTRUSTED_KEY) | Agent signs with the unbound key (`agent-unbound-key`). Signature is mathematically valid Ed25519, but the `publicKey` returned in the response does not match the bound key declared for `testAgentDid` in `verifierState.agentBindings`. |
| `fixtures/challenge-response-stale-challenge.json` | REJECT (CHALLENGE_EXPIRED) | `challenge.expiresAt` is 25 minutes earlier than `verifierState.clockRfc3339`. The signature is otherwise mathematically valid and made by the agent's bound key. |
| `fixtures/challenge-response-replay.json` | REJECT (NONCE_REPLAY) | Different challenge bytes from the valid fixture, but reuses its nonce. The signature is mathematically valid, the `publicKey` matches the bound key, the challenge is not expired — but the nonce appears in `verifierState.seenNonces`, modelling "a prior verification already consumed this nonce." |

The full requirement-to-fixture mapping is machine-readable in
[`conformance.json`](./conformance.json), regenerated from the fixtures by
[`scripts/conformance_profile.py`](./scripts/conformance_profile.py) and
CI-checked against drift. The profile also records what is covered
transitively (§6.4 via `atx-conformance`, §5 authorize responses via
`atp-conformance`) and what is not covered at all (§4 capability grants,
runtime surfaces) so suite-to-suite claims stay explicit.

## Continuous verification

[`.github/workflows/conformance.yml`](./.github/workflows/conformance.yml)
enforces every claim in this README on each push and pull request:

1. Both reference verifiers run against `fixtures/` and must report
   `4 pass, 0 fail`.
2. The fixture generator re-runs and the committed fixture bytes plus
   `MANIFEST.sha256` must reproduce exactly (byte-pin).
3. The cross-implementation parity gate
   ([`scripts/parity/parity.py`](./scripts/parity/parity.py)) asserts the Go
   and Python verifiers agree per fixture on gate status, verdict, and
   reject category, and publishes `parity-report.json` as a CI artifact.
4. `conformance.json` must match the fixture set.
5. Schema validation
   ([`scripts/schema_validation.py`](./scripts/schema_validation.py)): every
   fixture's `challengeResponse.challenge` / `.response` must validate against
   the AIP-SPEC machine-readable schemas, vendored under
   `schemas/vendor/agent-identity-protocol/` and byte-drift-gated against a
   pinned agent-identity-protocol ref.

## Running the verifiers

Both verifiers walk every `*.json` file in the directory you point them at
(or you may pass individual fixture files). Exit code is 0 if every
fixture's observed result matches the expected result and the rejection
category matches (when declared).

### Go

```bash
cd verifiers/go
go run . ../../fixtures
```

Depends on:

- Go 1.22 or later
- standard library only (no external Ed25519 dependency — uses `crypto/ed25519`)

### Python

```bash
cd verifiers/python
pip install -r requirements.txt
python verify.py ../../fixtures
```

Depends on:

- Python 3.11 or later
- `cryptography >= 42.0.0`

### Expected output

Both verifiers report `summary: 4 pass, 0 fail (4 fixtures)` against the
shipped fixture set. Any divergence on bytes (the fixture file was
modified) or on verifier semantics (the verifier has drifted from the
canonical signing form) shows up as one or more FAIL lines.

## Reproducing the fixtures

The fixtures in this repository are deterministic. To regenerate them
from the keypair vectors in [`vectors/`](./vectors):

```bash
cd scripts/generate-fixtures
go run .
```

The generator:

1. Loads each Ed25519 keypair vector. Re-derives the public key from the
   seed and panics on drift against the pinned `publicKeyHex`.
2. Constructs the challenge body, computes the pipe-delimited canonical
   5-field payload, Ed25519-signs it with the appropriate key.
3. Builds the response body with the back-refs to the challenge fields
   plus the signature, base64-no-padding public key, and signing metadata.
4. Marshals each fixture to byte-stable JSON (`encoding/json` with 2-space
   indent, fields in struct-declaration order) with a POSIX trailing
   newline.
5. Writes the fixture file. Recomputes its SHA-256. Updates
   `MANIFEST.sha256` in path-sorted order.

Re-running the generator MUST produce byte-identical fixtures. If the
bytes change, either (a) the generator changed, (b) the canonicalization
shifted, or (c) the Go standard library's `crypto/ed25519` implementation
changed (extremely unlikely). Any of those is a breaking change for
downstream verifiers.

## Version pinning

| Component | Version | Source |
|---|---|---|
| AIP spec | v1.0.0-draft | [`opena2a-org/agent-identity-protocol/AIP-SPEC.md`](https://github.com/opena2a-org/agent-identity-protocol/blob/main/AIP-SPEC.md) |
| `did:opena2a` method | v0.1 (W3C registration filed, PR `w3c/did-extensions#717`) | [`opena2a-standards/did-method-opena2a`](https://github.com/opena2a-standards/did-method-opena2a/blob/main/did-method-opena2a.md) |
| Ed25519 test vector source | RFC 8032 §7.1 Tests 1, 2, 3 | [datatracker.ietf.org/doc/html/rfc8032](https://datatracker.ietf.org/doc/html/rfc8032) |
| Go Ed25519 | `crypto/ed25519` (Go 1.22+ standard library) | [pkg.go.dev/crypto/ed25519](https://pkg.go.dev/crypto/ed25519) |
| Python Ed25519 | `cryptography >= 42.0.0` | [pyca/cryptography](https://github.com/pyca/cryptography) |
| Conformance fixture format | v1 (this repo) | [`fixtures/challenge-response-valid.json#$schema`](./fixtures/challenge-response-valid.json) |

The `agentDid`, `issuerDid`, and `keyId` strings in the vectors and fixtures
are ecosystem-scoped `did:opena2a` identifiers, carried as opaque strings per
AIP-SPEC §3.2. The suite pins the challenge-response transcript and the key
binding; DID resolution is not exercised, neither of `did:opena2a` nor of the
provider-scoped `did:web` identifiers an identity provider issues. The
`did:opena2a` registration is merged (`w3c/did-extensions#717`, 2026-07-04);
the pinned method version stays v0.1 until a fixture depends on a later
revision.

## Implementations that validate against this suite

| Implementation | Verifier | Status |
|---|---|---|
| `opena2a-standards/aip-conformance/verifiers/go` (this repo) | Go, Ed25519 (standard library) | 4 / 4 PASS |
| `opena2a-standards/aip-conformance/verifiers/python` (this repo) | Python, Ed25519 (`cryptography`) | 4 / 4 PASS |

Independent second-party implementations and cosigners are tracked in
[`COSIGNERS.md`](./COSIGNERS.md) and on the sibling issue
[`a2aproject/A2A#1885`](https://github.com/a2aproject/A2A/issues/1885).

## Sibling repositories

| Repo | Spec | Status |
|---|---|---|
| [`atx-conformance`](https://github.com/opena2a-standards/atx-conformance) | ATX v1.0 credential schema | 8 fixtures, 2 verifiers, `MANIFEST.sha256` pinned |
| [`atp-conformance`](https://github.com/opena2a-standards/atp-conformance) | ATP v1.0.0-rc1 protocol | 4 fixtures (discovery, trust-proof baseline, trust-proof hybrid, Signed Tree Head), 2 verifiers, `MANIFEST.sha256` pinned |
| `aip-conformance` (this repo) | AIP v1.0.0-draft identity protocol | v0.2: 4 §5.1 challenge-response fixtures, 2 verifiers, `MANIFEST.sha256` pinned; §6.4 covered transitively via `atx-conformance` cross-link |

## Repository layout

```
LICENSE                          Apache 2.0
README.md                        this file
MANIFEST.sha256                  per-fixture SHA-256 (path-sorted)
COSIGNERS.md                     second-party cosigner registry
fixtures/                        the 4 conformance fixtures (byte-stable JSON)
vectors/                         test keypair vectors (TEST-ONLY)
verifiers/go/                    Go reference verifier (Ed25519 stdlib)
verifiers/python/                Python reference verifier (Ed25519 cryptography)
scripts/generate-fixtures/       deterministic fixture generator (Go)
```

## Versioning and stability

- The conformance fixture file format (`$schema: fixture-v1`) is stable
  across patch revisions of this repository. Adding new fixture fields is
  a minor version bump; renaming or removing fields is a major version
  bump.
- The set of fixtures may grow. New fixtures are additive and do not
  invalidate prior `MANIFEST.sha256` entries; each new fixture appears as
  a new line in the manifest.
- Existing fixtures are immutable once published. If a fixture needs to
  change semantically, it ships under a new name. This is what makes
  `MANIFEST.sha256` a useful regression check.

## References

- [AIP-SPEC.md](https://github.com/opena2a-org/agent-identity-protocol/blob/main/AIP-SPEC.md) — the spec under test
- [AIP §5.1 Challenge-Response Protocol](https://github.com/opena2a-org/agent-identity-protocol/blob/main/AIP-SPEC.md#51-challenge-response-protocol) — the protocol surface this suite covers
- [`a2aproject/A2A#1885`](https://github.com/a2aproject/A2A/issues/1885) — the public maturity-bar claim this work delivers against
- [`atx-conformance`](https://github.com/opena2a-standards/atx-conformance) — covers AIP §6.4 (VC `AgentTrustCredential`) transitively; same `issuer-primary` keypair as this suite
- [`atp-conformance`](https://github.com/opena2a-standards/atp-conformance) — covers ATP wire protocol; the closest structural pattern this suite mirrors
- [`opena2a-standards/did-method-opena2a`](https://github.com/opena2a-standards/did-method-opena2a) (Apache-2.0), the formal specification of the `did:opena2a:<type>:<id>` DID method used by this suite's challenge and response fixtures; filed for W3C DID Extensions registry inclusion on [`w3c/did-extensions#717`](https://github.com/w3c/did-extensions/pull/717)

## Contributing

Issues and PRs welcome on this repository. Substantive coordination on
the AIP spec itself happens in
[`opena2a-org/agent-identity-protocol`](https://github.com/opena2a-org/agent-identity-protocol)
and in the A2A coordination map on
[`a2aproject/A2A#1885`](https://github.com/a2aproject/A2A/issues/1885).

## License

Apache 2.0, see [`LICENSE`](./LICENSE).
