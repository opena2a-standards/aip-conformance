# How the suite works

The signing form and wire format this suite pins, how CI enforces the
README's claims, how the fixtures are generated, and where each part lives.

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
[`vectors/issuer-primary.json`](../vectors/issuer-primary.json) is the
SAME bytes as
[`atx-conformance/vectors/issuer-primary.json`](https://github.com/opena2a-standards/atx-conformance/blob/main/vectors/issuer-primary.json)
and [`atp-conformance/vectors/issuer-primary.json`](https://github.com/opena2a-standards/atp-conformance/blob/main/vectors/issuer-primary.json):
RFC 8032 §7.1 Test 1 seed, `did:opena2a:authority:opena2a.org` issuer
DID. A peer cosigner who has already audited atx-conformance or
atp-conformance vectors can rely on the same audit for this suite. The
agent-bound and agent-unbound keypairs are RFC 8032 §7.1 Test 2 and Test
3 respectively. All three vector files are TEST-ONLY; the seeds are
publicly known and MUST NOT be used in production.

## Continuous verification

[`.github/workflows/conformance.yml`](../.github/workflows/conformance.yml)
runs the gates below on pull requests and on pushes to `main`; the
[README](../README.md#continuous-verification) summarizes them:

1. Both reference verifiers run against `fixtures/` and must report
   `0 fail`.
2. The fixture generator re-runs and the committed fixture bytes plus
   `MANIFEST.sha256` must reproduce exactly (byte-pin).
3. The cross-implementation parity gate
   ([`scripts/parity/parity.py`](../scripts/parity/parity.py)) asserts the Go
   and Python verifiers agree per fixture on gate status, verdict, and
   reject category, and publishes `parity-report.json` as a CI artifact.
4. `conformance.json` and the rows about this repository in
   `docs/ecosystem.md` must match the fixture set
   ([`scripts/conformance_profile.py --check`](../scripts/conformance_profile.py)):
   the verifier status rows, and the sibling-repositories row's version (the
   one the README status line declares), fixture count per spec section and
   verifier count.
5. Schema validation
   ([`scripts/schema_validation.py`](../scripts/schema_validation.py)): every
   fixture's `challengeResponse.challenge` / `.response` must validate against
   the AIP-SPEC machine-readable schemas, vendored under
   `schemas/vendor/agent-identity-protocol/` and byte-drift-gated against a
   pinned agent-identity-protocol ref.

## Expected output

Both verifiers report `summary: N pass, 0 fail (N fixtures)` against the
shipped fixture set, N being the number of `*.json` files in `fixtures/`
(sample run: [README](../README.md#running-the-verifiers)). Any divergence
on bytes (the fixture file was modified) or on verifier semantics (the
verifier has drifted from the canonical signing form) shows up as one or
more FAIL lines.

## Reproducing the fixtures

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

## Repository layout

```
LICENSE                          Apache 2.0
README.md                        the README: overview and verifier commands
MANIFEST.sha256                  per-fixture SHA-256 (path-sorted)
COSIGNERS.md                     second-party cosigner registry
conformance.json                 requirement-to-fixture profile (generated)
go.mod                           Go module root; `go run .../verifiers/go@latest` resolves here
fixtures.go                      embeds fixtures/*.json into the Go verifier's no-argument run
docs/                            reference pages, this one included
fixtures/                        conformance fixtures (byte-stable JSON)
vectors/                         test keypair vectors (TEST-ONLY)
schemas/                         vendored AIP-SPEC JSON schemas (drift-gated)
verifiers/go/                    Go reference verifier (Ed25519 stdlib), the published entry point
verifiers/python/                Python reference verifier (Ed25519 cryptography)
scripts/generate-fixtures/       deterministic fixture generator (Go)
scripts/parity/                  Go/Python verifier parity gate
scripts/conformance_profile.py   writes conformance.json; --check gates drift
scripts/schema_validation.py     validates fixture transcripts against schemas/
scripts/docs_check.py            checks docs fixture counts and this layout
tests/                           tests for scripts/conformance_profile.py (unittest)
```
