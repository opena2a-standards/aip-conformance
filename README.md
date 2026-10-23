# aip-conformance

Conformance fixtures and reference verifiers for the
[Agent Identity Protocol (AIP) v1.0.0-draft](https://github.com/opena2a-org/agent-identity-protocol).

**Status: v0.3 — AIP §5.1 challenge-response transcript fixtures (9) and
§6.1 trust-score composition fixtures (3) shipped, 2 verifiers,
`MANIFEST.sha256` pinned. AIP §6.4 (VC `AgentTrustCredential`) conformance
is covered transitively via
[`atx-conformance`](https://github.com/opena2a-standards/atx-conformance).**

## Running the verifiers

The Go verifier is published as part of this repository's Go module, with
the fixture set built in. With Go 1.22 or later installed, one command
verifies the shipped fixtures and needs no clone:

```bash
go run github.com/opena2a-standards/aip-conformance/verifiers/go@v0.3.0
```

The version is the suite version the status line declares, as a tag. The
first output line repeats it with the module path, then one block per
fixture follows and a summary:

```text
fixtures: 12 embedded in github.com/opena2a-standards/aip-conformance v0.3.0
PASS  fixtures/challenge-response-echoed-agent-differs.json
       expected: REJECT [SIGNATURE_INVALID]
       observed: REJECT[SIGNATURE_INVALID: response.agentDid does not match challenge.agentDid]
...
summary: 12 pass, 0 fail (12 fixtures)
```

Name the version: `@latest` does not reach the root module through the
public module proxy ([why](docs/versioning.md#versioning-and-stability)).
Pass directories or files to verify fixtures on disk instead, for example
`./fixtures` in a checkout. Each verifier also runs from a checkout:

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

Both verifiers walk every `*.json` file in the directory you point them at
(or you may pass individual fixture files); with no argument, the Go
verifier walks the copy of `fixtures/` built into it. Exit code is 0 if
every fixture's observed result matches the expected result and the
rejection category matches (when declared). Outside the two §5.1 bodies
(`challengeResponse.challenge` and `challengeResponse.response`), both read
a fixture's members under their exact names (`VerifierState` is not
`verifierState`), and a fixture that writes one member name twice in the
same JSON object fails to load, as does a `challengeResponse` fixture with
no `verifierState` object, and one whose `verifierState` holds a
`trustedIssuers`, `agentBindings` or `seenNonces` member that is neither an
array nor null, an `agentBindings` entry that is not an object, or a
`seenNonces` or `trustedIssuers` entry that is not a non-empty string; each
counts as a fail (exit code 1).
[`fixtures/load-errors/`](./fixtures/load-errors) holds pinned examples
that a conforming verifier refuses to load
([lines](docs/checks.md#load-error-fixtures)).

## Fixtures

Each §5.1 fixture is a byte-stable JSON file that bundles an IdP-issued
challenge AND the agent's signed response with verifier configuration and
an expected outcome (ACCEPT or REJECT). Two SDK-independent reference
verifiers (Go and Python) walk the fixture set and report PASS or FAIL
per vector. Fixture bytes are pinned in
[`MANIFEST.sha256`](./MANIFEST.sha256).

| Fixture | Expected | Exercises |
|---|---|---|
| `challenge-response-valid` | ACCEPT | bound key, unseen nonce, unexpired challenge: the MUST-implement baseline |
| `challenge-response-wrong-key` | REJECT (UNTRUSTED_KEY) | a valid signature by a key not bound to the agent |
| `challenge-response-stale-challenge` | REJECT (CHALLENGE_EXPIRED) | a challenge that expired 25 minutes before the pinned clock |
| `challenge-response-replay` | REJECT (NONCE_REPLAY) | a nonce already in `verifierState.seenNonces` |
| `challenge-response-echoed-nonce-differs` | REJECT (SIGNATURE_INVALID) | a response that echoes a nonce other than the signed challenge body's |
| `challenge-response-echoed-agent-differs` | REJECT (SIGNATURE_INVALID) | a response under another agent's key that echoes that agent's DID |
| `challenge-response-other-agent-key` | REJECT (UNTRUSTED_KEY) | a valid signature by a key bound to another agent |
| `challenge-response-untrusted-issuer` | REJECT (UNTRUSTED_ISSUER) | a challenge whose `issuerDid` is not in `verifierState.trustedIssuers` |
| `challenge-response-no-trusted-issuers` | REJECT (UNTRUSTED_ISSUER) | a `verifierState` with no `trustedIssuers` member, which trusts no issuer |
| `trust-score-unscored-zero-event-agent` | `UNSCORED` | included weight below the §6.1 threshold of 0.50 |
| `trust-score-measured-six-factors-capped` | `MEASURED` | the neutral-imputed ceiling binds |
| `trust-score-measured-at-included-weight-0.50` | `MEASURED` | included weight at the threshold; the threshold is strict |

The full requirement-to-fixture mapping is machine-readable in
[`conformance.json`](./conformance.json), regenerated from the fixtures by
[`scripts/conformance_profile.py`](./scripts/conformance_profile.py) and
CI-checked against drift. The profile also records what is covered
transitively (§6.4 via `atx-conformance`, §5 authorize responses via
`atp-conformance`) and what is not covered at all (§4 capability grants,
runtime surfaces) so suite-to-suite claims stay explicit.

Inputs, expected values and composition rules per fixture: [docs/checks.md](docs/checks.md).

## Honest scope notes

This is the section that future reviewers, second-implementation authors,
and A2A coordination-map readers should read before forming judgments.

- **Canonical form:** the agent signs 5 pipe-delimited fields, not the full JSON; `publicKey`, `keyId`, `signedAt` and `algorithm` are unsigned. The response's echo of each signed field must equal the challenge body's, and the checks read the challenge body.
- **Wire format:** challenge and response bodies pin fields beyond AIP-SPEC §5.1, as suite contracts, not spec changes.
- **Replay:** the verifier is stateless; the replay fixture declares prior nonces in `verifierState.seenNonces`.
- **Test keys:** `issuer-primary` is the same keypair as in atx-conformance and atp-conformance; all seeds are TEST-ONLY.
- **DID resolution:** not exercised; DIDs are opaque strings per AIP-SPEC §3.2.
- **Maturity bar:** criterion (c) on `a2aproject/A2A#1885` is not treated as closed until an independent Sigstore cosignature lands.

The first four in full: [docs/how-it-works.md](docs/how-it-works.md); DID resolution: [docs/versioning.md](docs/versioning.md); the maturity bar: [docs/USE-CASES.md](docs/USE-CASES.md).

## Continuous verification

[`.github/workflows/conformance.yml`](./.github/workflows/conformance.yml)
enforces every claim in this README on each push and pull request:

1. Both reference verifiers run against `fixtures/` and must report 0 fail.
2. The generator must reproduce the committed fixture bytes and `MANIFEST.sha256` exactly.
3. The Go and Python verifiers must agree per fixture ([`scripts/parity/parity.py`](./scripts/parity/parity.py)).
4. `conformance.json` and the rows about this repository in `docs/ecosystem.md` must match the fixture set: the verifier status rows, and the sibling-repositories row's version (the one this README's status line declares), fixture count per spec section and verifier count.
5. Each challenge and response must validate against the vendored AIP-SPEC schemas ([`scripts/schema_validation.py`](./scripts/schema_validation.py)).

Each gate in full: [docs/how-it-works.md](docs/how-it-works.md#continuous-verification).

## Reproducing the fixtures

The fixtures in this repository are deterministic. To regenerate them
from the keypair vectors in [`vectors/`](./vectors):

```bash
cd scripts/generate-fixtures
go run .
```

Re-running the generator MUST produce byte-identical fixtures. If the
bytes change, either (a) the generator changed, (b) the canonicalization
shifted, or (c) the Go standard library's `crypto/ed25519` implementation
changed (extremely unlikely). Any of those is a breaking change for
downstream verifiers.

## Documentation

- [docs/checks.md](docs/checks.md): every fixture, its inputs and what it exercises.
- [docs/how-it-works.md](docs/how-it-works.md): scope notes in full, each CI gate, the generator steps and the repository layout.
- [docs/USE-CASES.md](docs/USE-CASES.md): why AIP fixtures look different from ATX and ATP, and the scope decision.
- [docs/versioning.md](docs/versioning.md): pinned spec, DID method and library versions, and the fixture stability rules.
- [docs/ecosystem.md](docs/ecosystem.md): implementations that validate against this suite, sibling suites and references.
- [`COSIGNERS.md`](./COSIGNERS.md): second-party cosigners of `MANIFEST.sha256`.

Contributing: Issues and PRs welcome on this repository. Substantive coordination on
the AIP spec itself happens in
[`opena2a-org/agent-identity-protocol`](https://github.com/opena2a-org/agent-identity-protocol)
and in the A2A coordination map on
[`a2aproject/A2A#1885`](https://github.com/a2aproject/A2A/issues/1885).

## License

Apache 2.0, see [`LICENSE`](./LICENSE). All keypairs, seeds, and
identifiers in this repository are TEST-ONLY.
