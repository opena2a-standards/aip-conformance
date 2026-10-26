# Fixture catalogue

Every fixture in [`fixtures/`](../fixtures), with its inputs and what it
exercises. The [README](../README.md) lists them in short.

## §5.1 challenge-response fixtures

Both verifiers apply the AIP §5.1 checks in this order; the first that
fails decides the reject category:

1. Each of the five fields the response echoes (`challenge`, `agentDid`,
   `nonce`, `issuedAt`, `expiresAt`) equals the challenge body's, compared
   as written, and the Ed25519 signature verifies over the challenge body's
   canonical form under `response.publicKey` (`SIGNATURE_INVALID`).
2. `response.publicKey` is the key bound to `challenge.agentDid` in
   `verifierState.agentBindings` (`UNTRUSTED_KEY`).
3. The verifier clock is before `challenge.expiresAt` (`CHALLENGE_EXPIRED`).
4. `challenge.nonce` is not in `verifierState.seenNonces` (`NONCE_REPLAY`).
5. `challenge.issuerDid` is in `verifierState.trustedIssuers`
   (`UNTRUSTED_ISSUER`). A `trustedIssuers` that is missing, null or empty
   holds no issuer, so this check refuses every `issuerDid`.

When an echoed field differs, the reason shows both values, and the
`UNTRUSTED_KEY` and `UNTRUSTED_ISSUER` reasons and the ACCEPT note show the
DID they name; each value is written in double quotes, escaped as Go's
`strconv.QuoteToASCII` escapes it, so both verifiers print the same bytes.

All fixtures use:

- Trusted issuer DID: `did:opena2a:authority:opena2a.org` (the IdP that issued the challenge)
- Test agent DID: `did:opena2a:agent:agent_conformance_test_001`
- Pinned verifier clock: `2026-05-28T00:00:00Z`
- Agent-bound Ed25519 keypair source: [RFC 8032 §7.1 Test 2](https://datatracker.ietf.org/doc/html/rfc8032#section-7.1)
- Agent-unbound Ed25519 keypair source (wrong-key fixture): [RFC 8032 §7.1 Test 3](https://datatracker.ietf.org/doc/html/rfc8032#section-7.1)
- Second agent (echoed-agent-differs and other-agent-key fixtures): `did:opena2a:agent:agent_conformance_test_002`, bound keypair source [RFC 8032 §7.1 TEST 1024](https://datatracker.ietf.org/doc/html/rfc8032#section-7.1)

| Fixture | Expected | Exercises |
|---|---|---|
| `fixtures/challenge-response-valid.json` | ACCEPT | Agent signs the canonical 5-field payload with its bound key; the response `publicKey` matches the agentDid's bound key in `verifierState.agentBindings`; the nonce is unseen; the challenge has not expired against the pinned verifier clock. The MUST-implement baseline. |
| `fixtures/challenge-response-wrong-key.json` | REJECT (UNTRUSTED_KEY) | Agent signs with the unbound key (`agent-unbound-key`). Signature is mathematically valid Ed25519, but the `publicKey` returned in the response does not match the bound key declared for `testAgentDid` in `verifierState.agentBindings`. |
| `fixtures/challenge-response-stale-challenge.json` | REJECT (CHALLENGE_EXPIRED) | `challenge.expiresAt` is 25 minutes earlier than `verifierState.clockRfc3339`. The signature is otherwise mathematically valid and made by the agent's bound key. |
| `fixtures/challenge-response-replay.json` | REJECT (NONCE_REPLAY) | Different challenge bytes from the valid fixture, but reuses its nonce. The signature is mathematically valid, the `publicKey` matches the bound key, the challenge is not expired — but the nonce appears in `verifierState.seenNonces`, modelling "a prior verification already consumed this nonce." |
| `fixtures/challenge-response-echoed-nonce-differs.json` | REJECT (SIGNATURE_INVALID) | The replay transcript with one edit: the response echoes a nonce the verifier has not seen, while the signed challenge body carries the nonce listed in `verifierState.seenNonces`. Check 1 refuses the echo, naming `response.nonce`. |
| `fixtures/challenge-response-echoed-agent-differs.json` | REJECT (SIGNATURE_INVALID) | A challenge minted for `agent_conformance_test_001`, answered under the key bound to `agent_conformance_test_002` with that agent's DID echoed; `verifierState` binds both agents' keys. The signature verifies over the challenge body; check 1 refuses the echo, naming `response.agentDid`. |
| `fixtures/challenge-response-other-agent-key.json` | REJECT (UNTRUSTED_KEY) | The same challenge and key, with every challenge field echoed as written. The presented key is bound, but to another agent than `challenge.agentDid`. |
| `fixtures/challenge-response-untrusted-issuer.json` | REJECT (UNTRUSTED_ISSUER) | The valid transcript under a `verifierState` whose `trustedIssuers` does not hold the challenge's `issuerDid`. Checks 1-4 pass; check 5 refuses. |
| `fixtures/challenge-response-no-trusted-issuers.json` | REJECT (UNTRUSTED_ISSUER) | The valid transcript under a `verifierState` that writes no `trustedIssuers` member. An absent `trustedIssuers`, like a null or empty one, is the empty trusted-issuer set: the verifier trusts no issuer. Checks 1-4 pass; check 5 refuses. |

## Load-error fixtures

The files in [`fixtures/load-errors/`](../fixtures/load-errors) are the
valid fixture with one edit that the fixture format refuses, pinned in
`MANIFEST.sha256`. They are not part of `fixtures/*.json`: no verifier walk
of `fixtures/` reads them, and neither does the Go verifier's embedded set.
A conforming verifier refuses to load each one; their `expected` member is
the valid fixture's ACCEPT and is never reached. Both reference verifiers
print the same line for each, and a run over the directory exits 1:

| Fixture | Line both verifiers print |
|---|---|
| `challenge-response-repeated-challenge.json` | `parse error: challengeResponse.challenge: duplicate member name` |
| `challenge-response-repeated-response.json` | `parse error: challengeResponse.response: duplicate member name` |
| `verifier-state-agent-bindings-not-an-array.json` | `fixture error: verifierState.agentBindings: an object, not an array` |
| `verifier-state-seen-nonces-not-an-array.json` | `fixture error: verifierState.seenNonces: a number, not an array` |
| `verifier-state-trusted-issuers-not-an-array.json` | `fixture error: verifierState.trustedIssuers: a string, not an array` |

The two rules they pin: a JSON object outside the two §5.1 bodies
(`challengeResponse.challenge` and `challengeResponse.response`) that
writes one member name twice fails to load, `challengeResponse` included;
and a `trustedIssuers`, `agentBindings` or `seenNonces` member of
`verifierState` that is present must be an array or null (null and a
missing member read as the empty array).

Both reference verifiers also refuse to load a `challengeResponse` fixture
with no `verifierState` object, a fixture of another type whose
`verifierState` is neither an object nor null, and a fixture of any type
whose `verifierState` holds an `agentBindings` entry that is not an object,
or a `seenNonces` or `trustedIssuers` entry that is not a non-empty string,
null included; no file here pins those rules. The line names
`verifierState`, or the first such entry, with the members checked in the
order `agentBindings`, `seenNonces`, `trustedIssuers`. For the valid fixture
with one edit, both print:

| Edit | Line both verifiers print |
|---|---|
| no `verifierState` member | `fixture error: verifierState: missing` |
| `verifierState` set to `null` | `fixture error: verifierState: null, not an object` |
| `agentBindings` set to `[null, <the bound entry>]` | `fixture error: verifierState.agentBindings[0]: null, not an object` |
| `seenNonces` set to `[null, ""]` | `fixture error: verifierState.seenNonces[0]: null, not a string` |
| `trustedIssuers` set to `["did:opena2a:authority:opena2a.org", 5]` | `fixture error: verifierState.trustedIssuers[1]: a number, not a string` |
| `trustedIssuers` set to `["", "did:opena2a:authority:opena2a.org"]` | `fixture error: verifierState.trustedIssuers[0]: an empty string` |

The `trust-score-measured-at-included-weight-0.50` fixture writes no
`verifierState`. With a `verifierState` member of `0` added, both print
`fixture error: verifierState: a number, not an object`; with one of `null`
added, both print the fixture's `MEASURED` result.

## §6.1 trust-score composition fixtures

A `trustScoreComposition` fixture carries the nine §6.1 factors in table
order, each with its weight in points of 100, its per-factor score (null
when there is no data) and its data-availability confidence, plus the
state a verifier must reach: `expected.verifyResult` is `MEASURED` or
`UNSCORED`, and `expected.composition` pins `scoreStatus`, `score`
(`null` when unscored), `includedWeight` and `unscoredReason`. Both
verifiers compose the inputs under §6.1: exclusion of no-data factors,
proportional redistribution, the neutral-imputed ceiling, and the
unscored state when the included weight is below 0.50 (the section is the
one home of that threshold). Scores compare at four decimals.

| Fixture | includedWeight | Expected |
|---|---|---|
| `trust-score-unscored-zero-event-agent` | 0.30 | `UNSCORED`, score `null`, `insufficient_data` (the composition rule alone would publish 0.575) |
| `trust-score-measured-six-factors-capped` | 0.85 | `MEASURED`, score 0.81 (the ceiling binds: renormalised 0.8647) |
| `trust-score-measured-at-included-weight-0.50` | 0.50 | `MEASURED`, score 0.66 (the threshold is strict) |

The unscored cell was proven red first: against §6.1 as it read before the
unscored amendment both verifiers composed 0.575 for the zero-event agent
and the cell failed; with the amended rule it passes and the two measured
controls are unchanged.
