# Fixture catalogue

Every fixture in [`fixtures/`](../fixtures), with its inputs and what it
exercises. The [README](../README.md) lists them in short.

## §5.1 challenge-response fixtures

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
