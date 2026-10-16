# Motivation and scope decision

Why this suite exists, why it pins §5.1 transcripts, and which AIP
surfaces it leaves to the sibling suites.

This suite mirrors the pattern set by
[`atx-conformance`](https://github.com/opena2a-standards/atx-conformance)
(covers the ATX credential schema) and
[`atp-conformance`](https://github.com/opena2a-standards/atp-conformance)
(covers the ATP wire protocol). It closes the AIP-side of criterion (c)
on the OpenA2A maturity bar tracked in
[`a2aproject/A2A#1885`](https://github.com/a2aproject/A2A/issues/1885):
"peer-cosigned conformance fixtures for AIP, ATP, or ATX comparable to
the `aim-did-rfc9421/*` set."

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
[`MANIFEST.sha256`](../MANIFEST.sha256). Self-cosigned baseline only at
v0.2.
