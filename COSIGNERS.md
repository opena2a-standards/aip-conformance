# Cosigners

Second-party cosigners attest that they have independently:

1. Cloned this repository at a specific commit SHA
2. Run BOTH reference verifiers against the published fixture set
3. Observed `summary: 4 pass, 0 fail (4 fixtures)` from each verifier
4. Produced a Sigstore keyless cosign signature over [`MANIFEST.sha256`](./MANIFEST.sha256)

The signature attests to the fixture bytes; the entry below attests that
the verifiers were actually run. Both together close the gap noted in the
A2A coordination map's criterion (c) on
[`a2aproject/A2A#1885`](https://github.com/a2aproject/A2A/issues/1885)
for AIP.

This is the same cosignature shape as
[`atx-conformance/COSIGNERS.md`](https://github.com/opena2a-standards/atx-conformance/blob/main/COSIGNERS.md)
and
[`atp-conformance/COSIGNERS.md`](https://github.com/opena2a-standards/atp-conformance/blob/main/COSIGNERS.md).

## How to cosign

```bash
# Clone and verify
git clone https://github.com/opena2a-standards/aip-conformance
cd aip-conformance

# Run both verifiers and record exit summaries
(cd verifiers/go && go run . ../../fixtures)
(cd verifiers/python && pip install -r requirements.txt && python verify.py ../../fixtures)

# Sigstore keyless cosign over MANIFEST.sha256
cosign sign-blob MANIFEST.sha256 \
    --output-signature MANIFEST.sha256.sig \
    --output-certificate MANIFEST.sha256.crt

# Open a PR that:
#   - Adds your cosignature + certificate under .sigstore/<your-org>/
#   - Appends an entry to the v0.2 registry below
```

Both verifiers cover AIP §5.1 challenge-response transcripts end to end
(Ed25519 only — §5.1 does not specify a post-quantum signature path at
v1.0.0-draft). See the README's *Honest scope notes* section for the
canonical signing form, the challenge / response wire-format pinning,
and the stateless-verifier replay model.

## CI self-cosignature (baseline)

Every push to `main` keyless-signs the current `MANIFEST.sha256` in CI
(`sign-manifest` job in
[`conformance.yml`](./.github/workflows/conformance.yml)), after the full
conformance job (both verifiers, byte-pin, parity, profile) has passed. The
signature is recorded in the public Rekor transparency log — that entry is the
durable artifact; the workflow also uploads the bundle
(`MANIFEST.sha256.cosign.bundle`) as a run artifact for convenience.

To verify a bundle against the pinned CI identity:

```bash
cosign verify-blob \
    --bundle MANIFEST.sha256.cosign.bundle \
    --certificate-identity "https://github.com/opena2a-standards/aip-conformance/.github/workflows/conformance.yml@refs/heads/main" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    MANIFEST.sha256
```

Or look the digest up directly in Rekor (https://search.sigstore.dev) by the
SHA-256 of `MANIFEST.sha256`.

## Cosignature registry

### v0.2 — `MANIFEST.sha256` attestation (current)

| Cosigner | Commit SHA | Go verifier | Python verifier | Sigstore artifact | Date |
|---|---|---|---|---|---|
| opena2a-standards (self-cosigned baseline, CI) | every `main` push (see CI self-cosignature) | `4 pass, 0 fail` | `4 pass, 0 fail` | Rekor entry per push (keyless CI signature) | 2026-07-04 onward |

Self-cosignature exists to anchor the baseline; second-party signatures
are what close criterion (c). The (c) claim is not treated as closed for
AIP until at least one independent (non-OpenA2A) cosignature lands
against the v0.2 `MANIFEST.sha256`. Recruiting at least one
second-party cosigner is the immediate post-publish objective.

### v0.1 — cross-link attestation (historical)

At v0.1 this repository shipped no fixtures; cosignatures attested to
the §6.4 cross-link claim only. v0.1 cosignatures do NOT transfer
forward to v0.2 — v0.2 needs its own cosignatures against its own
`MANIFEST.sha256`. The v0.1 registry below is kept for historical
attestation and is closed to new entries.

| Cosigner | Commit SHA | atx-conformance verifier run | Sigstore artifact | Date |
|---|---|---|---|---|
| _(no v0.1 entries landed before v0.2 shipped)_ | | | | |
