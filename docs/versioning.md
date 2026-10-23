# Versions and stability

The spec, DID method and library versions this suite pins, and the rules
for changing the fixture set.

## Version pinning

| Component | Version | Source |
|---|---|---|
| AIP spec | v1.0.0-draft | [`opena2a-org/agent-identity-protocol/AIP-SPEC.md`](https://github.com/opena2a-org/agent-identity-protocol/blob/main/AIP-SPEC.md) |
| `did:opena2a` method | v0.1 (W3C registration filed, PR `w3c/did-extensions#717`) | [`opena2a-standards/did-method-opena2a`](https://github.com/opena2a-standards/did-method-opena2a/blob/main/did-method-opena2a.md) |
| Ed25519 test vector source | RFC 8032 §7.1 Tests 1, 2, 3 and TEST 1024 | [datatracker.ietf.org/doc/html/rfc8032](https://datatracker.ietf.org/doc/html/rfc8032) |
| Go Ed25519 | `crypto/ed25519` (Go 1.22+ standard library) | [pkg.go.dev/crypto/ed25519](https://pkg.go.dev/crypto/ed25519) |
| Python Ed25519 | `cryptography >= 42.0.0` | [pyca/cryptography](https://github.com/pyca/cryptography) |
| Conformance fixture format | v1 (this repo) | [`fixtures/challenge-response-valid.json#$schema`](../fixtures/challenge-response-valid.json) |

The `agentDid`, `issuerDid`, and `keyId` strings in the vectors and fixtures
are ecosystem-scoped `did:opena2a` identifiers, carried as opaque strings per
AIP-SPEC §3.2. The suite pins the challenge-response transcript and the key
binding; DID resolution is not exercised, for `did:opena2a` or for the
provider-scoped `did:web` identifiers an identity provider issues. The
`did:opena2a` registration is merged (`w3c/did-extensions#717`, 2026-07-04);
the pinned method version stays v0.1 until a fixture depends on a later
revision.

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
- The Go module is tagged at each suite version the README's status line
  declares (`**Status: vX.Y` is tag `vX.Y.Z`), and the README's first
  command names that tag; a module version is an immutable fixture set.
  Name a version rather than `@latest`: the public module proxy answers
  `@latest` and `@main` on the `verifiers/go` path with the module that
  lived there before the entry point was published, whose go.mod declares
  another path, and the go command stops on that module before it tries
  the root module (measured 2026-10-18 through proxy.golang.org; the same
  command with a version named ran every fixture and exited 0).
