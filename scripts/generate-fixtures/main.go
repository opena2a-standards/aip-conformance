// generate-fixtures produces the AIP v1.0.0-draft §5.1 conformance fixture set.
//
// Every fixture is byte-stable: same seeds, same canonicalization, same JSON
// encoding settings. Re-running the generator MUST produce identical bytes;
// MANIFEST.sha256 pins each fixture.
//
// Spec coverage of v0.2:
//   - challenge-response-valid              AIP §5.1 happy path (ACCEPT)
//   - challenge-response-wrong-key          AIP §5.1 publicKey-vs-bound-key check (REJECT UNTRUSTED_KEY)
//   - challenge-response-stale-challenge    AIP §5.1 5-minute expiry check (REJECT CHALLENGE_EXPIRED)
//   - challenge-response-replay             AIP §5.1 nonce-uniqueness check (REJECT NONCE_REPLAY)
//
// Canonical signing form (AIP §5.1, this suite's pinning):
//
//	canonical = "{challenge}|{agentDid}|{nonce}|{issuedAt}|{expiresAt}"
//	signature = Ed25519.Sign(agentBoundPrivKey, canonical)
//
// Where:
//   - challenge: base64-no-padding of 32 deterministic bytes (SHA-256 of a label)
//   - nonce:     base64-no-padding of 16 deterministic bytes (first 16 bytes of SHA-256 of a label)
//   - agentDid:  did:opena2a:agent:agent_conformance_test_001
//   - timestamps: RFC 3339 UTC
//
// Keypair reuse: issuer-primary is the SAME bytes as
// atx-conformance/vectors/issuer-primary.json and
// atp-conformance/vectors/issuer-primary.json (RFC 8032 §7.1 Test 1).
// agent-bound-key is RFC 8032 §7.1 Test 2; agent-unbound-key is Test 3.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	aipVersion        = "1.0.0-draft"
	fixedClockRFC3339 = "2026-05-28T00:00:00Z"
)

var outDir string

// ---------------------------------------------------------------------------
// fixture wrapper
// ---------------------------------------------------------------------------

type SpecRef struct {
	ID      string `json:"id"`
	Ref     string `json:"ref"`
	Section string `json:"section"`
}

type KeypairRef struct {
	Role         string `json:"role"`
	Path         string `json:"path"`
	Algorithm    string `json:"algorithm"`
	PublicKeyHex string `json:"publicKeyHex"`
	KeyID        string `json:"keyId"`
}

// AgentBinding pins agentDid → publicKey associations for the verifier.
// In production an AIP relying party would resolve agentDid → publicKey via
// a DID resolution call; in conformance fixtures the binding is pinned in
// verifierState so the test is hermetic.
type AgentBinding struct {
	AgentDID     string `json:"agentDid"`
	Algorithm    string `json:"algorithm"`
	PublicKeyHex string `json:"publicKeyHex"`
}

type VerifierState struct {
	ClockRFC3339   string         `json:"clockRfc3339"`
	TrustedIssuers []string       `json:"trustedIssuers"`
	AgentBindings  []AgentBinding `json:"agentBindings"`
	SeenNonces     []string       `json:"seenNonces"`
}

type ExpectedOutcome struct {
	VerifyResult   string `json:"verifyResult"`
	RejectCategory string `json:"rejectCategory,omitempty"`
	ReasonContains string `json:"reasonContains,omitempty"`
}

// Fixture is the language-agnostic wrapper.
type Fixture struct {
	Schema            string             `json:"$schema"`
	Name              string             `json:"name"`
	Description       string             `json:"description"`
	FixtureType       string             `json:"fixtureType"`
	Spec              []SpecRef          `json:"spec"`
	KeypairRefs       []KeypairRef       `json:"keypairRefs"`
	VerifierState     VerifierState      `json:"verifierState"`
	Expected          ExpectedOutcome    `json:"expected"`
	ChallengeResponse *ChallengeResponse `json:"challengeResponse,omitempty"`
}

// ---------------------------------------------------------------------------
// payload shape (AIP §5.1 challenge-response transcript)
// ---------------------------------------------------------------------------

// ChallengeResponse bundles the AIP §5.1 transcript: the challenge the IdP
// issued (step 2) AND the response the agent returned to the relying party
// (step 4). Bundling both halves into one fixture makes the test
// reproducible offline: a verifier walking this fixture has everything it
// needs to reconstruct what the canonical payload was and re-verify the
// signature, without a live IdP or live agent.
type ChallengeResponse struct {
	Challenge ChallengeBody `json:"challenge"`
	Response  ResponseBody  `json:"response"`
}

// ChallengeBody mirrors what an AIP §5.1 IdP returns at step 2.
//
// AIP-SPEC §5.1 step 2 names only {challenge, expiresAt}; this conformance
// suite pins additional fields (agentDid, nonce, issuedAt, issuerDid) so
// the challenge↔response binding and the issuer attribution are
// byte-stable. Documented in the repo README as a v0.2 conformance-suite
// pin, not a spec change.
type ChallengeBody struct {
	Challenge string `json:"challenge"`
	AgentDID  string `json:"agentDid"`
	Nonce     string `json:"nonce"`
	IssuedAt  string `json:"issuedAt"`
	ExpiresAt string `json:"expiresAt"`
	IssuerDID string `json:"issuerDid"`
}

// ResponseBody mirrors what the agent returns at AIP §5.1 step 4.
//
// AIP-SPEC §5.1 step 4 names only {signature, publicKey}; this conformance
// suite pins the back-refs to the challenge fields the signature commits
// to (challenge, agentDid, nonce, issuedAt, expiresAt) plus signedAt and
// keyId so the response is self-describing.
type ResponseBody struct {
	AgentDID     string `json:"agentDid"`
	Challenge    string `json:"challenge"`
	Nonce        string `json:"nonce"`
	IssuedAt     string `json:"issuedAt"`
	ExpiresAt    string `json:"expiresAt"`
	Signature    string `json:"signature"`
	PublicKey    string `json:"publicKey"`
	KeyID        string `json:"keyId"`
	SignedAt     string `json:"signedAt"`
	Algorithm    string `json:"algorithm"`
}

// ---------------------------------------------------------------------------
// canonicalization (AIP §5.1, 5 fields, pipe-delimited)
// ---------------------------------------------------------------------------

// canonicalChallengeResponsePayload is the AIP §5.1 canonical signing form
// pinned by this conformance suite. FIVE fields, pipe-delimited.
// Mirror VERBATIM in both reference verifiers.
//
//	challenge | agentDid | nonce | issuedAt | expiresAt
func canonicalChallengeResponsePayload(cb ChallengeBody) []byte {
	return []byte(fmt.Sprintf("%s|%s|%s|%s|%s",
		cb.Challenge,
		cb.AgentDID,
		cb.Nonce,
		normalizeRFC3339(cb.IssuedAt),
		normalizeRFC3339(cb.ExpiresAt),
	))
}

func normalizeRFC3339(s string) string {
	t, err := time.Parse(time.RFC3339, s)
	must(err)
	return t.UTC().Format(time.RFC3339)
}

// ---------------------------------------------------------------------------
// signing
// ---------------------------------------------------------------------------

func signEd25519(seedHex string, payload []byte) string {
	seed, err := hex.DecodeString(seedHex)
	must(err)
	if len(seed) != ed25519.SeedSize {
		panic(fmt.Sprintf("Ed25519 seed must be %d bytes, got %d", ed25519.SeedSize, len(seed)))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	sig := ed25519.Sign(priv, payload)
	return base64.RawStdEncoding.EncodeToString(sig)
}

// publicKeyB64Raw derives the public key from a seed and returns it
// base64-no-padding-encoded (matches the wire-format convention this
// suite pins for the response.publicKey field).
func publicKeyB64Raw(seedHex string) string {
	seed, err := hex.DecodeString(seedHex)
	must(err)
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	return base64.RawStdEncoding.EncodeToString(pub)
}

// ---------------------------------------------------------------------------
// keypair vector loading
// ---------------------------------------------------------------------------

type KeyVector struct {
	Comment      string `json:"$comment"`
	Role         string `json:"role"`
	Algorithm    string `json:"algorithm"`
	SeedHex      string `json:"seedHex"`
	PublicKeyHex string `json:"publicKeyHex"`
	IssuerDID    string `json:"issuerDid,omitempty"`
	AgentDID     string `json:"agentDid,omitempty"`
	KeyID        string `json:"keyId"`
}

func mustLoadKeyVector(path string) KeyVector {
	abs := filepath.Join(outDir, path)
	b, err := os.ReadFile(abs) //nolint:gosec // G304: build-time tool; outDir + constant path, no untrusted input
	must(err)
	var kv KeyVector
	must(json.Unmarshal(b, &kv))

	// Self-check: rederive the public key from the seed and panic on drift.
	derived := hex.EncodeToString(ed25519.NewKeyFromSeed(mustHex(kv.SeedHex)).Public().(ed25519.PublicKey))
	if derived != kv.PublicKeyHex {
		panic(fmt.Sprintf("keypair drift in %s: vector pubkey=%s..., seed-derived=%s...",
			path, kv.PublicKeyHex[:16], derived[:16]))
	}
	return kv
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	must(err)
	return b
}

func keypairRefFor(kv KeyVector, path string) KeypairRef {
	return KeypairRef{
		Role:         kv.Role,
		Path:         path,
		Algorithm:    kv.Algorithm,
		PublicKeyHex: kv.PublicKeyHex,
		KeyID:        kv.KeyID,
	}
}

// ---------------------------------------------------------------------------
// deterministic bytes for "random" fields
// ---------------------------------------------------------------------------

// detBytes returns deterministic bytes derived from a label, used in place
// of cryptographic randomness for the challenge / nonce fields so the
// fixtures are byte-stable across runs.
func detBytes(label string, n int) []byte {
	h := sha256.Sum256([]byte(label))
	if n > len(h) {
		panic(fmt.Sprintf("detBytes: requested %d bytes, only %d available", n, len(h)))
	}
	return h[:n]
}

func detB64Raw(label string, n int) string {
	return base64.RawStdEncoding.EncodeToString(detBytes(label, n))
}

// ---------------------------------------------------------------------------
// pinned values
// ---------------------------------------------------------------------------

var (
	testAgentDID     = "did:opena2a:agent:agent_conformance_test_001"
	testIssuerDID    = "did:opena2a:authority:opena2a.org"
	specRefURL       = "https://github.com/opena2a-org/agent-identity-protocol/blob/main/AIP-SPEC.md"

	// Fixture 1 (valid) — pinned challenge / nonce / time window
	validChallenge = detB64Raw("aip-conformance-v0.2-challenge-valid", 32)
	validNonce     = detB64Raw("aip-conformance-v0.2-nonce-valid", 16)
	validIssuedAt  = "2026-05-27T23:58:00Z"
	validExpiresAt = "2026-05-28T00:03:00Z" // 3 min past pinned clock — not yet expired
	validSignedAt  = "2026-05-27T23:58:30Z"

	// Fixture 3 (stale-challenge) — issued and expired before pinned clock
	staleChallenge  = detB64Raw("aip-conformance-v0.2-challenge-stale", 32)
	staleNonce      = detB64Raw("aip-conformance-v0.2-nonce-stale", 16)
	staleIssuedAt   = "2026-05-27T23:30:00Z"
	staleExpiresAt  = "2026-05-27T23:35:00Z" // 25 min before pinned clock — expired
	staleSignedAt   = "2026-05-27T23:30:30Z"

	// Fixture 4 (replay) — different challenge from fixture 1, but reuses fixture 1's nonce
	replayChallenge = detB64Raw("aip-conformance-v0.2-challenge-replay", 32)
	replayIssuedAt  = "2026-05-27T23:59:00Z"
	replayExpiresAt = "2026-05-28T00:04:00Z" // not yet expired
	replaySignedAt  = "2026-05-27T23:59:30Z"
)

// ---------------------------------------------------------------------------
// fixture builders
// ---------------------------------------------------------------------------

func specRefs(section string) []SpecRef {
	return []SpecRef{{
		ID:      "AIP-SPEC",
		Ref:     specRefURL,
		Section: section,
	}}
}

// baseVerifierState returns the default verifier-state for fixtures that
// don't add seen-nonces. The agent's bound key per agentDid is pinned here.
func baseVerifierState(boundKey KeyVector) VerifierState {
	return VerifierState{
		ClockRFC3339:   fixedClockRFC3339,
		TrustedIssuers: []string{testIssuerDID},
		AgentBindings: []AgentBinding{
			{
				AgentDID:     testAgentDID,
				Algorithm:    "Ed25519",
				PublicKeyHex: boundKey.PublicKeyHex,
			},
		},
		SeenNonces: []string{},
	}
}

func main() {
	outDir = mustResolveOutDir()

	primary := mustLoadKeyVector("vectors/issuer-primary.json")
	agentBound := mustLoadKeyVector("vectors/agent-bound-key.json")
	agentUnbound := mustLoadKeyVector("vectors/agent-unbound-key.json")

	type fixtureSpec struct {
		writePath string
		build     func() Fixture
	}

	fixtures := []fixtureSpec{
		// ----------------------------------------------------------------
		// Fixture 1: challenge-response-valid (ACCEPT)
		// ----------------------------------------------------------------
		{"fixtures/challenge-response-valid.json", func() Fixture {
			cb := ChallengeBody{
				Challenge: validChallenge,
				AgentDID:  testAgentDID,
				Nonce:     validNonce,
				IssuedAt:  validIssuedAt,
				ExpiresAt: validExpiresAt,
				IssuerDID: testIssuerDID,
			}
			sig := signEd25519(agentBound.SeedHex, canonicalChallengeResponsePayload(cb))
			rb := ResponseBody{
				AgentDID:  testAgentDID,
				Challenge: cb.Challenge,
				Nonce:     cb.Nonce,
				IssuedAt:  cb.IssuedAt,
				ExpiresAt: cb.ExpiresAt,
				Signature: sig,
				PublicKey: publicKeyB64Raw(agentBound.SeedHex),
				KeyID:     agentBound.KeyID,
				SignedAt:  validSignedAt,
				Algorithm: "Ed25519",
			}
			cr := ChallengeResponse{Challenge: cb, Response: rb}
			return Fixture{
				Schema:        "https://aip.opena2a.org/schemas/fixture-v1.json",
				Name:          "aip-v0.2/challenge-response-valid",
				Description:   "A well-formed AIP §5.1 challenge-response transcript. The IdP-issued challenge is bound to the agent's DID, the agent has signed the canonical 5-field payload with its bound key, the publicKey returned in the response matches the agentDid's bound key in verifierState, the nonce is unseen, and the challenge has not expired against the pinned verifier clock. Verifier MUST ACCEPT.",
				FixtureType:   "challengeResponse",
				Spec:          specRefs("§5.1 Challenge-Response Protocol"),
				KeypairRefs: []KeypairRef{
					keypairRefFor(primary, "vectors/issuer-primary.json"),
					keypairRefFor(agentBound, "vectors/agent-bound-key.json"),
				},
				VerifierState:     baseVerifierState(agentBound),
				Expected:          ExpectedOutcome{VerifyResult: "ACCEPT"},
				ChallengeResponse: &cr,
			}
		}},

		// ----------------------------------------------------------------
		// Fixture 2: challenge-response-wrong-key (REJECT UNTRUSTED_KEY)
		// ----------------------------------------------------------------
		{"fixtures/challenge-response-wrong-key.json", func() Fixture {
			cb := ChallengeBody{
				Challenge: validChallenge,
				AgentDID:  testAgentDID,
				Nonce:     validNonce,
				IssuedAt:  validIssuedAt,
				ExpiresAt: validExpiresAt,
				IssuerDID: testIssuerDID,
			}
			// Signature is mathematically VALID — it just wasn't made by the bound key.
			sig := signEd25519(agentUnbound.SeedHex, canonicalChallengeResponsePayload(cb))
			rb := ResponseBody{
				AgentDID:  testAgentDID,
				Challenge: cb.Challenge,
				Nonce:     cb.Nonce,
				IssuedAt:  cb.IssuedAt,
				ExpiresAt: cb.ExpiresAt,
				Signature: sig,
				PublicKey: publicKeyB64Raw(agentUnbound.SeedHex),
				KeyID:     agentUnbound.KeyID,
				SignedAt:  validSignedAt,
				Algorithm: "Ed25519",
			}
			cr := ChallengeResponse{Challenge: cb, Response: rb}
			return Fixture{
				Schema:        "https://aip.opena2a.org/schemas/fixture-v1.json",
				Name:          "aip-v0.2/challenge-response-wrong-key",
				Description:   "An AIP §5.1 challenge-response transcript where the agent signed with a key NOT bound to its DID. The signature is mathematically valid Ed25519, but the publicKey returned in the response does not match the bound key declared for testAgentDID in verifierState.agentBindings. Verifier MUST REJECT with UNTRUSTED_KEY.",
				FixtureType:   "challengeResponse",
				Spec:          specRefs("§5.1 Challenge-Response Protocol — step 5: publicKey matches registered agent"),
				KeypairRefs: []KeypairRef{
					keypairRefFor(primary, "vectors/issuer-primary.json"),
					keypairRefFor(agentBound, "vectors/agent-bound-key.json"),
					keypairRefFor(agentUnbound, "vectors/agent-unbound-key.json"),
				},
				VerifierState: baseVerifierState(agentBound), // bound key is agent-bound-key; response uses agent-unbound-key
				Expected: ExpectedOutcome{
					VerifyResult:   "REJECT",
					RejectCategory: "UNTRUSTED_KEY",
					ReasonContains: "publicKey does not match",
				},
				ChallengeResponse: &cr,
			}
		}},

		// ----------------------------------------------------------------
		// Fixture 3: challenge-response-stale-challenge (REJECT CHALLENGE_EXPIRED)
		// ----------------------------------------------------------------
		{"fixtures/challenge-response-stale-challenge.json", func() Fixture {
			cb := ChallengeBody{
				Challenge: staleChallenge,
				AgentDID:  testAgentDID,
				Nonce:     staleNonce,
				IssuedAt:  staleIssuedAt,
				ExpiresAt: staleExpiresAt,
				IssuerDID: testIssuerDID,
			}
			sig := signEd25519(agentBound.SeedHex, canonicalChallengeResponsePayload(cb))
			rb := ResponseBody{
				AgentDID:  testAgentDID,
				Challenge: cb.Challenge,
				Nonce:     cb.Nonce,
				IssuedAt:  cb.IssuedAt,
				ExpiresAt: cb.ExpiresAt,
				Signature: sig,
				PublicKey: publicKeyB64Raw(agentBound.SeedHex),
				KeyID:     agentBound.KeyID,
				SignedAt:  staleSignedAt,
				Algorithm: "Ed25519",
			}
			cr := ChallengeResponse{Challenge: cb, Response: rb}
			return Fixture{
				Schema:        "https://aip.opena2a.org/schemas/fixture-v1.json",
				Name:          "aip-v0.2/challenge-response-stale-challenge",
				Description:   "An AIP §5.1 challenge-response transcript where the challenge expired before the verifier's pinned clock. expiresAt is 25 minutes earlier than verifierState.clockRfc3339. The signature is otherwise mathematically valid and made by the agent's bound key. Verifier MUST REJECT with CHALLENGE_EXPIRED.",
				FixtureType:   "challengeResponse",
				Spec:          specRefs("§5.1 Challenge-Response Protocol — step 5: challenge not expired (5-minute window)"),
				KeypairRefs: []KeypairRef{
					keypairRefFor(primary, "vectors/issuer-primary.json"),
					keypairRefFor(agentBound, "vectors/agent-bound-key.json"),
				},
				VerifierState: baseVerifierState(agentBound),
				Expected: ExpectedOutcome{
					VerifyResult:   "REJECT",
					RejectCategory: "CHALLENGE_EXPIRED",
					ReasonContains: "expiresAt",
				},
				ChallengeResponse: &cr,
			}
		}},

		// ----------------------------------------------------------------
		// Fixture 4: challenge-response-replay (REJECT NONCE_REPLAY)
		// ----------------------------------------------------------------
		{"fixtures/challenge-response-replay.json", func() Fixture {
			// Different challenge from fixture 1, but the SAME nonce — and
			// verifierState lists that nonce as already-seen.
			cb := ChallengeBody{
				Challenge: replayChallenge,
				AgentDID:  testAgentDID,
				Nonce:     validNonce, // same as fixture 1
				IssuedAt:  replayIssuedAt,
				ExpiresAt: replayExpiresAt,
				IssuerDID: testIssuerDID,
			}
			sig := signEd25519(agentBound.SeedHex, canonicalChallengeResponsePayload(cb))
			rb := ResponseBody{
				AgentDID:  testAgentDID,
				Challenge: cb.Challenge,
				Nonce:     cb.Nonce,
				IssuedAt:  cb.IssuedAt,
				ExpiresAt: cb.ExpiresAt,
				Signature: sig,
				PublicKey: publicKeyB64Raw(agentBound.SeedHex),
				KeyID:     agentBound.KeyID,
				SignedAt:  replaySignedAt,
				Algorithm: "Ed25519",
			}
			cr := ChallengeResponse{Challenge: cb, Response: rb}

			// Verifier state pre-loaded with the nonce as "seen" — modelling
			// "a previous verification already recorded this nonce."
			vs := baseVerifierState(agentBound)
			vs.SeenNonces = []string{validNonce}

			return Fixture{
				Schema:        "https://aip.opena2a.org/schemas/fixture-v1.json",
				Name:          "aip-v0.2/challenge-response-replay",
				Description:   "An AIP §5.1 challenge-response transcript that reuses a nonce the verifier has already seen. The signature is mathematically valid, the publicKey matches the agentDid's bound key, the challenge is not expired — but the nonce appears in verifierState.seenNonces, modelling 'a prior verification already consumed this nonce.' Verifier MUST REJECT with NONCE_REPLAY.",
				FixtureType:   "challengeResponse",
				Spec:          specRefs("§5.1 Challenge-Response Protocol — step 5: nonce not reused"),
				KeypairRefs: []KeypairRef{
					keypairRefFor(primary, "vectors/issuer-primary.json"),
					keypairRefFor(agentBound, "vectors/agent-bound-key.json"),
				},
				VerifierState: vs,
				Expected: ExpectedOutcome{
					VerifyResult:   "REJECT",
					RejectCategory: "NONCE_REPLAY",
					ReasonContains: "nonce",
				},
				ChallengeResponse: &cr,
			}
		}},
	}

	manifest := make(map[string]string)
	for _, fs := range fixtures {
		f := fs.build()
		writeFixture(fs.writePath, f, manifest)
	}
	writeManifest("MANIFEST.sha256", manifest)
}

// ---------------------------------------------------------------------------
// io helpers
// ---------------------------------------------------------------------------

func writeFixture(relPath string, f Fixture, manifest map[string]string) {
	abs := filepath.Join(outDir, relPath)
	must(os.MkdirAll(filepath.Dir(abs), 0o755))

	b, err := json.MarshalIndent(f, "", "  ")
	must(err)
	b = append(b, '\n') // POSIX trailing newline
	must(os.WriteFile(abs, b, 0o644))

	sum := sha256.Sum256(b)
	manifest[relPath] = hex.EncodeToString(sum[:])
	fmt.Printf("wrote %s (%d bytes, sha256=%s)\n", relPath, len(b), hex.EncodeToString(sum[:]))
}

func writeManifest(relPath string, manifest map[string]string) {
	abs := filepath.Join(outDir, relPath)

	keys := make([]string, 0, len(manifest))
	for k := range manifest {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	b.WriteString("# AIP v1.0.0-draft §5.1 conformance fixtures — SHA-256 (per file, path-sorted)\n")
	b.WriteString("# Re-running scripts/generate-fixtures MUST reproduce these exact hashes.\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "%s  %s\n", manifest[k], k)
	}
	must(os.WriteFile(abs, []byte(b.String()), 0o644))
	fmt.Printf("wrote %s (%d entries)\n", relPath, len(keys))
}

func mustResolveOutDir() string {
	// generate-fixtures is invoked from scripts/generate-fixtures/. The repo
	// root is two levels up.
	wd, err := os.Getwd()
	must(err)
	repo := filepath.Clean(filepath.Join(wd, "..", ".."))
	// Sanity-check: the repo root must contain README.md and vectors/.
	if _, err := os.Stat(filepath.Join(repo, "README.md")); err != nil {
		panic(fmt.Sprintf("expected repo root at %s, no README.md found", repo))
	}
	if _, err := os.Stat(filepath.Join(repo, "vectors")); err != nil {
		panic(fmt.Sprintf("expected repo root at %s, no vectors/ found", repo))
	}
	return repo
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
