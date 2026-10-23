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
// Added in v0.3:
//   - challenge-response-echoed-nonce-differs  AIP §5.1 echoed fields equal the challenge body's (REJECT SIGNATURE_INVALID)
//   - challenge-response-echoed-agent-differs  AIP §5.1 echoed fields equal the challenge body's (REJECT SIGNATURE_INVALID)
//   - challenge-response-other-agent-key       AIP §5.1 key bound to the challenge's agentDid (REJECT UNTRUSTED_KEY)
//   - challenge-response-untrusted-issuer      AIP §5.1 trusted-issuer check (REJECT UNTRUSTED_ISSUER)
//   - load-errors/*                            fixtures both reference verifiers refuse to load
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
// agent-bound-key is RFC 8032 §7.1 Test 2; agent-unbound-key is Test 3;
// agent-second-key, the bound key of a second agent, is TEST 1024.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
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
	// Composition is set on trustScoreComposition fixtures only: the AIP §6.1
	// state the verifier must reach from the fixture's factor inputs.
	Composition *ExpectedComposition `json:"composition,omitempty"`
}

// ExpectedComposition is the §6.1 outcome. Score is a pointer with no omitempty
// so an unscored fixture serialises "score": null, the exact wire value the
// amended section requires (not 0, not a default).
type ExpectedComposition struct {
	ScoreStatus    string   `json:"scoreStatus"`
	Score          *float64 `json:"score"`
	IncludedWeight float64  `json:"includedWeight"`
	UnscoredReason string   `json:"unscoredReason,omitempty"`
}

// Fixture is the language-agnostic wrapper. The §5.1 transcript fields are
// optional so a §6.1 composition fixture carries none of them; the pointer
// forms marshal byte-identically to the value forms for the §5.1 fixtures
// (the byte-pin gate proves it).
type Fixture struct {
	Schema                string                 `json:"$schema"`
	Name                  string                 `json:"name"`
	Description           string                 `json:"description"`
	FixtureType           string                 `json:"fixtureType"`
	Spec                  []SpecRef              `json:"spec"`
	KeypairRefs           []KeypairRef           `json:"keypairRefs,omitempty"`
	VerifierState         *VerifierState         `json:"verifierState,omitempty"`
	Expected              ExpectedOutcome        `json:"expected"`
	ChallengeResponse     *ChallengeResponse     `json:"challengeResponse,omitempty"`
	TrustScoreComposition *TrustScoreComposition `json:"trustScoreComposition,omitempty"`
}

// ---------------------------------------------------------------------------
// payload shape (AIP §6.1 trust-score composition)
// ---------------------------------------------------------------------------

// FactorInput is one row of the AIP §6.1 factor table as an implementation
// holds it before composition: the factor identifier, its weight in points
// of 100, the per-factor score in 0.0-1.0 (absent when there is no data) and
// the data-availability confidence (0.0 = no data).
type FactorInput struct {
	Factor     string   `json:"factor"`
	Weight     int      `json:"weight"`
	Score      *float64 `json:"score"`
	Confidence float64  `json:"confidence"`
}

// TrustScoreComposition is the input side of a §6.1 fixture: the nine
// factors in table order. A verifier composes them under §6.1 and compares
// the state it reaches with Expected.Composition.
type TrustScoreComposition struct {
	Factors []FactorInput `json:"factors"`
}

func f64(v float64) *float64 { return &v }

func vsPtr(v VerifierState) *VerifierState { return &v }

// nineFactors returns the §6.1 table in order with the given per-factor
// inputs; a nil score with confidence 0 is "no data".
func nineFactors(in map[string]FactorInput) []FactorInput {
	order := []struct {
		id string
		w  int
	}{
		{"verification", 25}, {"uptime", 15}, {"successRate", 15}, {"securityAlerts", 15},
		{"compliance", 10}, {"executionIsolation", 10}, {"age", 5}, {"driftDetection", 3}, {"userFeedback", 2},
	}
	out := make([]FactorInput, 0, len(order))
	for _, o := range order {
		fi, ok := in[o.id]
		if !ok {
			fi = FactorInput{Score: nil, Confidence: 0}
		}
		fi.Factor = o.id
		fi.Weight = o.w
		out = append(out, fi)
	}
	return out
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
	AgentDID  string `json:"agentDid"`
	Challenge string `json:"challenge"`
	Nonce     string `json:"nonce"`
	IssuedAt  string `json:"issuedAt"`
	ExpiresAt string `json:"expiresAt"`
	Signature string `json:"signature"`
	PublicKey string `json:"publicKey"`
	KeyID     string `json:"keyId"`
	SignedAt  string `json:"signedAt"`
	Algorithm string `json:"algorithm"`
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

// normalizeRFC3339 is s as both reference verifiers read it, in UTC and
// written YYYY-MM-DDThh:mm:ssZ without its fraction of a second. It panics
// on a value parseRFC3339 does not read, which the verifiers put in the
// signed payload as written instead of reading it as a time. time.RFC3339
// writes year -1, which an offset can make of year 0, as -0001, and year
// 10000 as 10000.
func normalizeRFC3339(s string) string {
	t, err := parseRFC3339(s)
	if err != nil {
		panic(fmt.Sprintf("challenge issuedAt and expiresAt must be date-times the reference verifiers read: %v", err))
	}
	return t.UTC().Format(time.RFC3339)
}

// rfc3339DateTime matches the RFC 3339 date-time form both reference
// verifiers read; verifiers/go/verify.go rfc3339DateTime and
// verifiers/python/verify.py _RFC3339_DATE_TIME hold the same pattern. A
// four-digit year and two-digit month, day, hour, minute and second, an
// optional fraction of a second after a period, and Z or a UTC offset of
// the form +hh:mm or -hh:mm, with T and Z in upper case. time.Parse with
// the time.RFC3339 layout also reads forms outside RFC 3339, such as a
// one-digit hour, a comma before the fraction and an offset of +24:00
// (go.dev/issue/54580).
var rfc3339DateTime = regexp.MustCompile(`^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})` +
	`(?:\.([0-9]+))?(?:Z|([+-])([0-9]{2}):([0-9]{2}))$`)

// noUTCOffset matches a date alone, or a date and time with no UTC offset
// (verifiers/go/verify.go noUTCOffset).
var noUTCOffset = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}(?:T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?)?$`)

// parseRFC3339 is verifiers/go/verify.go parseRFC3339, with the same
// messages. It reads s as a time, or returns an error when s is not an RFC
// 3339 date-time in the form rfc3339DateTime matches. The month, day (by
// the month and year), hour, minute, second and offset must be in range,
// which leaves out a second of 60, an hour of 24 and an offset hour of 24.
// The fraction is cut to nanoseconds.
func parseRFC3339(s string) (time.Time, error) {
	m := rfc3339DateTime.FindStringSubmatch(s)
	if m == nil {
		if noUTCOffset.MatchString(s) {
			return time.Time{}, fmt.Errorf("%q has no UTC offset", s)
		}
		return time.Time{}, fmt.Errorf("%q is not of the form YYYY-MM-DDThh:mm:ss[.fraction] followed by Z, +hh:mm or -hh:mm", s)
	}
	// Each group read here is digits, or empty (0) for the offset of Z.
	num := func(group string) int {
		v, _ := strconv.Atoi(group)
		return v
	}
	year, month, day := num(m[1]), num(m[2]), num(m[3])
	hour, minute, second := num(m[4]), num(m[5]), num(m[6])
	offsetHour, offsetMinute := num(m[9]), num(m[10])
	// Day 0 of the next month is the last day of this one. For a month out
	// of range the month check below fails first.
	daysInMonth := time.Date(year, time.Month(month)+1, 0, 0, 0, 0, 0, time.UTC).Day()
	for _, f := range []struct {
		name             string
		value, low, high int
	}{
		{"month", month, 1, 12},
		{"day", day, 1, daysInMonth},
		{"hour", hour, 0, 23},
		{"minute", minute, 0, 59},
		{"second", second, 0, 59},
		{"UTC offset hour", offsetHour, 0, 23},
		{"UTC offset minute", offsetMinute, 0, 59},
	} {
		if f.value < f.low || f.value > f.high {
			return time.Time{}, fmt.Errorf("the %s of %q is out of range", f.name, s)
		}
	}
	nsec := num((m[7] + "000000000")[:9])
	offset := time.Duration(offsetHour*60+offsetMinute) * time.Minute
	if m[8] == "-" {
		offset = -offset
	}
	return time.Date(year, time.Month(month), day, hour, minute, second, nsec, time.UTC).Add(-offset), nil
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
	testAgentDID  = "did:opena2a:agent:agent_conformance_test_001"
	testIssuerDID = "did:opena2a:authority:opena2a.org"
	specRefURL    = "https://github.com/opena2a-org/agent-identity-protocol/blob/main/AIP-SPEC.md"

	// Fixture 1 (valid) — pinned challenge / nonce / time window
	validChallenge = detB64Raw("aip-conformance-v0.2-challenge-valid", 32)
	validNonce     = detB64Raw("aip-conformance-v0.2-nonce-valid", 16)
	validIssuedAt  = "2026-05-27T23:58:00Z"
	validExpiresAt = "2026-05-28T00:03:00Z" // 3 min past pinned clock — not yet expired
	validSignedAt  = "2026-05-27T23:58:30Z"

	// Fixture 3 (stale-challenge) — issued and expired before pinned clock
	staleChallenge = detB64Raw("aip-conformance-v0.2-challenge-stale", 32)
	staleNonce     = detB64Raw("aip-conformance-v0.2-nonce-stale", 16)
	staleIssuedAt  = "2026-05-27T23:30:00Z"
	staleExpiresAt = "2026-05-27T23:35:00Z" // 25 min before pinned clock — expired
	staleSignedAt  = "2026-05-27T23:30:30Z"

	// Fixture 4 (replay) — different challenge from fixture 1, but reuses fixture 1's nonce
	replayChallenge = detB64Raw("aip-conformance-v0.2-challenge-replay", 32)
	replayIssuedAt  = "2026-05-27T23:59:00Z"
	replayExpiresAt = "2026-05-28T00:04:00Z" // not yet expired
	replaySignedAt  = "2026-05-27T23:59:30Z"

	// Fixture 8 (echoed-nonce-differs) — the replay transcript's response
	// echoes this nonce, which the verifier has not seen, in place of the
	// challenge body's
	echoedNonce = detB64Raw("aip-conformance-v0.3-nonce-echoed", 16)

	// Fixture 11 (untrusted-issuer) — the one issuer the verifier trusts,
	// which is not the challenge's issuerDid
	otherIssuerDID = "did:opena2a:authority:example.org"
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

// answer is the response returned for cb: the five challenge fields echoed,
// with agentDID as the echoed agentDid, signed over cb's canonical payload
// with signer's seed and carrying signer's public key and keyId.
func answer(cb ChallengeBody, agentDID string, signer KeyVector, signedAt string) ResponseBody {
	return ResponseBody{
		AgentDID:  agentDID,
		Challenge: cb.Challenge,
		Nonce:     cb.Nonce,
		IssuedAt:  cb.IssuedAt,
		ExpiresAt: cb.ExpiresAt,
		Signature: signEd25519(signer.SeedHex, canonicalChallengeResponsePayload(cb)),
		PublicKey: publicKeyB64Raw(signer.SeedHex),
		KeyID:     signer.KeyID,
		SignedAt:  signedAt,
		Algorithm: "Ed25519",
	}
}

// bindingFor is the verifierState.agentBindings entry that binds kv's public
// key to agentDID.
func bindingFor(agentDID string, kv KeyVector) AgentBinding {
	return AgentBinding{AgentDID: agentDID, Algorithm: "Ed25519", PublicKeyHex: kv.PublicKeyHex}
}

// object is a JSON object written member by member, in order, a name
// written twice included, with each value as json.Marshal writes it. The
// load-error fixtures need it: a struct cannot write a member twice, or hold
// a value of the wrong JSON type for its field.
type object []member

type member struct {
	name  string
	value any
}

func (o object) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, m := range o {
		if i > 0 {
			b.WriteByte(',')
		}
		name, err := json.Marshal(m.name)
		if err != nil {
			return nil, err
		}
		value, err := json.Marshal(m.value)
		if err != nil {
			return nil, err
		}
		b.Write(name)
		b.WriteByte(':')
		b.Write(value)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// verifierStateWith is baseVerifierState(boundKey) written as an object, with
// the member name holding value.
func verifierStateWith(boundKey KeyVector, name string, value any) object {
	vs := baseVerifierState(boundKey)
	members := object{
		{"clockRfc3339", vs.ClockRFC3339},
		{"trustedIssuers", vs.TrustedIssuers},
		{"agentBindings", vs.AgentBindings},
		{"seenNonces", vs.SeenNonces},
	}
	for i := range members {
		if members[i].name == name {
			members[i].value = value
		}
	}
	return members
}

// loadErrorFixture is the challenge-response-valid fixture with its
// verifierState and challengeResponse members given as written, for a
// fixture both reference verifiers refuse to load. Its expected member is
// the valid fixture's ACCEPT, which no conforming verifier reaches.
func loadErrorFixture(name, description string, keypairRefs []KeypairRef, verifierState, challengeResponse any) object {
	return object{
		{"$schema", "https://aip.opena2a.org/schemas/fixture-v1.json"},
		{"name", "aip-v0.3/load-errors/" + name},
		{"description", description},
		{"fixtureType", "challengeResponse"},
		{"spec", specRefs("§5.1 Challenge-Response Protocol")},
		{"keypairRefs", keypairRefs},
		{"verifierState", verifierState},
		{"expected", ExpectedOutcome{VerifyResult: "ACCEPT"}},
		{"challengeResponse", challengeResponse},
	}
}

func main() {
	outDir = mustResolveOutDir()

	primary := mustLoadKeyVector("vectors/issuer-primary.json")
	agentBound := mustLoadKeyVector("vectors/agent-bound-key.json")
	agentUnbound := mustLoadKeyVector("vectors/agent-unbound-key.json")
	agentSecond := mustLoadKeyVector("vectors/agent-second-key.json")

	// The challenge-response-valid transcript, which fixtures 9-11 and the
	// load-error fixtures start from.
	validBody := ChallengeBody{
		Challenge: validChallenge,
		AgentDID:  testAgentDID,
		Nonce:     validNonce,
		IssuedAt:  validIssuedAt,
		ExpiresAt: validExpiresAt,
		IssuerDID: testIssuerDID,
	}
	validResponse := answer(validBody, testAgentDID, agentBound, validSignedAt)

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
				Schema:      "https://aip.opena2a.org/schemas/fixture-v1.json",
				Name:        "aip-v0.2/challenge-response-valid",
				Description: "A well-formed AIP §5.1 challenge-response transcript. The IdP-issued challenge is bound to the agent's DID, the agent has signed the canonical 5-field payload with its bound key, the publicKey returned in the response matches the agentDid's bound key in verifierState, the nonce is unseen, and the challenge has not expired against the pinned verifier clock. Verifier MUST ACCEPT.",
				FixtureType: "challengeResponse",
				Spec:        specRefs("§5.1 Challenge-Response Protocol"),
				KeypairRefs: []KeypairRef{
					keypairRefFor(primary, "vectors/issuer-primary.json"),
					keypairRefFor(agentBound, "vectors/agent-bound-key.json"),
				},
				VerifierState:     vsPtr(baseVerifierState(agentBound)),
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
				Schema:      "https://aip.opena2a.org/schemas/fixture-v1.json",
				Name:        "aip-v0.2/challenge-response-wrong-key",
				Description: "An AIP §5.1 challenge-response transcript where the agent signed with a key NOT bound to its DID. The signature is mathematically valid Ed25519, but the publicKey returned in the response does not match the bound key declared for testAgentDID in verifierState.agentBindings. Verifier MUST REJECT with UNTRUSTED_KEY.",
				FixtureType: "challengeResponse",
				Spec:        specRefs("§5.1 Challenge-Response Protocol — step 5: publicKey matches registered agent"),
				KeypairRefs: []KeypairRef{
					keypairRefFor(primary, "vectors/issuer-primary.json"),
					keypairRefFor(agentBound, "vectors/agent-bound-key.json"),
					keypairRefFor(agentUnbound, "vectors/agent-unbound-key.json"),
				},
				VerifierState: vsPtr(baseVerifierState(agentBound)), // bound key is agent-bound-key; response uses agent-unbound-key
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
				Schema:      "https://aip.opena2a.org/schemas/fixture-v1.json",
				Name:        "aip-v0.2/challenge-response-stale-challenge",
				Description: "An AIP §5.1 challenge-response transcript where the challenge expired before the verifier's pinned clock. expiresAt is 25 minutes earlier than verifierState.clockRfc3339. The signature is otherwise mathematically valid and made by the agent's bound key. Verifier MUST REJECT with CHALLENGE_EXPIRED.",
				FixtureType: "challengeResponse",
				Spec:        specRefs("§5.1 Challenge-Response Protocol — step 5: challenge not expired (5-minute window)"),
				KeypairRefs: []KeypairRef{
					keypairRefFor(primary, "vectors/issuer-primary.json"),
					keypairRefFor(agentBound, "vectors/agent-bound-key.json"),
				},
				VerifierState: vsPtr(baseVerifierState(agentBound)),
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
				Schema:      "https://aip.opena2a.org/schemas/fixture-v1.json",
				Name:        "aip-v0.2/challenge-response-replay",
				Description: "An AIP §5.1 challenge-response transcript that reuses a nonce the verifier has already seen. The signature is mathematically valid, the publicKey matches the agentDid's bound key, the challenge is not expired — but the nonce appears in verifierState.seenNonces, modelling 'a prior verification already consumed this nonce.' Verifier MUST REJECT with NONCE_REPLAY.",
				FixtureType: "challengeResponse",
				Spec:        specRefs("§5.1 Challenge-Response Protocol — step 5: nonce not reused"),
				KeypairRefs: []KeypairRef{
					keypairRefFor(primary, "vectors/issuer-primary.json"),
					keypairRefFor(agentBound, "vectors/agent-bound-key.json"),
				},
				VerifierState: vsPtr(vs),
				Expected: ExpectedOutcome{
					VerifyResult:   "REJECT",
					RejectCategory: "NONCE_REPLAY",
					ReasonContains: "nonce",
				},
				ChallengeResponse: &cr,
			}
		}},

		// ----------------------------------------------------------------
		// Fixture 5: trust-score-unscored-zero-event-agent (UNSCORED)
		// ----------------------------------------------------------------
		{writePath: "fixtures/trust-score-unscored-zero-event-agent.json", build: func() Fixture {
			factors := nineFactors(map[string]FactorInput{
				"securityAlerts":     {Score: f64(1.0), Confidence: 1.0},
				"executionIsolation": {Score: f64(0.6), Confidence: 1.0},
				"age":                {Score: f64(0.3), Confidence: 1.0},
			})
			return Fixture{
				Schema:      "https://aip.opena2a.org/schemas/fixture-v1.json",
				Name:        "aip-v0.3/trust-score-unscored-zero-event-agent",
				Description: "An AIP §6.1 composition for an agent with no verification events: verification, uptime and successRate have no data (confidence 0), and the three proposed factors (compliance, driftDetection, userFeedback) are unmeasured. Only securityAlerts, executionIsolation and age carry data, so includedWeight is 0.30. Under the unscored rule the verifier MUST reach scoreStatus unscored with score null and unscoredReason insufficient_data. The composition rule alone (exclusion, redistribution, neutral-imputed ceiling) would publish 0.575 here, which is the number the rule exists to withhold.",
				FixtureType: "trustScoreComposition",
				Spec:        specRefs("§6.1 Multi-Factor Algorithm — unscored state: includedWeight below 0.50"),
				Expected: ExpectedOutcome{
					VerifyResult: "UNSCORED",
					Composition: &ExpectedComposition{
						ScoreStatus:    "unscored",
						Score:          nil,
						IncludedWeight: 0.30,
						UnscoredReason: "insufficient_data",
					},
				},
				TrustScoreComposition: &TrustScoreComposition{Factors: factors},
			}
		}},
		// ----------------------------------------------------------------
		// Fixture 6: trust-score-measured-six-factors-capped (MEASURED)
		// ----------------------------------------------------------------
		{writePath: "fixtures/trust-score-measured-six-factors-capped.json", build: func() Fixture {
			factors := nineFactors(map[string]FactorInput{
				"verification":       {Score: f64(0.9), Confidence: 1.0},
				"uptime":             {Score: f64(0.95), Confidence: 1.0},
				"successRate":        {Score: f64(0.8), Confidence: 1.0},
				"securityAlerts":     {Score: f64(1.0), Confidence: 1.0},
				"executionIsolation": {Score: f64(0.6), Confidence: 1.0},
				"age":                {Score: f64(0.75), Confidence: 1.0},
			})
			return Fixture{
				Schema:      "https://aip.opena2a.org/schemas/fixture-v1.json",
				Name:        "aip-v0.3/trust-score-measured-six-factors-capped",
				Description: "An AIP §6.1 composition with the six measured factors of the reference implementation carrying data and the three proposed factors excluded: includedWeight 0.85, measured. The weighted sum over the included factors is 0.735; renormalised over 0.85 it is 0.8647, and the neutral-imputed ceiling (0.735 plus 0.15 at 0.5) is 0.81, so the published score is the lower value 0.81. The verifier MUST reach scoreStatus measured with score 0.81.",
				FixtureType: "trustScoreComposition",
				Spec:        specRefs("§6.1 Multi-Factor Algorithm — exclusion, redistribution and the anti-gaming ceiling"),
				Expected: ExpectedOutcome{
					VerifyResult: "MEASURED",
					Composition: &ExpectedComposition{
						ScoreStatus:    "measured",
						Score:          f64(0.81),
						IncludedWeight: 0.85,
					},
				},
				TrustScoreComposition: &TrustScoreComposition{Factors: factors},
			}
		}},
		// ----------------------------------------------------------------
		// Fixture 7: trust-score-measured-at-included-weight-0.50 (MEASURED)
		// ----------------------------------------------------------------
		{writePath: "fixtures/trust-score-measured-at-included-weight-0.50.json", build: func() Fixture {
			factors := nineFactors(map[string]FactorInput{
				"verification":       {Score: f64(0.8), Confidence: 1.0},
				"uptime":             {Score: f64(1.0), Confidence: 1.0},
				"executionIsolation": {Score: f64(0.6), Confidence: 1.0},
			})
			return Fixture{
				Schema:      "https://aip.opena2a.org/schemas/fixture-v1.json",
				Name:        "aip-v0.3/trust-score-measured-at-included-weight-0.50",
				Description: "An AIP §6.1 composition sitting exactly on the threshold: verification, uptime and executionIsolation carry data (weights 25, 15 and 10), so includedWeight is 0.50, which is not below 0.50. The verifier MUST reach scoreStatus measured: weighted sum 0.41, renormalised 0.82, neutral-imputed ceiling 0.66, published score 0.66.",
				FixtureType: "trustScoreComposition",
				Spec:        specRefs("§6.1 Multi-Factor Algorithm — unscored state: the threshold is strict (0.50 is measured)"),
				Expected: ExpectedOutcome{
					VerifyResult: "MEASURED",
					Composition: &ExpectedComposition{
						ScoreStatus:    "measured",
						Score:          f64(0.66),
						IncludedWeight: 0.50,
					},
				},
				TrustScoreComposition: &TrustScoreComposition{Factors: factors},
			}
		}},

		// ----------------------------------------------------------------
		// Fixture 8: challenge-response-echoed-nonce-differs (REJECT SIGNATURE_INVALID)
		// ----------------------------------------------------------------
		{"fixtures/challenge-response-echoed-nonce-differs.json", func() Fixture {
			// The replay transcript: its challenge body carries fixture 1's
			// nonce, which verifierState lists as seen. Only the response's
			// echo of the nonce changes.
			cb := ChallengeBody{
				Challenge: replayChallenge,
				AgentDID:  testAgentDID,
				Nonce:     validNonce,
				IssuedAt:  replayIssuedAt,
				ExpiresAt: replayExpiresAt,
				IssuerDID: testIssuerDID,
			}
			rb := answer(cb, testAgentDID, agentBound, replaySignedAt)
			rb.Nonce = echoedNonce
			vs := baseVerifierState(agentBound)
			vs.SeenNonces = []string{validNonce}
			return Fixture{
				Schema:      "https://aip.opena2a.org/schemas/fixture-v1.json",
				Name:        "aip-v0.3/challenge-response-echoed-nonce-differs",
				Description: "The challenge-response-replay transcript with one edit: the response echoes a nonce the verifier has not seen, while the challenge body, which the signature covers, carries the nonce listed in verifierState.seenNonces. The signature verifies under the agent's bound key and the challenge has not expired. Each of the five fields the response echoes must equal the challenge body's, and the nonce check reads the challenge body. Verifier MUST REJECT with SIGNATURE_INVALID.",
				FixtureType: "challengeResponse",
				Spec:        specRefs("§5.1 Challenge-Response Protocol — step 5: the five fields the response echoes equal the challenge body's"),
				KeypairRefs: []KeypairRef{
					keypairRefFor(primary, "vectors/issuer-primary.json"),
					keypairRefFor(agentBound, "vectors/agent-bound-key.json"),
				},
				VerifierState: vsPtr(vs),
				Expected: ExpectedOutcome{
					VerifyResult:   "REJECT",
					RejectCategory: "SIGNATURE_INVALID",
					ReasonContains: "response.nonce",
				},
				ChallengeResponse: &ChallengeResponse{Challenge: cb, Response: rb},
			}
		}},

		// ----------------------------------------------------------------
		// Fixture 9: challenge-response-echoed-agent-differs (REJECT SIGNATURE_INVALID)
		// ----------------------------------------------------------------
		{"fixtures/challenge-response-echoed-agent-differs.json", func() Fixture {
			vs := baseVerifierState(agentBound)
			vs.AgentBindings = append(vs.AgentBindings, bindingFor(agentSecond.AgentDID, agentSecond))
			return Fixture{
				Schema:      "https://aip.opena2a.org/schemas/fixture-v1.json",
				Name:        "aip-v0.3/challenge-response-echoed-agent-differs",
				Description: "An AIP §5.1 transcript whose challenge was minted for agent_conformance_test_001 and whose response is signed with the key bound to agent_conformance_test_002 and echoes that agent's DID. verifierState binds both agents' keys. The signature verifies over the challenge body, but the echoed agentDid is not the challenge body's. Each of the five fields the response echoes must equal the challenge body's, and the bound-key check reads the challenge body's agentDid. Verifier MUST REJECT with SIGNATURE_INVALID.",
				FixtureType: "challengeResponse",
				Spec:        specRefs("§5.1 Challenge-Response Protocol — step 5: the five fields the response echoes equal the challenge body's"),
				KeypairRefs: []KeypairRef{
					keypairRefFor(primary, "vectors/issuer-primary.json"),
					keypairRefFor(agentBound, "vectors/agent-bound-key.json"),
					keypairRefFor(agentSecond, "vectors/agent-second-key.json"),
				},
				VerifierState: vsPtr(vs),
				Expected: ExpectedOutcome{
					VerifyResult:   "REJECT",
					RejectCategory: "SIGNATURE_INVALID",
					ReasonContains: "response.agentDid",
				},
				ChallengeResponse: &ChallengeResponse{
					Challenge: validBody,
					Response:  answer(validBody, agentSecond.AgentDID, agentSecond, validSignedAt),
				},
			}
		}},

		// ----------------------------------------------------------------
		// Fixture 10: challenge-response-other-agent-key (REJECT UNTRUSTED_KEY)
		// ----------------------------------------------------------------
		{"fixtures/challenge-response-other-agent-key.json", func() Fixture {
			vs := baseVerifierState(agentBound)
			vs.AgentBindings = append(vs.AgentBindings, bindingFor(agentSecond.AgentDID, agentSecond))
			return Fixture{
				Schema:      "https://aip.opena2a.org/schemas/fixture-v1.json",
				Name:        "aip-v0.3/challenge-response-other-agent-key",
				Description: "An AIP §5.1 transcript whose challenge was minted for agent_conformance_test_001 and whose response echoes every challenge field but is signed with the key bound to agent_conformance_test_002. verifierState binds both agents' keys. The signature verifies, but the presented publicKey is not the key bound to the challenge's agentDid. Verifier MUST REJECT with UNTRUSTED_KEY.",
				FixtureType: "challengeResponse",
				Spec:        specRefs("§5.1 Challenge-Response Protocol — step 5: publicKey matches the key bound to the challenge's agentDid"),
				KeypairRefs: []KeypairRef{
					keypairRefFor(primary, "vectors/issuer-primary.json"),
					keypairRefFor(agentBound, "vectors/agent-bound-key.json"),
					keypairRefFor(agentSecond, "vectors/agent-second-key.json"),
				},
				VerifierState: vsPtr(vs),
				Expected: ExpectedOutcome{
					VerifyResult:   "REJECT",
					RejectCategory: "UNTRUSTED_KEY",
					ReasonContains: "publicKey does not match",
				},
				ChallengeResponse: &ChallengeResponse{
					Challenge: validBody,
					Response:  answer(validBody, testAgentDID, agentSecond, validSignedAt),
				},
			}
		}},

		// ----------------------------------------------------------------
		// Fixture 11: challenge-response-untrusted-issuer (REJECT UNTRUSTED_ISSUER)
		// ----------------------------------------------------------------
		{"fixtures/challenge-response-untrusted-issuer.json", func() Fixture {
			vs := baseVerifierState(agentBound)
			vs.TrustedIssuers = []string{otherIssuerDID}
			return Fixture{
				Schema:      "https://aip.opena2a.org/schemas/fixture-v1.json",
				Name:        "aip-v0.3/challenge-response-untrusted-issuer",
				Description: "The challenge-response-valid transcript under a verifierState whose trustedIssuers does not hold the challenge's issuerDid. The signature verifies under the agent's bound key, the challenge has not expired and the nonce is unseen; the trusted-issuer check runs after those four. Verifier MUST REJECT with UNTRUSTED_ISSUER.",
				FixtureType: "challengeResponse",
				Spec:        specRefs("§5.1 Challenge-Response Protocol — step 5: issuerDid is a trusted issuer"),
				KeypairRefs: []KeypairRef{
					keypairRefFor(primary, "vectors/issuer-primary.json"),
					keypairRefFor(agentBound, "vectors/agent-bound-key.json"),
				},
				VerifierState: vsPtr(vs),
				Expected: ExpectedOutcome{
					VerifyResult:   "REJECT",
					RejectCategory: "UNTRUSTED_ISSUER",
					ReasonContains: "issuerDid",
				},
				ChallengeResponse: &ChallengeResponse{Challenge: validBody, Response: validResponse},
			}
		}},
	}

	// Load-error fixtures: the valid fixture with one edit that makes both
	// reference verifiers refuse to load it. They sit outside fixtures/*.json,
	// so no verifier walk of fixtures/ reads them; MANIFEST.sha256 pins them.
	validKeys := []KeypairRef{
		keypairRefFor(primary, "vectors/issuer-primary.json"),
		keypairRefFor(agentBound, "vectors/agent-bound-key.json"),
	}
	validState := baseVerifierState(agentBound)
	loadErrors := []struct {
		writePath string
		build     func() object
	}{
		{"fixtures/load-errors/challenge-response-repeated-challenge.json", func() object {
			return loadErrorFixture("challenge-response-repeated-challenge",
				"The challenge-response-valid fixture with one edit: challengeResponse writes its challenge member twice, both copies the same. A JSON object outside the two §5.1 bodies that writes one member name twice has no single reading. A verifier MUST refuse to load the fixture; the expected member is the valid fixture's and is never reached.",
				validKeys, validState,
				object{{"challenge", validBody}, {"challenge", validBody}, {"response", validResponse}})
		}},
		{"fixtures/load-errors/challenge-response-repeated-response.json", func() object {
			return loadErrorFixture("challenge-response-repeated-response",
				"The challenge-response-valid fixture with one edit: challengeResponse writes its response member twice, both copies the same. A JSON object outside the two §5.1 bodies that writes one member name twice has no single reading. A verifier MUST refuse to load the fixture; the expected member is the valid fixture's and is never reached.",
				validKeys, validState,
				object{{"challenge", validBody}, {"response", validResponse}, {"response", validResponse}})
		}},
		{"fixtures/load-errors/verifier-state-seen-nonces-not-an-array.json", func() object {
			return loadErrorFixture("verifier-state-seen-nonces-not-an-array",
				"The challenge-response-valid fixture with one edit: verifierState.seenNonces is the number 0. A trustedIssuers, agentBindings or seenNonces member of verifierState that is present must be an array or null. A verifier MUST refuse to load the fixture; the expected member is the valid fixture's and is never reached.",
				validKeys, verifierStateWith(agentBound, "seenNonces", 0),
				ChallengeResponse{Challenge: validBody, Response: validResponse})
		}},
		{"fixtures/load-errors/verifier-state-agent-bindings-not-an-array.json", func() object {
			return loadErrorFixture("verifier-state-agent-bindings-not-an-array",
				"The challenge-response-valid fixture with one edit: verifierState.agentBindings is an empty object. A trustedIssuers, agentBindings or seenNonces member of verifierState that is present must be an array or null. A verifier MUST refuse to load the fixture; the expected member is the valid fixture's and is never reached.",
				validKeys, verifierStateWith(agentBound, "agentBindings", object{}),
				ChallengeResponse{Challenge: validBody, Response: validResponse})
		}},
		{"fixtures/load-errors/verifier-state-trusted-issuers-not-an-array.json", func() object {
			return loadErrorFixture("verifier-state-trusted-issuers-not-an-array",
				"The challenge-response-valid fixture with one edit: verifierState.trustedIssuers is an empty string. A trustedIssuers, agentBindings or seenNonces member of verifierState that is present must be an array or null. A verifier MUST refuse to load the fixture; the expected member is the valid fixture's and is never reached.",
				validKeys, verifierStateWith(agentBound, "trustedIssuers", ""),
				ChallengeResponse{Challenge: validBody, Response: validResponse})
		}},
	}

	manifest := make(map[string]string)
	for _, fs := range fixtures {
		f := fs.build()
		writeFixture(fs.writePath, f, manifest)
	}
	for _, le := range loadErrors {
		writeFixture(le.writePath, le.build(), manifest)
	}
	writeManifest("MANIFEST.sha256", manifest)
}

// ---------------------------------------------------------------------------
// io helpers
// ---------------------------------------------------------------------------

func writeFixture(relPath string, f any, manifest map[string]string) {
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
	b.WriteString("# AIP conformance fixtures (§5.1 challenge-response, §6.1 trust-score composition) — SHA-256 (per file, path-sorted)\n")
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
