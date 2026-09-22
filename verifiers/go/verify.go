// verify is a reference verifier for the AIP §5.1 challenge-response
// conformance fixtures. It walks every *.json file in a directory (or
// individual fixture files), reconstructs the canonical signing payload,
// verifies the Ed25519 signature, and applies the AIP §5.1 step-5 checks
// against the fixture's pinned verifierState.
//
// Exit code is 0 if every fixture's observed result matches the expected
// result AND the rejection category matches (when declared).
//
// Canonical signing form (5 fields, pipe-delimited) — MUST mirror
// scripts/generate-fixtures/main.go canonicalChallengeResponsePayload
// VERBATIM:
//
//	challenge | agentDid | nonce | issuedAt | expiresAt
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// fixture wrapper (must match scripts/generate-fixtures shape)
// ---------------------------------------------------------------------------

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
	// Composition is set on trustScoreComposition fixtures only.
	Composition *ExpectedComposition `json:"composition,omitempty"`
}

// ExpectedComposition is the AIP §6.1 state a composition fixture pins.
type ExpectedComposition struct {
	ScoreStatus    string   `json:"scoreStatus"`
	Score          *float64 `json:"score"`
	IncludedWeight float64  `json:"includedWeight"`
	UnscoredReason string   `json:"unscoredReason,omitempty"`
}

// FactorInput is one §6.1 factor as an implementation holds it before
// composition: identifier, weight in points of 100, per-factor score (nil when
// there is no data) and the data-availability confidence.
type FactorInput struct {
	Factor     string   `json:"factor"`
	Weight     int      `json:"weight"`
	Score      *float64 `json:"score"`
	Confidence float64  `json:"confidence"`
}

type TrustScoreComposition struct {
	Factors []FactorInput `json:"factors"`
}

type ChallengeBody struct {
	Challenge string `json:"challenge"`
	AgentDID  string `json:"agentDid"`
	Nonce     string `json:"nonce"`
	IssuedAt  string `json:"issuedAt"`
	ExpiresAt string `json:"expiresAt"`
	IssuerDID string `json:"issuerDid"`
}

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

type ChallengeResponse struct {
	Challenge ChallengeBody `json:"challenge"`
	Response  ResponseBody  `json:"response"`
}

type Fixture struct {
	Schema            string             `json:"$schema"`
	Name              string             `json:"name"`
	Description       string             `json:"description"`
	FixtureType       string             `json:"fixtureType"`
	VerifierState     VerifierState      `json:"verifierState"`
	Expected          ExpectedOutcome    `json:"expected"`
	ChallengeResponse *ChallengeResponse `json:"challengeResponse,omitempty"`
	// TrustScoreComposition is set on trustScoreComposition fixtures only.
	TrustScoreComposition *TrustScoreComposition `json:"trustScoreComposition,omitempty"`
}

// ---------------------------------------------------------------------------
// AIP §6.1 trust-score composition (MUST match the Python verifier)
// ---------------------------------------------------------------------------

type compositionResult struct {
	verdict        string // "MEASURED" or "UNSCORED"
	score          float64
	includedWeight float64
	unscoredReason string
}

func round4(v float64) float64 { return math.Round(v*10000) / 10000 }

// composeTrustScore applies AIP §6.1 to the fixture's factor inputs. A factor
// with confidence 0 or no score is excluded and its weight redistributed
// proportionally (the sum is renormalised over the included weight); the
// published value is capped at the neutral-imputed composite (every excluded
// factor scored 0.5), so withholding data never outscores a neutral measurement.
func composeTrustScore(c *TrustScoreComposition) compositionResult {
	var weightedSum, includedWeight, excludedWeight float64
	for _, f := range c.Factors {
		w := float64(f.Weight) / 100
		if f.Confidence <= 0 || f.Score == nil {
			excludedWeight += w
			continue
		}
		includedWeight += w
		weightedSum += w * (*f.Score) * f.Confidence
	}
	renormalised := 0.0
	if includedWeight > 0 {
		renormalised = weightedSum / includedWeight
	}
	imputed := weightedSum + excludedWeight*0.5
	return compositionResult{
		verdict:        "MEASURED",
		score:          round4(math.Min(renormalised, imputed)),
		includedWeight: round4(includedWeight),
	}
}

func runComposition(path string, f Fixture) bool {
	if f.TrustScoreComposition == nil || f.Expected.Composition == nil {
		fmt.Printf("FAIL  %s\n       trustScoreComposition payload or expected.composition missing\n", path)
		return false
	}
	exp := f.Expected.Composition
	r := composeTrustScore(f.TrustScoreComposition)

	expectedDetail := fmt.Sprintf("%s [scoreStatus=%s", f.Expected.VerifyResult, exp.ScoreStatus)
	if exp.Score != nil {
		expectedDetail += fmt.Sprintf(" score=%.4f", *exp.Score)
	} else {
		expectedDetail += " score=null"
	}
	expectedDetail += fmt.Sprintf(" includedWeight=%.4f", exp.IncludedWeight)
	if exp.UnscoredReason != "" {
		expectedDetail += " unscoredReason=" + exp.UnscoredReason
	}
	expectedDetail += "]"

	observedDetail := r.verdict + "["
	if r.verdict == "UNSCORED" {
		observedDetail += "score=null unscoredReason=" + r.unscoredReason
	} else {
		observedDetail += fmt.Sprintf("score=%.4f", r.score)
	}
	observedDetail += fmt.Sprintf(" includedWeight=%.4f]", r.includedWeight)

	ok := r.verdict == f.Expected.VerifyResult &&
		round4(r.includedWeight) == round4(exp.IncludedWeight)
	if ok && r.verdict == "MEASURED" {
		ok = exp.Score != nil && round4(r.score) == round4(*exp.Score)
	}
	if ok && r.verdict == "UNSCORED" {
		ok = exp.Score == nil && (exp.UnscoredReason == "" || exp.UnscoredReason == r.unscoredReason)
	}
	gate := "PASS"
	if !ok {
		gate = "FAIL"
	}
	fmt.Printf("%s  %s\n       expected: %s\n       observed: %s\n", gate, path, expectedDetail, observedDetail)
	return ok
}

// ---------------------------------------------------------------------------
// canonicalization (MUST match generator)
// ---------------------------------------------------------------------------

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
	if err != nil {
		return s
	}
	return t.UTC().Format(time.RFC3339)
}

// ---------------------------------------------------------------------------
// verification
// ---------------------------------------------------------------------------

type result struct {
	verdict        string // "ACCEPT" or "REJECT"
	rejectCategory string // populated on REJECT
	reason         string
	signaturesNote string // diagnostic line shown in PASS/FAIL output
}

// verifyChallengeResponse applies the AIP §5.1 step-5 checks in order:
//
//  1. Signature valid for challenge + publicKey (cryptographic check)
//  2. publicKey matches the agentDid's bound key in verifierState.agentBindings
//  3. Challenge not expired (verifier clock < expiresAt)
//  4. Nonce not in verifierState.seenNonces
//
// The first failing check wins; subsequent checks are not performed.
func verifyChallengeResponse(cr *ChallengeResponse, vs VerifierState) result {
	// (1) Signature verification
	pubBytes, err := base64.RawStdEncoding.DecodeString(cr.Response.PublicKey)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return result{
			verdict:        "REJECT",
			rejectCategory: "SIGNATURE_INVALID",
			reason:         fmt.Sprintf("response.publicKey is not a valid base64-no-padding Ed25519 public key (%d bytes)", len(pubBytes)),
		}
	}
	sigBytes, err := base64.RawStdEncoding.DecodeString(cr.Response.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return result{
			verdict:        "REJECT",
			rejectCategory: "SIGNATURE_INVALID",
			reason:         fmt.Sprintf("response.signature is not a valid base64-no-padding Ed25519 signature (%d bytes)", len(sigBytes)),
		}
	}
	canonical := canonicalChallengeResponsePayload(cr.Challenge)
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), canonical, sigBytes) {
		return result{
			verdict:        "REJECT",
			rejectCategory: "SIGNATURE_INVALID",
			reason:         "Ed25519 signature did not verify against the canonical 5-field payload",
		}
	}

	// (2) publicKey matches bound key for response.agentDid
	bound, found := lookupAgentBinding(vs, cr.Response.AgentDID)
	if !found {
		return result{
			verdict:        "REJECT",
			rejectCategory: "UNTRUSTED_KEY",
			reason:         fmt.Sprintf("response.agentDid %s has no agentBinding in verifierState", cr.Response.AgentDID),
		}
	}
	boundPubHex := hex.EncodeToString(pubBytes)
	if boundPubHex != bound.PublicKeyHex {
		return result{
			verdict:        "REJECT",
			rejectCategory: "UNTRUSTED_KEY",
			reason:         fmt.Sprintf("response.publicKey does not match bound key for agentDid %s (got %s..., bound is %s...)", cr.Response.AgentDID, boundPubHex[:16], bound.PublicKeyHex[:16]),
		}
	}

	// (3) Challenge not expired
	clock, err := time.Parse(time.RFC3339, vs.ClockRFC3339)
	if err != nil {
		return result{
			verdict:        "REJECT",
			rejectCategory: "SIGNATURE_INVALID",
			reason:         fmt.Sprintf("verifierState.clockRfc3339 is not RFC 3339: %v", err),
		}
	}
	expiresAt, err := time.Parse(time.RFC3339, cr.Challenge.ExpiresAt)
	if err != nil {
		return result{
			verdict:        "REJECT",
			rejectCategory: "CHALLENGE_EXPIRED",
			reason:         fmt.Sprintf("challenge.expiresAt is not RFC 3339: %v", err),
		}
	}
	if !clock.Before(expiresAt) {
		return result{
			verdict:        "REJECT",
			rejectCategory: "CHALLENGE_EXPIRED",
			reason:         fmt.Sprintf("verifier clock %s is not before challenge.expiresAt %s", clock.UTC().Format(time.RFC3339), expiresAt.UTC().Format(time.RFC3339)),
		}
	}

	// (4) Nonce not in seenNonces
	for _, seen := range vs.SeenNonces {
		if seen == cr.Response.Nonce {
			return result{
				verdict:        "REJECT",
				rejectCategory: "NONCE_REPLAY",
				reason:         fmt.Sprintf("response.nonce was already seen by the verifier"),
			}
		}
	}

	return result{
		verdict:        "ACCEPT",
		signaturesNote: fmt.Sprintf("signature: ed25519=true (verified against agentDid %s bound key)", cr.Response.AgentDID),
	}
}

func lookupAgentBinding(vs VerifierState, agentDID string) (AgentBinding, bool) {
	for _, b := range vs.AgentBindings {
		if b.AgentDID == agentDID {
			return b, true
		}
	}
	return AgentBinding{}, false
}

// ---------------------------------------------------------------------------
// fixture walking + reporting
// ---------------------------------------------------------------------------

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: verify <fixture-dir-or-file> [...]")
		os.Exit(2)
	}

	paths := collectFixturePaths(os.Args[1:])
	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "no fixtures found")
		os.Exit(2)
	}

	pass, fail := 0, 0
	for _, p := range paths {
		ok := runFixture(p)
		if ok {
			pass++
		} else {
			fail++
		}
	}
	fmt.Printf("\nsummary: %d pass, %d fail (%d fixtures)\n", pass, fail, len(paths))
	if fail > 0 {
		os.Exit(1)
	}
}

func collectFixturePaths(args []string) []string {
	var out []string
	for _, a := range args {
		info, err := os.Stat(a) //nolint:gosec // G703: operator-supplied CLI arg, not request-derived
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot stat %s: %v\n", a, err)
			continue
		}
		if info.IsDir() {
			matches, err := filepath.Glob(filepath.Join(a, "*.json"))
			if err != nil {
				fmt.Fprintf(os.Stderr, "glob %s: %v\n", a, err)
				continue
			}
			out = append(out, matches...)
		} else {
			out = append(out, a)
		}
	}
	sort.Strings(out)
	return out
}

func runFixture(path string) bool {
	// path originates from os.Args[1:] (operator-supplied fixture file/dir); this is a
	// standalone CLI verifier with no network/request surface, so no untrusted taint.
	b, err := os.ReadFile(path) //nolint:gosec // G304: operator-supplied CLI arg, not request-derived
	if err != nil {
		fmt.Printf("FAIL  %s\n       read error: %v\n", path, err)
		return false
	}
	var f Fixture
	if err := json.Unmarshal(b, &f); err != nil {
		fmt.Printf("FAIL  %s\n       parse error: %v\n", path, err)
		return false
	}

	if f.FixtureType == "trustScoreComposition" {
		return runComposition(path, f)
	}
	if f.FixtureType != "challengeResponse" {
		fmt.Printf("SKIP  %s\n       fixtureType=%s (this verifier handles challengeResponse and trustScoreComposition)\n", path, f.FixtureType)
		return true
	}
	if f.ChallengeResponse == nil {
		fmt.Printf("FAIL  %s\n       challengeResponse payload missing\n", path)
		return false
	}

	r := verifyChallengeResponse(f.ChallengeResponse, f.VerifierState)
	expected := f.Expected.VerifyResult
	observedDetail := r.verdict
	if r.verdict == "REJECT" {
		observedDetail = fmt.Sprintf("REJECT[%s: %s]", r.rejectCategory, r.reason)
	}

	if r.verdict != expected {
		fmt.Printf("FAIL  %s\n       expected: %s%s\n       observed: %s\n",
			path, expected, formatExpectedReject(f.Expected), observedDetail)
		return false
	}

	if expected == "REJECT" && f.Expected.RejectCategory != "" && r.rejectCategory != f.Expected.RejectCategory {
		fmt.Printf("FAIL  %s\n       expected: REJECT [%s]\n       observed: REJECT [%s: %s]\n",
			path, f.Expected.RejectCategory, r.rejectCategory, r.reason)
		return false
	}
	if expected == "REJECT" && f.Expected.ReasonContains != "" && !strings.Contains(strings.ToLower(r.reason), strings.ToLower(f.Expected.ReasonContains)) {
		fmt.Printf("FAIL  %s\n       expected reason to contain: %q\n       observed reason: %s\n",
			path, f.Expected.ReasonContains, r.reason)
		return false
	}

	fmt.Printf("PASS  %s\n       expected: %s%s\n       observed: %s\n",
		path, expected, formatExpectedReject(f.Expected), observedDetail)
	if r.signaturesNote != "" {
		fmt.Printf("       %s\n", r.signaturesNote)
	}
	return true
}

func formatExpectedReject(e ExpectedOutcome) string {
	if e.VerifyResult != "REJECT" {
		return ""
	}
	if e.RejectCategory == "" {
		return ""
	}
	return fmt.Sprintf(" [%s]", e.RejectCategory)
}
