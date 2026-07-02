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

	if f.FixtureType != "challengeResponse" {
		fmt.Printf("SKIP  %s\n       fixtureType=%s (this verifier only handles challengeResponse)\n", path, f.FixtureType)
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
