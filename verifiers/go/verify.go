// verify is a reference verifier for the AIP §5.1 challenge-response
// conformance fixtures. It walks every *.json file in a directory (or
// individual fixture files), reconstructs the canonical signing payload,
// verifies the Ed25519 signature, and applies the AIP §5.1 step-5 checks
// against the fixture's pinned verifierState.
//
// With no arguments it walks the fixture set embedded in the module root
// (fixtures/*.json at this module version), so the published entry point
//
//	go run github.com/opena2a-standards/aip-conformance/verifiers/go@latest
//
// verifies the shipped fixtures without a checkout.
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
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	aipconformance "github.com/opena2a-standards/aip-conformance"
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

// unscoredThreshold is the AIP §6.1 included-weight threshold: below it the
// agent is unscored. The section is the one home of this number.
const unscoredThreshold = 0.50

// composeTrustScore applies AIP §6.1 to the fixture's factor inputs. A factor
// with confidence 0 or no score is excluded and its weight redistributed
// proportionally (the sum is renormalised over the included weight); the
// published value is capped at the neutral-imputed composite (every excluded
// factor scored 0.5), so withholding data never outscores a neutral measurement.
// When the included weight is below the threshold the agent is unscored: no
// composite is published (score null), the reason is insufficient_data.
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
	if round4(includedWeight) < unscoredThreshold {
		return compositionResult{
			verdict:        "UNSCORED",
			includedWeight: round4(includedWeight),
			unscoredReason: "insufficient_data",
		}
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

func runComposition(w io.Writer, path string, f Fixture) bool {
	if f.TrustScoreComposition == nil || f.Expected.Composition == nil {
		fmt.Fprintf(w, "FAIL  %s\n       trustScoreComposition payload or expected.composition missing\n", path)
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
	fmt.Fprintf(w, "%s  %s\n       expected: %s\n       observed: %s\n", gate, path, expectedDetail, observedDetail)
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
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// embeddedFixtureDir is the directory of the module root that fixtures.go
// embeds; embedded fixtures are reported under this module-relative path.
const embeddedFixtureDir = "fixtures"

// run verifies the fixtures named by args (directories or files) and returns
// the process exit code: 0 when every fixture passes, 1 when one or more
// fail, 2 when the arguments name no fixture file. With no args it walks the
// fixture set embedded in the module root instead, after one line naming
// the module and version those fixtures came from.
func run(args []string, stdout, stderr io.Writer) int {
	var (
		paths []string
		read  func(string) ([]byte, error)
	)
	if len(args) == 0 {
		paths = embeddedFixturePaths()
		read = func(p string) ([]byte, error) { return fs.ReadFile(aipconformance.Fixtures, p) }
		fmt.Fprintf(stdout, "fixtures: %d embedded in %s\n", len(paths), moduleIdentity())
	} else {
		paths = collectFixturePaths(args, stderr)
		read = readFixtureFile
	}
	if len(paths) == 0 {
		fmt.Fprintln(stderr, "no fixtures found")
		return 2
	}

	pass, fail := 0, 0
	for _, p := range paths {
		if runFixture(stdout, p, read) {
			pass++
		} else {
			fail++
		}
	}
	fmt.Fprintf(stdout, "\nsummary: %d pass, %d fail (%d fixtures)\n", pass, fail, len(paths))
	if fail > 0 {
		return 1
	}
	return 0
}

// embeddedFixturePaths lists the fixture files embedded in the module root,
// sorted by path like the on-disk walk.
func embeddedFixturePaths() []string {
	matches, err := fs.Glob(aipconformance.Fixtures, embeddedFixtureDir+"/*.json")
	if err != nil {
		return nil
	}
	sort.Strings(matches)
	return matches
}

// moduleIdentity names the module and version this binary was built from, so
// a run over the embedded fixtures records which published fixture set it
// verified. A build without version stamping reports the module path alone.
func moduleIdentity() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok || bi.Main.Path == "" {
		return "this build"
	}
	if bi.Main.Version == "" {
		return bi.Main.Path
	}
	return bi.Main.Path + " " + bi.Main.Version
}

// readFixtureFile reads a fixture named on the command line. The path
// originates from os.Args (operator-supplied fixture file/dir); this is a
// standalone CLI verifier with no network/request surface, so no untrusted
// taint.
func readFixtureFile(path string) ([]byte, error) {
	return os.ReadFile(path) //nolint:gosec // G304: operator-supplied CLI arg, not request-derived
}

func collectFixturePaths(args []string, stderr io.Writer) []string {
	var out []string
	for _, a := range args {
		info, err := os.Stat(a) //nolint:gosec // G703: operator-supplied CLI arg, not request-derived
		if err != nil {
			fmt.Fprintf(stderr, "cannot stat %s: %v\n", a, err)
			continue
		}
		if info.IsDir() {
			matches, err := filepath.Glob(filepath.Join(a, "*.json"))
			if err != nil {
				fmt.Fprintf(stderr, "glob %s: %v\n", a, err)
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

// runFixture verifies one fixture, read through read (a file on disk or an
// embedded entry), and reports its PASS or FAIL block on w.
func runFixture(w io.Writer, path string, read func(string) ([]byte, error)) bool {
	b, err := read(path)
	if err != nil {
		fmt.Fprintf(w, "FAIL  %s\n       read error: %v\n", path, err)
		return false
	}
	var f Fixture
	if err := json.Unmarshal(b, &f); err != nil {
		fmt.Fprintf(w, "FAIL  %s\n       parse error: %v\n", path, err)
		return false
	}

	if f.FixtureType == "trustScoreComposition" {
		return runComposition(w, path, f)
	}
	if f.FixtureType != "challengeResponse" {
		fmt.Fprintf(w, "SKIP  %s\n       fixtureType=%s (this verifier handles challengeResponse and trustScoreComposition)\n", path, f.FixtureType)
		return true
	}
	if f.ChallengeResponse == nil {
		fmt.Fprintf(w, "FAIL  %s\n       challengeResponse payload missing\n", path)
		return false
	}

	r := verifyChallengeResponse(f.ChallengeResponse, f.VerifierState)
	expected := f.Expected.VerifyResult
	observedDetail := r.verdict
	if r.verdict == "REJECT" {
		observedDetail = fmt.Sprintf("REJECT[%s: %s]", r.rejectCategory, r.reason)
	}

	if r.verdict != expected {
		fmt.Fprintf(w, "FAIL  %s\n       expected: %s%s\n       observed: %s\n",
			path, expected, formatExpectedReject(f.Expected), observedDetail)
		return false
	}

	if expected == "REJECT" && f.Expected.RejectCategory != "" && r.rejectCategory != f.Expected.RejectCategory {
		fmt.Fprintf(w, "FAIL  %s\n       expected: REJECT [%s]\n       observed: REJECT [%s: %s]\n",
			path, f.Expected.RejectCategory, r.rejectCategory, r.reason)
		return false
	}
	if expected == "REJECT" && f.Expected.ReasonContains != "" && !strings.Contains(strings.ToLower(r.reason), strings.ToLower(f.Expected.ReasonContains)) {
		fmt.Fprintf(w, "FAIL  %s\n       expected reason to contain: %q\n       observed reason: %s\n",
			path, f.Expected.ReasonContains, r.reason)
		return false
	}

	fmt.Fprintf(w, "PASS  %s\n       expected: %s%s\n       observed: %s\n",
		path, expected, formatExpectedReject(f.Expected), observedDetail)
	if r.signaturesNote != "" {
		fmt.Fprintf(w, "       %s\n", r.signaturesNote)
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
