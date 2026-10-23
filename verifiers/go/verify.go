// verify is a reference verifier for the AIP §5.1 challenge-response
// conformance fixtures. It walks every *.json file in a directory (or
// individual fixture files), reconstructs the canonical signing payload,
// verifies the Ed25519 signature, and applies the AIP §5.1 step-5 checks
// against the fixture's pinned verifierState.
//
// With no arguments it walks the fixture set embedded in the module root
// (fixtures/*.json at this module version), so the published entry point
//
//	go run github.com/opena2a-standards/aip-conformance/verifiers/go@<version>
//
// verifies the shipped fixtures without a checkout. The README's first
// command names the current suite version.
//
// Exit code is 0 if every fixture's observed result matches the expected
// result AND the rejection category matches (when declared).
//
// Outside challengeResponse a fixture's members are read under their exact
// names (VerifierState is not verifierState), and a fixture that writes one
// member name twice in the same JSON object fails to load on both verifiers,
// which counts as a fail (exit code 1).
//
// A challengeResponse fixture whose agentBindings entry for response.agentDid
// has no publicKeyHex member, or a null one, prints a FAIL block naming the
// member, in the form the Python verifier uses for a fixture error:
//
//	FAIL  <path>
//	       fixture error: verifierState.agentBindings[0].publicKeyHex: missing
//
// The checks read that entry only after the signature check passes. The
// fixture counts as a fail, and the run goes on to the next fixture and
// prints the summary line.
//
// Canonical signing form (5 fields, pipe-delimited) — MUST mirror
// scripts/generate-fixtures/main.go canonicalChallengeResponsePayload
// VERBATIM:
//
//	challenge | agentDid | nonce | issuedAt | expiresAt
package main

import (
	"bytes"
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
	"reflect"
	"runtime/debug"
	"sort"
	"strconv"
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
	// publicKeyHexProblem is "missing" when the entry writes no publicKeyHex
	// member and "null, not a string" when it writes null there, both of
	// which encoding/json decodes as the empty string. parseFixture sets it.
	publicKeyHexProblem string
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
// fixture parsing (MUST match the Python verifier's load_fixture)
// ---------------------------------------------------------------------------

// protocolMessages names the fixture member that holds the protocol messages
// under test. parseFixture leaves its value to encoding/json as written: it
// is not walked for repeated member names, and its members are not narrowed
// to their exact names. The Python verifier's _PROTOCOL_MESSAGES holds the
// same name.
var protocolMessages = map[string]bool{"challengeResponse": true}

// protocolMessagesType is the decode target of the protocolMessages member.
var protocolMessagesType = reflect.TypeOf(ChallengeResponse{})

// parseFixture decodes a fixture file. A JSON object outside the value of
// challengeResponse that writes one member name twice is a load error: the
// verifier state or expected outcome it carries has no single reading, and
// encoding/json would decode both copies into one struct, keeping a member
// the later copy omits, where the Python verifier reads the later copy
// alone. Outside challengeResponse each member is read under its exact name
// (exactMembers). A file that is not JSON fails with the error json.Unmarshal
// reports for it. An agentBindings entry that writes no publicKeyHex, or a
// null one, is marked for the checks (markPublicKeyHexProblems).
func parseFixture(b []byte) (Fixture, error) {
	var f Fixture
	if json.Valid(b) {
		if member, ok := repeatedMember("", b, protocolMessages); ok {
			return f, fmt.Errorf("%s: duplicate member name", member)
		}
		b = exactMembers(b, reflect.TypeOf(f))
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return f, err
	}
	markPublicKeyHexProblems(b, f.VerifierState.AgentBindings)
	return f, nil
}

// markPublicKeyHexProblems sets publicKeyHexProblem on each entry of
// bindings, the verifierState.agentBindings decoded from raw without error,
// whose publicKeyHex member raw leaves out or writes as null. The Python
// verifier's FixtureError names the same two problems.
func markPublicKeyHexProblems(raw []byte, bindings []AgentBinding) {
	var written struct {
		VerifierState struct {
			AgentBindings []map[string]json.RawMessage `json:"agentBindings"`
		} `json:"verifierState"`
	}
	if json.Unmarshal(raw, &written) != nil {
		return
	}
	for i, entry := range written.VerifierState.AgentBindings {
		if i == len(bindings) {
			break
		}
		if value, ok := entry["publicKeyHex"]; !ok {
			bindings[i].publicKeyHexProblem = "missing"
		} else if string(value) == "null" {
			bindings[i].publicKeyHexProblem = "null, not a string"
		}
	}
}

// repeatedMember returns the first member name, in document order, that a
// JSON object in raw writes twice, and whether there is one. The member is
// named object.member and array[index], and a top-level member with an empty
// label by its bare name, as in verifierState.agentBindings[0].agentDid.
// Names are compared after JSON unescaping, in which encoding/json decodes
// an unpaired surrogate escape such as \ud800 to U+FFFD (the Python
// verifier's _UNPAIRED_SURROGATE), and never folded, so VerifierState does
// not repeat verifierState. The value of a member whose path is in skip is
// not walked. raw is valid JSON.
func repeatedMember(label string, raw []byte, skip map[string]bool) (string, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	// Without UseNumber, Token stops with an error at a number such as 1e400
	// that does not fit a float64, and a repeat after it would go unseen.
	dec.UseNumber()
	w := memberWalk{dec: dec, skip: skip, label: label}
	for path := range skip {
		w.longest = max(w.longest, len(path))
	}
	member, found, _ := w.walk(w.cut(label))
	return member, found
}

// memberWalk is the state of one repeatedMember walk. A path grows with its
// nesting depth, so the walk keeps the path of the value it reads as the
// label and one segment for each array or object around that value, and
// writes a whole path out only for the member it returns.
type memberWalk struct {
	dec      *json.Decoder
	skip     map[string]bool
	longest  int // the length of the longest path in skip
	label    string
	segments []pathSegment
}

// pathSegment is the member name or the array index of a value in the object
// or array that holds it.
type pathSegment struct {
	name  string
	index int // -1 for a member name
}

// appendTo appends to path, the path of the object or array that holds s,
// what s adds to it: [index], or .name, or the bare name when path is empty.
func (s pathSegment) appendTo(path []byte) []byte {
	switch {
	case s.index >= 0:
		path = append(path, '[')
		path = strconv.AppendInt(path, int64(s.index), 10)
		return append(path, ']')
	case len(path) > 0:
		path = append(path, '.')
	}
	return append(path, s.name...)
}

// path returns the path of the member at last in the object the walk is
// reading.
func (w *memberWalk) path(last pathSegment) string {
	b := []byte(w.label)
	for _, s := range w.segments {
		b = s.appendTo(b)
	}
	return string(last.appendTo(b))
}

// cut returns path cut to one byte more than the longest path in skip, which
// is enough to tell whether path is empty and whether skip holds it.
func (w *memberWalk) cut(path string) string {
	if len(path) > w.longest+1 {
		return path[:w.longest+1]
	}
	return path
}

// headAt returns the cut path of the value at s in the object or array whose
// cut path is head.
func (w *memberWalk) headAt(head string, s pathSegment) string {
	if len(head) > w.longest {
		return head
	}
	return w.cut(string(s.appendTo([]byte(head))))
}

// walk reads the next JSON value from dec and returns the first repeated
// member in it, and whether there is one. head is the value's cut path.
func (w *memberWalk) walk(head string) (string, bool, error) {
	tok, err := w.dec.Token()
	if err != nil {
		return "", false, err
	}
	switch tok {
	case json.Delim('{'):
		seen := map[string]bool{}
		for w.dec.More() {
			if tok, err = w.dec.Token(); err != nil {
				return "", false, err
			}
			name, _ := tok.(string)
			s := pathSegment{name: name, index: -1}
			if seen[name] {
				return w.path(s), true, nil
			}
			seen[name] = true
			if memberHead := w.headAt(head, s); w.skip[memberHead] {
				var value json.RawMessage
				err = w.dec.Decode(&value)
			} else {
				var member string
				var found bool
				if member, found, err = w.walkAt(memberHead, s); found {
					return member, true, nil
				}
			}
			if err != nil {
				return "", false, err
			}
		}
	case json.Delim('['):
		for i := 0; w.dec.More(); i++ {
			s := pathSegment{index: i}
			if member, found, err := w.walkAt(w.headAt(head, s), s); found || err != nil {
				return member, found, err
			}
		}
	default:
		return "", false, nil
	}
	_, err = w.dec.Token() // the closing } or ]
	return "", false, err
}

// walkAt walks the value at s, whose cut path is head.
func (w *memberWalk) walkAt(head string, s pathSegment) (string, bool, error) {
	w.segments = append(w.segments, s)
	member, found, err := w.walk(head)
	w.segments = w.segments[:len(w.segments)-1]
	return member, found, err
}

// exactMembers returns raw with each member of an object that decodes into a
// struct left out unless its name is exactly the JSON name of one of the
// struct's fields, walking raw along the decode target t (pointers, struct
// fields, slice elements). encoding/json matches a member name to a field
// case-insensitively, so on its own it decodes VerifierState as
// verifierState; the Python verifier reads each member by its exact name, so
// in both verifiers such a member is not the fixture member, which is then
// absent. The value of challengeResponse (protocolMessagesType) is returned
// as written. The members kept stay in document order. A value that is not
// the JSON type t needs is returned unchanged, for the decode to reject.
func exactMembers(raw json.RawMessage, t reflect.Type) json.RawMessage {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == protocolMessagesType {
		return raw
	}
	switch t.Kind() {
	case reflect.Struct:
		members, ok := objectMembers(raw)
		if !ok {
			return raw
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			if name, decoded := memberName(t.Field(i)); decoded {
				fields[name] = t.Field(i).Type
			}
		}
		var kept []objectMember
		for _, m := range members {
			if ft, ok := fields[m.name]; ok {
				kept = append(kept, objectMember{m.name, exactMembers(m.value, ft)})
			}
		}
		return encodeObject(kept)
	case reflect.Slice:
		elems, ok := arrayElements(raw)
		if !ok {
			return raw
		}
		out := []byte{'['}
		for i, elem := range elems {
			if i > 0 {
				out = append(out, ',')
			}
			out = append(out, exactMembers(elem, t.Elem())...)
		}
		return append(out, ']')
	}
	return raw
}

// memberName is the JSON member name encoding/json decodes into field, and
// whether it decodes into field at all.
func memberName(field reflect.StructField) (string, bool) {
	name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
	if name == "" {
		name = field.Name
	}
	return name, field.IsExported() && name != "-"
}

// objectMember is one member of a JSON object: its name and its raw value.
type objectMember struct {
	name  string
	value json.RawMessage
}

// objectMembers returns the members of raw in document order when raw is a
// JSON object.
func objectMembers(raw json.RawMessage) ([]objectMember, bool) {
	if !json.Valid(raw) {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, false
	}
	var members []objectMember
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, false
		}
		name, _ := tok.(string)
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, false
		}
		members = append(members, objectMember{name, value})
	}
	return members, true
}

// encodeObject writes members as a JSON object, in order.
func encodeObject(members []objectMember) json.RawMessage {
	out := []byte{'{'}
	for i, m := range members {
		if i > 0 {
			out = append(out, ',')
		}
		name, _ := json.Marshal(m.name)
		out = append(out, name...)
		out = append(out, ':')
		out = append(out, m.value...)
	}
	return append(out, '}')
}

// arrayElements returns the elements of raw when it is a JSON array.
func arrayElements(raw json.RawMessage) ([]json.RawMessage, bool) {
	var elems []json.RawMessage
	if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 || trimmed[0] != '[' || json.Unmarshal(raw, &elems) != nil {
		return nil, false
	}
	return elems, true
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
	fixtureError   string // set in place of a verdict: "<member>: <problem>"
}

// verifyChallengeResponse applies the AIP §5.1 step-5 checks in order:
//
//  1. Signature valid for challenge + publicKey (cryptographic check)
//  2. publicKey matches the agentDid's bound key in verifierState.agentBindings
//  3. Challenge not expired (verifier clock < expiresAt)
//  4. Nonce not in verifierState.seenNonces
//
// The first failing check wins; subsequent checks are not performed. When the
// agentBindings entry check 2 reads has no publicKeyHex, or a null one, the
// result is a fixtureError naming that member instead of a verdict.
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
	bound, entry, found := lookupAgentBinding(vs, cr.Response.AgentDID)
	if !found {
		return result{
			verdict:        "REJECT",
			rejectCategory: "UNTRUSTED_KEY",
			reason:         fmt.Sprintf("response.agentDid %s has no agentBinding in verifierState", cr.Response.AgentDID),
		}
	}
	if bound.publicKeyHexProblem != "" {
		return result{fixtureError: entry + ".publicKeyHex: " + bound.publicKeyHexProblem}
	}
	boundPubHex := hex.EncodeToString(pubBytes)
	if boundPubHex != bound.PublicKeyHex {
		return result{
			verdict:        "REJECT",
			rejectCategory: "UNTRUSTED_KEY",
			reason:         fmt.Sprintf("response.publicKey does not match bound key for agentDid %s (got %s..., bound is %s...)", cr.Response.AgentDID, quotedKey(boundPubHex), quotedKey(bound.PublicKeyHex)),
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

// quotedKey is the part of a key the UNTRUSTED_KEY reason quotes: its first
// 16 bytes, or the whole key when it is shorter, such as a bound publicKeyHex
// of "abc" or "".
func quotedKey(key string) string {
	if len(key) > 16 {
		return key[:16]
	}
	return key
}

// lookupAgentBinding returns the first verifierState.agentBindings entry whose
// agentDid is agentDID, and the member name of that entry, as in
// verifierState.agentBindings[0].
func lookupAgentBinding(vs VerifierState, agentDID string) (AgentBinding, string, bool) {
	for i, b := range vs.AgentBindings {
		if b.AgentDID == agentDID {
			return b, fmt.Sprintf("verifierState.agentBindings[%d]", i), true
		}
	}
	return AgentBinding{}, "", false
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
	f, err := parseFixture(b)
	if err != nil {
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
	if r.fixtureError != "" {
		fmt.Fprintf(w, "FAIL  %s\n       fixture error: %s\n", path, r.fixtureError)
		return false
	}
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
