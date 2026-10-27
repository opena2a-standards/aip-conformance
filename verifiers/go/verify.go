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
// A fixture's members are read under their exact names (VerifierState is not
// verifierState). Outside the two §5.1 bodies (challengeResponse.challenge
// and challengeResponse.response) a fixture that writes one member name
// twice in the same JSON object fails to load on both verifiers, which
// counts as a fail (exit code 1). Inside them, before check 1, a JSON object
// that writes one member name twice, or a body member whose name AIP §5.1.1
// or §5.1.2 does not give that body, is REJECT [PARSE_ERROR]
// (memberNameDefect).
//
// A challengeResponse fixture whose verifierState is missing or is not an
// object, a fixture of another fixtureType whose verifierState is neither an
// object nor null, and a fixture of any fixtureType whose verifierState is an
// object holding an agentBindings, seenNonces or trustedIssuers that is not an
// array or null, an agentBindings entry that is not an object, an
// agentBindings entry whose agentDid, algorithm or publicKeyHex is missing or
// is not a string, a clockRfc3339 that is not a string, or a seenNonces or
// trustedIssuers entry that is not a non-empty string, null included, prints
// a FAIL block before any check runs, with the line the Python verifier
// prints for it:
//
//	FAIL  <path>
//	       fixture error: verifierState.seenNonces: a number, not an array
//
// So does a challengeResponse fixture whose verifierState writes no
// clockRfc3339. The line names the first member or entry the rule refuses,
// as in
//
//	fixture error: verifierState.agentBindings[0].agentDid: missing
//	fixture error: verifierState.clockRfc3339: a number, not a string
//	fixture error: verifierState.trustedIssuers[1]: a number, not a string
//	fixture error: verifierState.seenNonces[0]: an empty string
//
// A challengeResponse fixture whose verifierState.clockRfc3339 is a string
// parseRFC3339 does not read prints that FAIL block when the expiry check
// reads it, after the signature and bound-key checks pass, as in
//
//	fixture error: verifierState.clockRfc3339: cannot be read as a date-time ("2026-05-28T00:00:00" has no UTC offset)
//
// Each counts as a fail, and the run goes on to the next fixture and prints
// the summary line.
//
// Canonical signing form (5 fields, pipe-delimited) — MUST mirror
// scripts/generate-fixtures/main.go canonicalChallengeResponsePayload
// VERBATIM:
//
//	challenge | agentDid | nonce | issuedAt | expiresAt
//
// A timestamp is read as a date-time in the RFC 3339 form rfc3339DateTime
// matches, the form the Python verifier reads: issuedAt and expiresAt go
// into the payload as that time in UTC, written YYYY-MM-DDThh:mm:ssZ
// (normalizeRFC3339), and a value not in that form goes in as written.
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
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

// AgentBinding is a verifierState.agentBindings entry. checkVerifierState
// refuses, before the decode, an entry that is not an object or whose
// agentDid, algorithm or publicKeyHex is missing or is not a string, so each
// field holds the member as written.
type AgentBinding struct {
	AgentDID     string `json:"agentDid"`
	Algorithm    string `json:"algorithm"`
	PublicKeyHex string `json:"publicKeyHex"`
}

// VerifierState is a fixture's verifierState. checkVerifierState refuses,
// before the decode, a clockRfc3339 that is not a string, and a
// challengeResponse fixture that writes none, so ClockRFC3339 holds the
// member as written for the checks; a missing or null array member decodes
// as the empty slice.
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

// protocolMessages names the fixture members that hold the protocol messages
// under test: the two §5.1 bodies inside challengeResponse, each by the
// member names on its path from the top-level object. parseFixture does not
// walk their values for repeated member names: inside a body a name written
// twice is a verdict, which memberNameDefect gives before check 1, not a
// load error. challengeResponse itself is fixture format, read like the rest
// of the fixture. The Python verifier's _PROTOCOL_MESSAGES holds the same
// paths.
var protocolMessages = [][]string{{"challengeResponse", "challenge"}, {"challengeResponse", "response"}}

// parseFixture decodes a fixture file. A JSON object outside the two §5.1
// bodies that writes one member name twice is a load error: the verifier
// state, expected outcome or body it carries has no single reading, and
// encoding/json would decode both copies into one struct, keeping a member
// the later copy omits, where the Python verifier reads the later copy
// alone. Each member, inside the two bodies too, is read under its exact
// name (exactMembers). A file that is not JSON fails with the error json.Unmarshal
// reports for it. A challengeResponse fixture whose verifierState is missing
// or is not an object is a *memberError, and so is a fixture of another
// fixtureType whose verifierState is neither an object nor null, and a
// verifierState member or entry that checkVerifierState refuses: an
// agentBindings, seenNonces or trustedIssuers that is not an array or null,
// an entry of one that is not of the type verifierStateArrays gives it, an
// agentBindings entry whose agentDid, algorithm or publicKeyHex is missing or
// is not a string, and a clockRfc3339 that is not a string, or that a
// challengeResponse fixture does not write.
func parseFixture(b []byte) (Fixture, error) {
	var f Fixture
	if json.Valid(b) {
		if member, ok := repeatedMember("", b, protocolMessages); ok {
			return f, fmt.Errorf("%s: duplicate member name", member)
		}
		b = exactMembers(b, reflect.TypeOf(f))
		if err := checkVerifierState(b); err != nil {
			return f, err
		}
	}
	err := json.Unmarshal(b, &f)
	return f, err
}

// memberError is a fixture member that holds a value the verifier cannot
// use. runFixture prints it as a fixture error, the line the Python
// verifier's FixtureError prints for the same member.
type memberError struct {
	member, problem string
}

func (e *memberError) Error() string { return e.member + ": " + e.problem }

// verifierStateArrays names the verifierState members that hold an array,
// each with the JSON type of its entries; a string entry must also not be
// empty, and an object entry's agentBindingMembers are strings. The Python
// verifier's _VERIFIER_STATE_ARRAYS holds the same names with the same entry
// types.
var verifierStateArrays = map[string]string{
	"agentBindings":  "an object",
	"seenNonces":     "a string",
	"trustedIssuers": "a string",
}

// agentBindingMembers names the members of a verifierState.agentBindings
// entry, each a string, in the order checkArrayMember checks them. The
// Python verifier's _AGENT_BINDING_MEMBERS holds the same names in the same
// order.
var agentBindingMembers = []string{"agentDid", "algorithm", "publicKeyHex"}

// checkVerifierState returns a *memberError naming the verifierState of a
// challengeResponse fixture in raw when raw writes none or writes one that is
// not an object, such as null or [], and the verifierState of a fixture of
// another fixtureType when raw writes one that is neither an object nor null,
// such as 0 or [], which encoding/json would fail to decode into a
// VerifierState. Otherwise it names the first member or entry of the
// verifierState object that the load rule refuses, checking the members in
// the order of their names: agentBindings (checkArrayMember), then
// clockRfc3339, which must be a string when it is written, and written in a
// challengeResponse fixture (stringMember), then seenNonces and
// trustedIssuers (checkArrayMember). Each value and entry is read from raw:
// encoding/json decodes a null entry into the empty string or the zero
// AgentBinding, a missing or null member into the zero value and an empty
// string as written, with no error, and fails on a value of another type
// with a line of its own. It returns nil when there is none, or when raw is
// not an object, which the decode reports.
func checkVerifierState(raw []byte) error {
	var doc map[string]json.RawMessage
	if json.Unmarshal(raw, &doc) != nil {
		return nil
	}
	state, written := doc["verifierState"]
	var fixtureType string
	challengeResponse := json.Unmarshal(doc["fixtureType"], &fixtureType) == nil && fixtureType == "challengeResponse"
	if challengeResponse && !written {
		return &memberError{"verifierState", "missing"}
	}
	if written {
		if kind := jsonType(state); kind != "an object" && (challengeResponse || kind != "null") {
			return &memberError{"verifierState", kind + ", not an object"}
		}
	}
	var vs map[string]json.RawMessage
	if json.Unmarshal(state, &vs) != nil {
		return nil
	}
	if err := checkArrayMember(vs, "agentBindings"); err != nil {
		return err
	}
	if _, ok := vs["clockRfc3339"]; ok || challengeResponse {
		if err := stringMember(vs, "verifierState", "clockRfc3339"); err != nil {
			return err
		}
	}
	if err := checkArrayMember(vs, "seenNonces"); err != nil {
		return err
	}
	return checkArrayMember(vs, "trustedIssuers")
}

// checkArrayMember returns a *memberError naming verifierState.name when the
// verifierState object vs holds a value there that is not an array or null,
// such as 0, false, "" or {}; otherwise naming the first entry of the array
// that is not of the verifierStateArrays entry type, null included, or is
// the empty string, as in verifierState.seenNonces[1]; otherwise naming the
// first agentBindingMembers member of an agentBindings entry that is missing
// or is not a string, as in verifierState.agentBindings[0].agentDid, the
// members of each entry checked before the next entry. A missing or null
// member holds no entry. It returns nil when there is none.
func checkArrayMember(vs map[string]json.RawMessage, name string) error {
	value, ok := vs[name]
	if !ok {
		return nil
	}
	if kind := jsonType(value); kind != "an array" && kind != "null" {
		return &memberError{"verifierState." + name, kind + ", not an array"}
	}
	entries, _ := arrayElements(value)
	for i, entry := range entries {
		member := fmt.Sprintf("verifierState.%s[%d]", name, i)
		if kind := jsonType(entry); kind != verifierStateArrays[name] {
			return &memberError{member, kind + ", not " + verifierStateArrays[name]}
		}
		if string(bytes.TrimSpace(entry)) == `""` {
			return &memberError{member, "an empty string"}
		}
		if name == "agentBindings" {
			var binding map[string]json.RawMessage
			if err := json.Unmarshal(entry, &binding); err != nil {
				return err
			}
			for _, field := range agentBindingMembers {
				if err := stringMember(binding, member, field); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// stringMember returns a *memberError naming label.name when the JSON object
// members writes no member name, or writes one that is not a string, null
// included, as in verifierState.agentBindings[0].agentDid: missing. It
// returns nil when the member is a string.
func stringMember(members map[string]json.RawMessage, label, name string) error {
	value, ok := members[name]
	if !ok {
		return &memberError{label + "." + name, "missing"}
	}
	if kind := jsonType(value); kind != "a string" {
		return &memberError{label + "." + name, kind + ", not a string"}
	}
	return nil
}

// jsonType names the JSON type of the valid JSON value raw as the Python
// verifier's _json_type names it.
func jsonType(raw json.RawMessage) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return "a number"
	}
	switch trimmed[0] {
	case 'n':
		return "null"
	case 't', 'f':
		return "a boolean"
	case '"':
		return "a string"
	case '[':
		return "an array"
	case '{':
		return "an object"
	}
	return "a number"
}

// repeatedMember returns the first member name, in document order, that a
// JSON object in raw writes twice, and whether there is one. The member is
// named object.member and array[index], and a top-level member with an empty
// label by its bare name, as in verifierState.agentBindings[0].agentDid.
// Names are compared after JSON unescaping, in which encoding/json decodes
// an unpaired surrogate escape such as \ud800 to U+FFFD (the Python
// verifier's _UNPAIRED_SURROGATE), and never folded, so VerifierState does
// not repeat verifierState. The value at a path in skip, the member names
// that lead to it from the top-level value of raw, is not walked. A skip path
// is compared name by name, not as the joined path, so a top-level member
// named challengeResponse.challenge is walked. raw is valid JSON, and each
// path in skip holds at least one name.
func repeatedMember(label string, raw []byte, skip [][]string) (string, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	// Without UseNumber, Token stops with an error at a number such as 1e400
	// that does not fit a float64, and a repeat after it would go unseen.
	dec.UseNumber()
	w := memberWalk{dec: dec, label: label}
	member, found, _ := w.walk(skip)
	return member, found
}

// memberWalk is the state of one repeatedMember walk. A path grows with its
// nesting depth, so the walk keeps the path of the value it reads as the
// label and one segment for each array or object around that value, and
// writes a whole path out only for the member it returns.
type memberWalk struct {
	dec      *json.Decoder
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

// skipRest returns the rest of each path in skip that begins with the member
// name, and whether one of them is that name alone, in which case the walk
// does not read the member's value.
func skipRest(skip [][]string, name string) ([][]string, bool) {
	var rest [][]string
	for _, path := range skip {
		if path[0] != name {
			continue
		}
		if len(path) == 1 {
			return nil, true
		}
		rest = append(rest, path[1:])
	}
	return rest, false
}

// walk reads the next JSON value from dec and returns the first repeated
// member in it, and whether there is one. skip holds the rest of each skip
// path that begins with the member names leading to the value.
func (w *memberWalk) walk(skip [][]string) (string, bool, error) {
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
			if rest, skipped := skipRest(skip, name); skipped {
				var value json.RawMessage
				err = w.dec.Decode(&value)
			} else {
				var member string
				var found bool
				if member, found, err = w.walkAt(rest, s); found {
					return member, true, nil
				}
			}
			if err != nil {
				return "", false, err
			}
		}
	case json.Delim('['):
		// A skip path names members only, so it leads to no element.
		for i := 0; w.dec.More(); i++ {
			if member, found, err := w.walkAt(nil, pathSegment{index: i}); found || err != nil {
				return member, found, err
			}
		}
	default:
		return "", false, nil
	}
	_, err = w.dec.Token() // the closing } or ]
	return "", false, err
}

// walkAt walks the value at s, with skip the rest of each skip path that
// begins with the member names leading to it.
func (w *memberWalk) walkAt(skip [][]string, s pathSegment) (string, bool, error) {
	w.segments = append(w.segments, s)
	member, found, err := w.walk(skip)
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
// absent. Inside the two §5.1 bodies such a member is also a name the body's
// section does not give it, which memberNameDefect rejects before check 1.
// The members kept stay in document order. A value that is not the JSON type
// t needs is returned unchanged, for the decode to reject.
func exactMembers(raw json.RawMessage, t reflect.Type) json.RawMessage {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
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
// member names of the two §5.1 bodies (MUST match the Python verifier)
// ---------------------------------------------------------------------------

// protocolMessageBodies are the two §5.1 bodies in the order the member-name
// rule reads them, each with the name a reason gives it, its protocolMessages
// path and the member names its section gives it: AIP §5.1.1 for the
// challenge body and §5.1.2 for the response body, the JSON names of
// ChallengeBody's and ResponseBody's fields. The Python verifier's
// _PROTOCOL_MESSAGE_BODIES holds the same bodies in the same order, with the
// same names.
var protocolMessageBodies = []struct {
	name    string
	path    []string
	members map[string]bool
}{
	{"challenge", protocolMessages[0], fieldNames(reflect.TypeOf(ChallengeBody{}))},
	{"response", protocolMessages[1], fieldNames(reflect.TypeOf(ResponseBody{}))},
}

// fieldNames is the set of member names encoding/json decodes into the
// fields of the struct type t.
func fieldNames(t reflect.Type) map[string]bool {
	names := map[string]bool{}
	for i := 0; i < t.NumField(); i++ {
		if name, decoded := memberName(t.Field(i)); decoded {
			names[name] = true
		}
	}
	return names
}

// memberNameDefect applies the AIP §5.1.4 rule on the member names of the
// two §5.1 bodies in the fixture text raw, which runs before check 1. First
// the duplicate test: no JSON object in the challenge body, then in the
// response body, writes one member name twice (repeatedBodyMember). Then the
// defined-name test: each member of the challenge body, then of the response
// body, read in document order, has a name that the body's section gives it
// (protocolMessageBodies). Names are compared code point for code point after
// JSON escapes are resolved, never folded. The first defect decides: it
// returns the REJECT [PARSE_ERROR] result naming it, and whether there is
// one. A body that is missing or is not a JSON object holds no member name
// to test. The Python verifier's _member_name_defect returns the same result.
func memberNameDefect(raw []byte) (result, bool) {
	bodies := make([]json.RawMessage, len(protocolMessageBodies))
	for i, body := range protocolMessageBodies {
		if value, ok := memberAt(raw, body.path); ok && jsonType(value) == "an object" {
			bodies[i] = value
		}
	}
	for i, body := range protocolMessageBodies {
		if name, ok := repeatedBodyMember(bodies[i]); ok {
			return memberNameResult(body.name, "duplicate", name), true
		}
	}
	for i, body := range protocolMessageBodies {
		members, _ := objectMembers(bodies[i])
		for _, m := range members {
			if !body.members[m.name] {
				return memberNameResult(body.name, "undefined", m.name), true
			}
		}
	}
	return result{}, false
}

// memberNameResult is the REJECT [PARSE_ERROR] result for the member name of
// body that the member-name rule refuses as defect, "duplicate" or
// "undefined". The reason writes the name as strconv.QuoteToASCII writes it.
func memberNameResult(body, defect, name string) result {
	return result{
		verdict:        "REJECT",
		rejectCategory: "PARSE_ERROR",
		reason:         fmt.Sprintf("%s contains %s member %s (member names are compared exactly, after JSON escapes are resolved)", body, defect, strconv.QuoteToASCII(name)),
	}
}

// memberAt returns the value at path, the member names that lead to it from
// the top-level object of the JSON text raw, each read under its exact name,
// and whether there is one.
func memberAt(raw []byte, path []string) (json.RawMessage, bool) {
	value := json.RawMessage(raw)
	for _, name := range path {
		members, ok := objectMembers(value)
		if !ok {
			return nil, false
		}
		found := false
		for _, m := range members {
			if m.name == name {
				value, found = m.value, true
				break
			}
		}
		if !found {
			return nil, false
		}
	}
	return value, true
}

// repeatedBodyMember returns the member name the duplicate test names in the
// §5.1 body raw, and whether there is one: of the JSON objects in raw that
// write a member name twice, the one that opens first in the text, and in it
// the name whose second occurrence comes first. Names are compared after
// JSON unescaping, in which encoding/json decodes an unpaired surrogate
// escape to U+FFFD, and never folded. The Python verifier's
// _repeated_body_member names the same member.
func repeatedBodyMember(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	// Without UseNumber, Token stops with an error at a number such as 1e400
	// that does not fit a float64, and a repeat after it would go unseen.
	dec.UseNumber()
	w := bodyWalk{dec: dec, first: -1}
	if w.walk() != nil {
		return "", false
	}
	return w.name, w.first >= 0
}

// bodyWalk is the state of one repeatedBodyMember walk: the number of
// objects opened so far, and the open index and repeated name of the object
// that opens first of those found to write a name twice (first is -1 while
// there is none).
type bodyWalk struct {
	dec    *json.Decoder
	opened int
	first  int
	name   string
}

// walk reads the next JSON value from dec. An object's repeat is recorded
// when the object closes, after the objects nested in it, so the comparison
// of open indexes decides which object is named.
func (w *bodyWalk) walk() error {
	tok, err := w.dec.Token()
	if err != nil {
		return err
	}
	switch tok {
	case json.Delim('{'):
		index := w.opened
		w.opened++
		seen := map[string]bool{}
		repeat, repeated := "", false
		for w.dec.More() {
			if tok, err = w.dec.Token(); err != nil {
				return err
			}
			name, _ := tok.(string)
			if seen[name] && !repeated {
				repeat, repeated = name, true
			}
			seen[name] = true
			if err = w.walk(); err != nil {
				return err
			}
		}
		if repeated && (w.first < 0 || index < w.first) {
			w.first, w.name = index, repeat
		}
	case json.Delim('['):
		for w.dec.More() {
			if err = w.walk(); err != nil {
				return err
			}
		}
	default:
		return nil
	}
	_, err = w.dec.Token() // the closing } or ]
	return err
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

// normalizeRFC3339 is s as parseRFC3339 reads it, in UTC and written
// YYYY-MM-DDThh:mm:ssZ without its fraction of a second, or s as written
// when parseRFC3339 does not read it. time.RFC3339 writes year -1, which an
// offset can make of year 0, as -0001, and year 10000 as 10000.
func normalizeRFC3339(s string) string {
	t, err := parseRFC3339(s)
	if err != nil {
		return s
	}
	return t.UTC().Format(time.RFC3339)
}

// rfc3339DateTime matches the RFC 3339 date-time form both verifiers read;
// the Python verifier's _RFC3339_DATE_TIME holds the same pattern. A
// four-digit year and two-digit month, day, hour, minute and second, an
// optional fraction of a second after a period, and Z or a UTC offset of
// the form +hh:mm or -hh:mm, with T and Z in upper case. time.Parse with
// the time.RFC3339 layout also reads forms outside RFC 3339, such as a
// one-digit hour, a comma before the fraction and an offset of +24:00
// (go.dev/issue/54580).
var rfc3339DateTime = regexp.MustCompile(`^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})` +
	`(?:\.([0-9]+))?(?:Z|([+-])([0-9]{2}):([0-9]{2}))$`)

// noUTCOffset matches a date alone, or a date and time with no UTC offset
// (the Python verifier's _NO_UTC_OFFSET).
var noUTCOffset = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}(?:T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?)?$`)

// parseRFC3339 reads s as a time, or returns an error when s is not an RFC
// 3339 date-time in the form rfc3339DateTime matches. The month, day (by
// the month and year), hour, minute, second and offset must be in range,
// which leaves out a second of 60, an hour of 24 and an offset hour of 24.
// The fraction is cut to nanoseconds. The Python verifier's _parse_rfc3339
// reads the same values as the same times, with the same messages, Python
// quoting the value as repr does.
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
//  1. Each of the five fields the response echoes (challenge, agentDid,
//     nonce, issuedAt, expiresAt) equals the challenge body's, compared as
//     written, and the signature is valid for the challenge body's canonical
//     payload under publicKey (cryptographic check)
//  2. publicKey matches the key bound to the challenge body's agentDid in
//     verifierState.agentBindings
//  3. Challenge not expired (verifier clock < challenge.expiresAt)
//  4. The challenge body's nonce is not in verifierState.seenNonces
//  5. The challenge body's issuerDid is in verifierState.trustedIssuers
//
// The first failing check wins; subsequent checks are not performed. When the
// verifierState.clockRfc3339 check 3 reads is a string parseRFC3339 does not
// read, the result is a fixtureError naming that member instead of a
// verdict; checkVerifierState refuses the other verifierState values the
// checks cannot use before the fixture reaches them. runFixture applies the
// rule on the bodies' member names (memberNameDefect) before check 1, so a
// transcript the checks read has each body member under a name its section
// gives the body, once.
func verifyChallengeResponse(cr *ChallengeResponse, vs VerifierState) result {
	// (1) The response echoes the challenge body, whose canonical payload the
	// signature covers, and the signature verifies
	echoes := []struct{ name, challenge, response string }{
		{"challenge", cr.Challenge.Challenge, cr.Response.Challenge},
		{"agentDid", cr.Challenge.AgentDID, cr.Response.AgentDID},
		{"nonce", cr.Challenge.Nonce, cr.Response.Nonce},
		{"issuedAt", cr.Challenge.IssuedAt, cr.Response.IssuedAt},
		{"expiresAt", cr.Challenge.ExpiresAt, cr.Response.ExpiresAt},
	}
	for _, e := range echoes {
		if e.response != e.challenge {
			return result{
				verdict:        "REJECT",
				rejectCategory: "SIGNATURE_INVALID",
				reason:         fmt.Sprintf("response.%s %s does not match challenge.%s %s", e.name, strconv.QuoteToASCII(e.response), e.name, strconv.QuoteToASCII(e.challenge)),
			}
		}
	}
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

	// (2) publicKey matches the key bound to challenge.agentDid
	bound, found := lookupAgentBinding(vs, cr.Challenge.AgentDID)
	if !found {
		return result{
			verdict:        "REJECT",
			rejectCategory: "UNTRUSTED_KEY",
			reason:         fmt.Sprintf("challenge.agentDid %s has no agentBinding in verifierState", strconv.QuoteToASCII(cr.Challenge.AgentDID)),
		}
	}
	boundPubHex := hex.EncodeToString(pubBytes)
	if boundPubHex != bound.PublicKeyHex {
		return result{
			verdict:        "REJECT",
			rejectCategory: "UNTRUSTED_KEY",
			reason:         fmt.Sprintf("response.publicKey does not match bound key for agentDid %s (got %s..., bound is %s...)", strconv.QuoteToASCII(cr.Challenge.AgentDID), quotedKey(boundPubHex), quotedKey(bound.PublicKeyHex)),
		}
	}

	// (3) Challenge not expired
	clock, err := parseRFC3339(vs.ClockRFC3339)
	if err != nil {
		return result{fixtureError: fmt.Sprintf("verifierState.clockRfc3339: cannot be read as a date-time (%v)", err)}
	}
	expiresAt, err := parseRFC3339(cr.Challenge.ExpiresAt)
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

	// (4) challenge.nonce not in seenNonces
	for _, seen := range vs.SeenNonces {
		if seen == cr.Challenge.Nonce {
			return result{
				verdict:        "REJECT",
				rejectCategory: "NONCE_REPLAY",
				reason:         "challenge.nonce was already seen by the verifier",
			}
		}
	}

	// (5) challenge.issuerDid is a trusted issuer
	if !trustedIssuer(vs, cr.Challenge.IssuerDID) {
		return result{
			verdict:        "REJECT",
			rejectCategory: "UNTRUSTED_ISSUER",
			reason:         fmt.Sprintf("challenge.issuerDid %s is not in verifierState.trustedIssuers", strconv.QuoteToASCII(cr.Challenge.IssuerDID)),
		}
	}

	return result{
		verdict:        "ACCEPT",
		signaturesNote: fmt.Sprintf("signature: ed25519=true (verified against agentDid %s bound key)", strconv.QuoteToASCII(cr.Challenge.AgentDID)),
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

func trustedIssuer(vs VerifierState, issuerDID string) bool {
	for _, trusted := range vs.TrustedIssuers {
		if trusted == issuerDID {
			return true
		}
	}
	return false
}

// lookupAgentBinding returns the first verifierState.agentBindings entry whose
// agentDid is agentDID, and whether there is one.
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
	f, err := parseFixture(b)
	var unusable *memberError
	if errors.As(err, &unusable) {
		fmt.Fprintf(w, "FAIL  %s\n       fixture error: %v\n", path, unusable)
		return false
	}
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

	r, refused := memberNameDefect(b)
	if !refused {
		r = verifyChallengeResponse(f.ChallengeResponse, f.VerifierState)
	}
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
