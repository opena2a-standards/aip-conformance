package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode"

	aipconformance "github.com/opena2a-standards/aip-conformance"
)

// publishedModule is the module path a user types. The README's first command
// is `go run <publishedModule>/verifiers/go@<publishedVersion>`, and the go
// command resolves that package only when go.mod declares this exact path:
// the GitHub repository is opena2a-standards/aip-conformance, so any other
// path makes the published entry point fail with "module declares its path
// as ...".
const publishedModule = "github.com/opena2a-standards/aip-conformance"

// publishedVersion is the module version the README's first command names:
// the tag of the suite version the README's status line declares
// (`**Status: vX.Y` is tag vX.Y.Z). The command names a version rather than
// @latest because the public module proxy answers @latest and @main on the
// verifiers/go path with the module that lived there before the entry point
// was published, whose go.mod declares another path, and the go command
// stops on that module before it tries the root module (measured 2026-10-18
// through proxy.golang.org; the command with a version named ran every
// fixture and exited 0).
const publishedVersion = "v0.3.0"

// statusVersion matches the suite version the README's status line declares,
// as scripts/conformance_profile.py reads it.
var statusVersion = regexp.MustCompile(`\*\*Status: (v\d+(?:\.\d+)+)`)

// semverTag matches a release tag of the form vX.Y.Z.
var semverTag = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

// checkoutFixtures is the repository's fixtures/ directory, the set both
// verifiers and CI walk; the test binary runs with verifiers/go as its
// working directory.
var checkoutFixtures = os.DirFS(filepath.Join("..", "..", "fixtures"))

// checkoutFixtureNames returns the sorted basenames of fixtures/*.json.
func checkoutFixtureNames(t *testing.T) []string {
	t.Helper()
	names, err := fs.Glob(checkoutFixtures, "*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(names) == 0 {
		t.Fatal("no *.json files under ../../fixtures")
	}
	sort.Strings(names)
	return names
}

func TestModulePathIsThePublishedImportPath(t *testing.T) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		t.Fatal("debug.ReadBuildInfo returned no build info")
	}
	if bi.Main.Path != publishedModule {
		t.Fatalf("main module path is %q, want %q so that `go run %s/verifiers/go@%s` resolves",
			bi.Main.Path, publishedModule, publishedModule, publishedVersion)
	}
}

// firstBashCommand returns the first line of the first ```bash block in text.
func firstBashCommand(text string) string {
	const fence = "```bash\n"
	i := strings.Index(text, fence)
	if i < 0 {
		return ""
	}
	rest := text[i+len(fence):]
	if j := strings.IndexByte(rest, '\n'); j >= 0 {
		rest = rest[:j]
	}
	return strings.TrimSpace(rest)
}

// TestReadmeFirstCommandIsThePublishedEntryPoint pins the README's first
// command to the published module path and version, and the version to a
// release tag within the suite version the README's status line declares,
// so the three move together.
func TestReadmeFirstCommandIsThePublishedEntryPoint(t *testing.T) {
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	want := "go run " + publishedModule + "/verifiers/go@" + publishedVersion
	if got := firstBashCommand(string(readme)); got != want {
		t.Fatalf("README's first command is %q, want %q", got, want)
	}
	if !semverTag.MatchString(publishedVersion) {
		t.Fatalf("publishedVersion %q is not a release tag vX.Y.Z", publishedVersion)
	}
	m := statusVersion.FindSubmatch(readme)
	if m == nil {
		t.Fatal("README has no `**Status: vX.Y` line to take the suite version from")
	}
	if status := string(m[1]); !strings.HasPrefix(publishedVersion, status+".") {
		t.Fatalf("the README's first command names %s; its status line declares %s, so the tag must be %s.<patch>",
			publishedVersion, status, status)
	}
}

func TestEmbeddedFixturesAreTheCheckoutFixtures(t *testing.T) {
	want := checkoutFixtureNames(t)
	entries, err := fs.ReadDir(aipconformance.Fixtures, embeddedFixtureDir)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(entries))
	for _, e := range entries {
		got = append(got, e.Name())
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("embedded fixtures %v, checkout fixtures %v", got, want)
	}
	for _, name := range want {
		disk, err := fs.ReadFile(checkoutFixtures, name)
		if err != nil {
			t.Fatal(err)
		}
		embedded, err := fs.ReadFile(aipconformance.Fixtures, embeddedFixtureDir+"/"+name)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(disk, embedded) {
			t.Errorf("%s: embedded bytes differ from the checkout", name)
		}
	}
}

func TestNoArgumentsVerifyTheEmbeddedFixtures(t *testing.T) {
	names := checkoutFixtureNames(t)
	var stdout, stderr bytes.Buffer
	if code := run(nil, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d, want 0\nstdout:\n%s\nstderr:\n%s", code, &stdout, &stderr)
	}
	out := stdout.String()
	first, _, _ := strings.Cut(out, "\n")
	wantFirst := fmt.Sprintf("fixtures: %d embedded in %s", len(names), publishedModule)
	if !strings.HasPrefix(first, wantFirst) {
		t.Errorf("first line %q, want prefix %q", first, wantFirst)
	}
	for _, name := range names {
		if !strings.Contains(out, "PASS  "+embeddedFixtureDir+"/"+name+"\n") {
			t.Errorf("no PASS line for embedded %s in:\n%s", name, out)
		}
	}
	summary := fmt.Sprintf("summary: %d pass, 0 fail (%d fixtures)", len(names), len(names))
	if !strings.Contains(out, summary) {
		t.Errorf("missing %q in:\n%s", summary, out)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr not empty:\n%s", &stderr)
	}
}

func TestDirectoryArgumentWalksDiskFixtures(t *testing.T) {
	names := checkoutFixtureNames(t)
	dir := filepath.Join("..", "..", "fixtures")
	var stdout, stderr bytes.Buffer
	if code := run([]string{dir}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d, want 0\nstdout:\n%s\nstderr:\n%s", code, &stdout, &stderr)
	}
	out := stdout.String()
	if strings.HasPrefix(out, "fixtures:") {
		t.Errorf("a run over disk fixtures printed the embedded-set header:\n%s", out)
	}
	for _, name := range names {
		if !strings.Contains(out, "PASS  "+filepath.Join(dir, name)+"\n") {
			t.Errorf("no PASS line for %s in:\n%s", name, out)
		}
	}
	summary := fmt.Sprintf("summary: %d pass, 0 fail (%d fixtures)", len(names), len(names))
	if !strings.Contains(out, summary) {
		t.Errorf("missing %q in:\n%s", summary, out)
	}
}

func TestDirectoryWithoutFixturesExitsTwo(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{t.TempDir()}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit %d, want 2 for a directory without fixtures\nstdout:\n%s", code, &stdout)
	}
	if !strings.Contains(stderr.String(), "no fixtures found") {
		t.Errorf("stderr %q, want it to say no fixtures found", &stderr)
	}
}

func TestFailingFixtureExitsOne(t *testing.T) {
	raw, err := fs.ReadFile(aipconformance.Fixtures, embeddedFixtureDir+"/challenge-response-valid.json")
	if err != nil {
		t.Fatal(err)
	}
	// The valid transcript is ACCEPTed; pinning REJECT as its expectation
	// makes the observed verdict contradict the fixture.
	flipped := strings.Replace(string(raw), `"verifyResult": "ACCEPT"`, `"verifyResult": "REJECT"`, 1)
	if flipped == string(raw) {
		t.Fatal("the valid fixture declares no ACCEPT expectation to flip")
	}
	path := filepath.Join(t.TempDir(), "flipped.json")
	if err := os.WriteFile(path, []byte(flipped), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{path}, &stdout, &stderr); code != 1 {
		t.Fatalf("exit %d, want 1 for a failing fixture\nstdout:\n%s", code, &stdout)
	}
	out := stdout.String()
	if !strings.Contains(out, "FAIL  "+path+"\n") {
		t.Errorf("no FAIL line for %s in:\n%s", path, out)
	}
	if !strings.Contains(out, "summary: 0 pass, 1 fail (1 fixtures)") {
		t.Errorf("missing failing summary in:\n%s", out)
	}
}

// memberText returns the one member name written in doc, as text: its quoted
// name, ": " and its value as written.
func memberText(t *testing.T, doc, name string) string {
	t.Helper()
	key := strconv.Quote(name) + ": "
	if n := strings.Count(doc, key); n != 1 {
		t.Fatalf("the fixture writes %s %d times, want once", key, n)
	}
	start := strings.Index(doc, key)
	dec := json.NewDecoder(strings.NewReader(doc[start+len(key):]))
	var value json.RawMessage
	if err := dec.Decode(&value); err != nil {
		t.Fatal(err)
	}
	return doc[start : start+len(key)+int(dec.InputOffset())]
}

// appendMember returns doc with member written as text after the last member
// of its top-level object.
func appendMember(t *testing.T, doc, member string) string {
	t.Helper()
	body, ok := strings.CutSuffix(doc, "\n}\n")
	if !ok {
		t.Fatal("the fixture does not end with the } of its top-level object")
	}
	return body + ",\n  " + member + "\n}\n"
}

// TestRepeatedWrapperMemberIsALoadError: a fixture that writes one member
// name twice in a JSON object outside challengeResponse fails to load,
// whatever the two copies hold, and counts as a fail with no verdict. The
// cases are built from the replay fixture, whose REJECT [NONCE_REPLAY] rests
// on verifierState.seenNonces. A member spelled in another case is another
// name: it repeats nothing and is not read as the member, so the verdict
// stays, as it does for the shipped fixture. ../python/test_verify.py builds
// the same cases and expects the same lines.
func TestRepeatedWrapperMemberIsALoadError(t *testing.T) {
	raw, err := fs.ReadFile(aipconformance.Fixtures, embeddedFixtureDir+"/challenge-response-replay.json")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	state := memberText(t, doc, "verifierState")
	seen := memberText(t, doc, "seenNonces")
	var members map[string]json.RawMessage
	if err := json.Unmarshal([]byte(strings.TrimPrefix(state, `"verifierState": `)), &members); err != nil {
		t.Fatal(err)
	}
	delete(members, "seenNonces")
	withoutSeen, err := json.Marshal(members)
	if err != nil {
		t.Fatal(err)
	}

	repeats := []struct{ name, doc, member string }{
		{"verifierState twice, the later copy without seenNonces", appendMember(t, doc, `"verifierState": `+string(withoutSeen)), "verifierState"},
		{"verifierState twice, both copies the same", appendMember(t, doc, state), "verifierState"},
		{"seenNonces twice in one verifierState", strings.Replace(doc, seen, seen+",\n    "+seen, 1), "verifierState.seenNonces"},
		{"the empty name twice in the top-level object", appendMember(t, appendMember(t, doc, `"": 1`), `"": 2`), ""},
		{"two unpaired surrogate escapes, each decoded to U+FFFD", appendMember(t, appendMember(t, doc, `"\ud800": 1`), `"\udbff": 2`), string(unicode.ReplacementChar)},
		// Nested past the Python interpreter's default recursion limit of
		// 1000, which the Python verifier's walk does not recurse into.
		{"a repeat nested 1100 arrays deep", appendMember(t, doc, `"note": `+strings.Repeat("[", 1100)+`{"a": 1, "a": 2}`+strings.Repeat("]", 1100)), "note" + strings.Repeat("[0]", 1100) + ".a"},
	}
	for _, tc := range repeats {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "fixture.json")
			if err := os.WriteFile(path, []byte(tc.doc), 0o600); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			code := run([]string{path}, &stdout, &stderr)
			want := "FAIL  " + path + "\n       parse error: " + tc.member + ": duplicate member name\n\nsummary: 0 pass, 1 fail (1 fixtures)\n"
			if code != 1 || stdout.String() != want || stderr.Len() != 0 {
				t.Errorf("exit %d, stdout:\n%s\nstderr:\n%s\nwant exit 1, stdout:\n%s", code, &stdout, &stderr, want)
			}
		})
	}

	verdicts := []struct{ name, doc string }{
		{"VerifierState after verifierState", appendMember(t, doc, `"VerifierState": {"seenNonces": []}`)},
		{"the shipped fixture", ""},
	}
	for _, tc := range verdicts {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join("..", "..", "fixtures", "challenge-response-replay.json")
			if tc.doc != "" {
				path = filepath.Join(t.TempDir(), "fixture.json")
				if err := os.WriteFile(path, []byte(tc.doc), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var stdout, stderr bytes.Buffer
			code := run([]string{path}, &stdout, &stderr)
			want := "PASS  " + path + "\n       expected: REJECT [NONCE_REPLAY]\n       observed: REJECT[NONCE_REPLAY: response.nonce was already seen by the verifier]\n\nsummary: 1 pass, 0 fail (1 fixtures)\n"
			if code != 0 || stdout.String() != want || stderr.Len() != 0 {
				t.Errorf("exit %d, stdout:\n%s\nstderr:\n%s\nwant exit 0, stdout:\n%s", code, &stdout, &stderr, want)
			}
		})
	}
}

// TestRepeatedMemberWalkAllocatesInProportionToTheDocument: the repeated-member
// walk writes out a whole path only for the member it returns, and allocates
// at most 256 bytes per document byte over the replay fixture with one more
// top-level member holding 9,999 nested empty arrays, or 9,999 nested arrays
// around 1,000,000 zeros. With the top-level object that is 10,000 levels;
// json.Valid rejects a document nested deeper, and parseFixture walks only a
// document json.Valid accepts. ../python/test_verify.py bounds the Python
// walk over the same nested arrays.
func TestRepeatedMemberWalkAllocatesInProportionToTheDocument(t *testing.T) {
	raw, err := fs.ReadFile(aipconformance.Fixtures, embeddedFixtureDir+"/challenge-response-replay.json")
	if err != nil {
		t.Fatal(err)
	}
	const depth = 9999
	cases := []struct{ name, extra string }{
		{"9,999 nested empty arrays", strings.Repeat("[", depth) + strings.Repeat("]", depth)},
		{"9,999 nested arrays around 1,000,000 zeros", strings.Repeat("[", depth) + strings.Repeat("0,", 999999) + "0" + strings.Repeat("]", depth)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := []byte(appendMember(t, string(raw), `"extra": `+tc.extra))
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			member, found := repeatedMember("", doc, protocolMessages)
			runtime.ReadMemStats(&after)
			if found {
				t.Fatalf("repeatedMember returned %q, want no repeated member", member)
			}
			// When this bound was set the walk allocated about 60 bytes per
			// document byte in each case (go1.26.3), and a walk that writes
			// out the path of every value allocated over 6,900.
			allocated := after.TotalAlloc - before.TotalAlloc
			if limit := uint64(256 * len(doc)); allocated > limit {
				t.Errorf("the walk allocated %d bytes over a %d-byte document, want at most %d (256 per byte)", allocated, len(doc), limit)
			}
		})
	}
}

// TestShortOrMissingBoundKeyFailsItsFixtureAndTheRunGoesOn: when the
// agentBindings entry for response.agentDid has no publicKeyHex, a null one,
// or a string shorter than 16 characters that is not the response key, the
// fixture prints one FAIL block, and the run goes on to the next fixture and
// prints the summary line. A missing or null publicKeyHex is a fixture error
// naming the member; a short string is quoted whole in the REJECT
// [UNTRUSTED_KEY] reason. The cases are built from the valid fixture, and
// each runs before a copy of it, whose PASS block follows unchanged. The
// checks do not read an entry for another agentDid, or any entry when the
// signature does not verify, so those cases keep their verdicts.
// ../python/verify.py prints the same lines for copies edited the same way.
func TestShortOrMissingBoundKeyFailsItsFixtureAndTheRunGoesOn(t *testing.T) {
	raw, err := fs.ReadFile(aipconformance.Fixtures, embeddedFixtureDir+"/challenge-response-valid.json")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	bindings := memberText(t, doc, "agentBindings")
	var entries []map[string]any
	if err := json.Unmarshal([]byte(strings.TrimPrefix(bindings, `"agentBindings": `)), &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("the valid fixture writes %d agentBindings entries, want 1", len(entries))
	}
	agent, _ := entries[0]["agentDid"].(string)
	// The valid fixture binds the response key, so the reason's "got" prefix
	// is the bound key's.
	key, _ := entries[0]["publicKeyHex"].(string)
	if len(key) < 16 {
		t.Fatalf("the valid fixture's bound key %q is shorter than 16 characters", key)
	}

	// withBindings returns doc with agentBindings holding the entries edit
	// returns, given a copy of the bound entry and a copy for another agentDid.
	withBindings := func(edit func(bound, other map[string]any) []map[string]any) string {
		t.Helper()
		other := maps.Clone(entries[0])
		other["agentDid"] = "did:opena2a:agent:not_bound"
		edited, err := json.Marshal(edit(maps.Clone(entries[0]), other))
		if err != nil {
			t.Fatal(err)
		}
		return strings.Replace(doc, bindings, `"agentBindings": `+string(edited), 1)
	}
	withKey := func(value any) string {
		return withBindings(func(bound, _ map[string]any) []map[string]any {
			bound["publicKeyHex"] = value
			return []map[string]any{bound}
		})
	}
	withoutKey := func(bound, _ map[string]any) []map[string]any {
		delete(bound, "publicKeyHex")
		return []map[string]any{bound}
	}
	replaced := func(text, from, to string) string {
		t.Helper()
		if !strings.Contains(text, from) {
			t.Fatalf("the fixture does not write %s", from)
		}
		return strings.Replace(text, from, to, 1)
	}
	// The challenge comes before the response in the fixture, so the first
	// issuedAt is the signed one.
	badSignature := replaced(replaced(withBindings(withoutKey),
		`"issuedAt": "2026-05-27T23:58:00Z"`, `"issuedAt": "2026-05-27T23:59:00Z"`),
		`"verifyResult": "ACCEPT"`, `"verifyResult": "REJECT", "rejectCategory": "SIGNATURE_INVALID"`)
	mismatch := func(quoted string) string {
		return "       expected: ACCEPT\n" +
			"       observed: REJECT[UNTRUSTED_KEY: response.publicKey does not match bound key for agentDid " + agent +
			" (got " + key[:16] + "..., bound is " + quoted + "...)]\n"
	}

	dir := t.TempDir()
	write := func(t *testing.T, name, text string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	// valid.json sorts after fixture.json, so each case runs before it.
	valid := write(t, "valid.json", doc)
	var stdout, stderr bytes.Buffer
	alone := "\nsummary: 1 pass, 0 fail (1 fixtures)\n"
	if code := run([]string{valid}, &stdout, &stderr); code != 0 || !strings.HasPrefix(stdout.String(), "PASS  "+valid+"\n") || !strings.HasSuffix(stdout.String(), alone) {
		t.Fatalf("the valid copy alone: exit %d, stdout:\n%s\nstderr:\n%s", code, &stdout, &stderr)
	}
	validBlock := strings.TrimSuffix(stdout.String(), alone)

	cases := []struct {
		name, doc string
		keeps     bool   // the case keeps its verdict and passes
		lines     string // the case's block after its PASS or FAIL line
	}{
		{"the bound entry with no publicKeyHex", withBindings(withoutKey), false,
			"       fixture error: verifierState.agentBindings[0].publicKeyHex: missing\n"},
		{"the bound entry's publicKeyHex null", withKey(nil), false,
			"       fixture error: verifierState.agentBindings[0].publicKeyHex: null, not a string\n"},
		{"the bound entry second, with no publicKeyHex", withBindings(func(bound, other map[string]any) []map[string]any {
			delete(bound, "publicKeyHex")
			return []map[string]any{other, bound}
		}), false, "       fixture error: verifierState.agentBindings[1].publicKeyHex: missing\n"},
		{"the bound entry's publicKeyHex abc", withKey("abc"), false, mismatch("abc")},
		{"the bound entry's publicKeyHex empty", withKey(""), false, mismatch("")},
		{"an entry for another agentDid with no publicKeyHex", withBindings(func(bound, other map[string]any) []map[string]any {
			delete(other, "publicKeyHex")
			return []map[string]any{other, bound}
		}), true, strings.TrimPrefix(validBlock, "PASS  "+valid+"\n")},
		{"a signature that does not verify, with no publicKeyHex", badSignature, true,
			"       expected: REJECT [SIGNATURE_INVALID]\n" +
				"       observed: REJECT[SIGNATURE_INVALID: Ed25519 signature did not verify against the canonical 5-field payload]\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := write(t, "fixture.json", tc.doc)
			gate, summary, wantCode := "FAIL", "summary: 1 pass, 1 fail (2 fixtures)", 1
			if tc.keeps {
				gate, summary, wantCode = "PASS", "summary: 2 pass, 0 fail (2 fixtures)", 0
			}
			var stdout, stderr bytes.Buffer
			code := run([]string{path, valid}, &stdout, &stderr)
			want := gate + "  " + path + "\n" + tc.lines + validBlock + "\n" + summary + "\n"
			if code != wantCode || stdout.String() != want || stderr.Len() != 0 {
				t.Errorf("exit %d, stdout:\n%s\nstderr:\n%s\nwant exit %d, stdout:\n%s", code, &stdout, &stderr, wantCode, want)
			}
		})
	}
}

// TestVerifierStateArrayOfAnotherTypeIsAFixtureError: a verifierState
// agentBindings or seenNonces that holds 0, false, "" or {} fails its fixture
// with a fixture error naming the member and the value's JSON type, before
// any check runs: under a signature that does not verify, and in a
// trustScoreComposition fixture, too. The cases are built from the replay
// fixture, whose REJECT [NONCE_REPLAY] rests on both members.
// ../python/test_verify.py builds the same cases and expects the same lines.
func TestVerifierStateArrayOfAnotherTypeIsAFixtureError(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		raw, err := fs.ReadFile(aipconformance.Fixtures, embeddedFixtureDir+"/"+name)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	replay := read("challenge-response-replay.json")
	replaced := func(text, from, to string) string {
		t.Helper()
		if !strings.Contains(text, from) {
			t.Fatalf("the fixture does not write %s", from)
		}
		return strings.Replace(text, from, to, 1)
	}
	// The challenge comes before the response in the fixture, so the first
	// issuedAt is the signed one.
	badSignature := replaced(replaced(replay,
		`"issuedAt": "2026-05-27T23:59:00Z"`, `"issuedAt": "2026-05-27T23:58:00Z"`),
		`"rejectCategory": "NONCE_REPLAY"`, `"rejectCategory": "SIGNATURE_INVALID"`)

	type testCase struct{ name, doc, line string }
	var cases []testCase
	for _, member := range []string{"agentBindings", "seenNonces"} {
		for _, v := range []struct{ value, kind string }{
			{"0", "a number"}, {"false", "a boolean"}, {`""`, "a string"}, {"{}", "an object"},
		} {
			cases = append(cases, testCase{
				member + " " + v.value,
				replaced(replay, memberText(t, replay, member), strconv.Quote(member)+": "+v.value),
				"fixture error: verifierState." + member + ": " + v.kind + ", not an array",
			})
		}
	}
	cases = append(cases,
		testCase{"seenNonces 0 under a signature that does not verify",
			replaced(badSignature, memberText(t, badSignature, "seenNonces"), `"seenNonces": 0`),
			"fixture error: verifierState.seenNonces: a number, not an array"},
		testCase{"agentBindings and seenNonces both 0",
			replaced(replaced(replay, memberText(t, replay, "seenNonces"), `"seenNonces": 0`),
				memberText(t, replay, "agentBindings"), `"agentBindings": 0`),
			"fixture error: verifierState.agentBindings: a number, not an array"},
		testCase{"seenNonces {} in a trustScoreComposition fixture",
			appendMember(t, read("trust-score-measured-six-factors-capped.json"), `"verifierState": {"seenNonces": {}}`),
			"fixture error: verifierState.seenNonces: an object, not an array"},
	)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "fixture.json")
			if err := os.WriteFile(path, []byte(tc.doc), 0o600); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			code := run([]string{path}, &stdout, &stderr)
			want := "FAIL  " + path + "\n       " + tc.line + "\n\nsummary: 0 pass, 1 fail (1 fixtures)\n"
			if code != 1 || stdout.String() != want || stderr.Len() != 0 {
				t.Errorf("exit %d, stdout:\n%s\nstderr:\n%s\nwant exit 1, stdout:\n%s", code, &stdout, &stderr, want)
			}
		})
	}
}

// TestUnreadableClockFailsItsFixtureAndTheRunGoesOn: a verifierState whose
// clockRfc3339 is missing, null, or a string the verifier does not read as
// a date-time is a fixture error naming the member, the line the Python
// verifier prints for the same file apart from the quotes around the value
// (%q here, repr there). The cases are built from the valid fixture, and
// each runs before a copy of it, whose PASS block follows unchanged. The
// checks do not read verifierState when the signature does not verify, so
// that case keeps its verdict.
func TestUnreadableClockFailsItsFixtureAndTheRunGoesOn(t *testing.T) {
	raw, err := fs.ReadFile(aipconformance.Fixtures, embeddedFixtureDir+"/challenge-response-valid.json")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	clock := memberText(t, doc, "clockRfc3339")
	withClock := func(member string) string { return strings.Replace(doc, clock, member, 1) }
	// The member and the line break and indentation after it.
	withoutClock := strings.Replace(doc, clock+",\n    ", "", 1)
	if withoutClock == doc {
		t.Fatal("the valid fixture does not write clockRfc3339 before another verifierState member")
	}
	badSignature := strings.Replace(strings.Replace(withClock(`"clockRfc3339": null`),
		`"issuedAt": "2026-05-27T23:58:00Z"`, `"issuedAt": "2026-05-27T23:59:00Z"`, 1),
		`"verifyResult": "ACCEPT"`, `"verifyResult": "REJECT", "rejectCategory": "SIGNATURE_INVALID"`, 1)
	form := "is not of the form YYYY-MM-DDThh:mm:ss[.fraction] followed by Z, +hh:mm or -hh:mm"

	dir := t.TempDir()
	write := func(t *testing.T, name, text string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	// valid.json sorts after fixture.json, so each case runs before it.
	valid := write(t, "valid.json", doc)
	var stdout, stderr bytes.Buffer
	alone := "\nsummary: 1 pass, 0 fail (1 fixtures)\n"
	if code := run([]string{valid}, &stdout, &stderr); code != 0 || !strings.HasPrefix(stdout.String(), "PASS  "+valid+"\n") || !strings.HasSuffix(stdout.String(), alone) {
		t.Fatalf("the valid copy alone: exit %d, stdout:\n%s\nstderr:\n%s", code, &stdout, &stderr)
	}
	validBlock := strings.TrimSuffix(stdout.String(), alone)

	cases := []struct{ name, doc, line string }{
		{"no clockRfc3339", withoutClock, "fixture error: verifierState.clockRfc3339: missing"},
		{"ClockRfc3339 in place of clockRfc3339", withClock(`"ClockRfc3339": "2026-05-28T00:00:00Z"`),
			"fixture error: verifierState.clockRfc3339: missing"},
		{"clockRfc3339 null", withClock(`"clockRfc3339": null`), "fixture error: verifierState.clockRfc3339: null, not a string"},
		{"clockRfc3339 with no UTC offset", withClock(`"clockRfc3339": "2026-05-28T00:00:00"`),
			`fixture error: verifierState.clockRfc3339: cannot be read as a date-time ("2026-05-28T00:00:00" has no UTC offset)`},
		{"clockRfc3339 a date alone", withClock(`"clockRfc3339": "2026-05-28"`),
			`fixture error: verifierState.clockRfc3339: cannot be read as a date-time ("2026-05-28" has no UTC offset)`},
		{"clockRfc3339 tomorrow", withClock(`"clockRfc3339": "tomorrow"`),
			`fixture error: verifierState.clockRfc3339: cannot be read as a date-time ("tomorrow" ` + form + `)`},
		{"clockRfc3339 empty", withClock(`"clockRfc3339": ""`),
			`fixture error: verifierState.clockRfc3339: cannot be read as a date-time ("" ` + form + `)`},
		{"clockRfc3339 with a one-digit hour", withClock(`"clockRfc3339": "2026-05-28T0:00:00Z"`),
			`fixture error: verifierState.clockRfc3339: cannot be read as a date-time ("2026-05-28T0:00:00Z" ` + form + `)`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := write(t, "fixture.json", tc.doc)
			var stdout, stderr bytes.Buffer
			code := run([]string{path, valid}, &stdout, &stderr)
			want := "FAIL  " + path + "\n       " + tc.line + "\n" + validBlock + "\nsummary: 1 pass, 1 fail (2 fixtures)\n"
			if code != 1 || stdout.String() != want || stderr.Len() != 0 {
				t.Errorf("exit %d, stdout:\n%s\nstderr:\n%s\nwant exit 1, stdout:\n%s", code, &stdout, &stderr, want)
			}
		})
	}
	t.Run("a signature that does not verify, with clockRfc3339 null", func(t *testing.T) {
		path := write(t, "fixture.json", badSignature)
		var stdout, stderr bytes.Buffer
		code := run([]string{path}, &stdout, &stderr)
		want := "PASS  " + path + "\n       expected: REJECT [SIGNATURE_INVALID]\n" +
			"       observed: REJECT[SIGNATURE_INVALID: Ed25519 signature did not verify against the canonical 5-field payload]\n" +
			"\nsummary: 1 pass, 0 fail (1 fixtures)\n"
		if code != 0 || stdout.String() != want || stderr.Len() != 0 {
			t.Errorf("exit %d, stdout:\n%s\nstderr:\n%s\nwant exit 0, stdout:\n%s", code, &stdout, &stderr, want)
		}
	})
}

// readTimestamps are timestamps both verifiers read: the value, the UTC form
// the verifier puts in the signed payload, and whether the time is after the
// valid fixture's verifier clock, 2026-05-28T00:00:00Z.
// ../python/test_verify.py holds the same table as READ_TIMESTAMPS.
var readTimestamps = []struct {
	value, utc string
	afterClock bool
}{
	{"2026-05-28T00:03:00Z", "2026-05-28T00:03:00Z", true},
	{"2026-05-28T02:33:00+02:30", "2026-05-28T00:03:00Z", true},
	{"2026-05-27T23:03:00-01:00", "2026-05-28T00:03:00Z", true},
	{"2026-05-28T00:03:00-00:00", "2026-05-28T00:03:00Z", true},
	{"2026-05-28T00:03:00.999999999Z", "2026-05-28T00:03:00Z", true},
	{"2026-05-28T00:00:00.000000001Z", "2026-05-28T00:00:00Z", true},
	// A tenth digit of the fraction is cut, which leaves the clock itself.
	{"2026-05-28T00:00:00.0000000001Z", "2026-05-28T00:00:00Z", false},
	{"2024-02-29T23:30:00-01:00", "2024-03-01T00:30:00Z", false},
	{"0000-02-29T12:00:00Z", "0000-02-29T12:00:00Z", false},
	// A UTC time outside years 1 to 9999.
	{"0001-01-01T00:00:00+01:00", "0000-12-31T23:00:00Z", false},
	{"0000-01-01T00:00:00+23:59", "-0001-12-31T00:01:00Z", false},
	{"9999-12-31T23:59:59-01:00", "10000-01-01T00:59:59Z", true},
}

const timestampForm = "{} is not of the form YYYY-MM-DDThh:mm:ss[.fraction] followed by Z, +hh:mm or -hh:mm"

// unreadTimestamps are timestamps neither verifier reads, which each puts in
// the signed payload as written, and the message each gives, with {}
// standing for the value as the verifier quotes it (%q here, repr in
// Python). time.Parse with the time.RFC3339 layout reads the one-digit
// hour, the comma before the fraction and the offsets +24:00 and +23:60.
// ../python/test_verify.py holds the same table as UNREAD_TIMESTAMPS.
var unreadTimestamps = []struct{ value, problem string }{
	{"2026-05-28T00:03Z", timestampForm},
	{"2026-05-28 00:03:00Z", timestampForm},
	{"20260528T000300Z", timestampForm},
	{"2026-W22-4T00:03:00Z", timestampForm},
	{"2026-05-28T00:03:00+0000", timestampForm},
	{"2026-05-28T00:03:00+00", timestampForm},
	{"2026-05-28T0:03:00Z", timestampForm},
	{"2026-05-28T00:03:00,5Z", timestampForm},
	{"2026-05-28t00:03:00z", timestampForm},
	{"2026-05-28T00:03:00.Z", timestampForm},
	{"2026-05-28T00:03:00Z\n", timestampForm},
	{"tomorrow", timestampForm},
	{"", timestampForm},
	{"2026-05-28T00:03:00", "{} has no UTC offset"},
	{"2026-05-28", "{} has no UTC offset"},
	{"2026-13-28T00:03:00Z", "the month of {} is out of range"},
	{"2026-02-29T00:03:00Z", "the day of {} is out of range"},
	{"2026-05-28T24:00:00Z", "the hour of {} is out of range"},
	{"2026-05-28T00:60:00Z", "the minute of {} is out of range"},
	{"2026-05-28T23:59:60Z", "the second of {} is out of range"},
	{"2026-05-28T00:03:00+24:00", "the UTC offset hour of {} is out of range"},
	{"2026-05-28T00:03:00+23:60", "the UTC offset minute of {} is out of range"},
}

// validDoc returns the valid fixture as a decoded JSON document.
func validDoc(t *testing.T) map[string]any {
	t.Helper()
	raw, err := fs.ReadFile(aipconformance.Fixtures, embeddedFixtureDir+"/challenge-response-valid.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// object returns the JSON object at the member path in doc.
func object(doc map[string]any, path ...string) map[string]any {
	for _, name := range path {
		doc, _ = doc[name].(map[string]any)
	}
	return doc
}

// signChallenge signs the challenge in doc with the agent's bound key over
// the canonical payload that holds issuedAt and expiresAt as written, or as
// the strings signed names for them.
func signChallenge(t *testing.T, doc map[string]any, signed map[string]string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "vectors", "agent-bound-key.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		SeedHex string `json:"seedHex"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(vector.SeedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("agent-bound-key.json seedHex: %v", err)
	}
	challenge := object(doc, "challengeResponse", "challenge")
	var fields []string
	for _, name := range []string{"challenge", "agentDid", "nonce", "issuedAt", "expiresAt"} {
		value, ok := signed[name]
		if !ok {
			value, _ = challenge[name].(string)
		}
		fields = append(fields, value)
	}
	signature := ed25519.Sign(ed25519.NewKeyFromSeed(seed), []byte(strings.Join(fields, "|")))
	object(doc, "challengeResponse", "response")["signature"] = base64.RawStdEncoding.EncodeToString(signature)
}

// assertVerdict runs a file holding doc, with its expected block set to
// verdict and category, and checks that the fixture passes with that
// verdict and the reason.
func assertVerdict(t *testing.T, doc map[string]any, verdict, category, reason string) {
	t.Helper()
	expected := map[string]any{"verifyResult": verdict}
	lines := "       expected: ACCEPT\n       observed: ACCEPT\n" +
		"       signature: ed25519=true (verified against agentDid did:opena2a:agent:agent_conformance_test_001 bound key)\n"
	if category != "" {
		expected["rejectCategory"] = category
		lines = fmt.Sprintf("       expected: REJECT [%s]\n       observed: REJECT[%s: %s]\n", category, category, reason)
	}
	doc["expected"] = expected
	text, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "fixture.json")
	if err := os.WriteFile(path, append(text, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{path}, &stdout, &stderr)
	want := "PASS  " + path + "\n" + lines + "\nsummary: 1 pass, 0 fail (1 fixtures)\n"
	if code != 0 || stdout.String() != want || stderr.Len() != 0 {
		t.Errorf("exit %d, stdout:\n%s\nstderr:\n%s\nwant exit 0, stdout:\n%s", code, &stdout, &stderr, want)
	}
}

// TestEachTimestampIsReadAsInPython: the verifier puts each timestamp of
// readTimestamps in the signed payload in its UTC form, and each of
// unreadTimestamps as written.
func TestEachTimestampIsReadAsInPython(t *testing.T) {
	for _, tc := range readTimestamps {
		if got := normalizeRFC3339(tc.value); got != tc.utc {
			t.Errorf("normalizeRFC3339(%q) = %q, want %q", tc.value, got, tc.utc)
		}
	}
	for _, tc := range unreadTimestamps {
		if got := normalizeRFC3339(tc.value); got != tc.value {
			t.Errorf("normalizeRFC3339(%q) = %q, want it as written", tc.value, got)
		}
	}
}

// TestEachTimestampGetsThePythonVerdict: each timestamp of readTimestamps
// and unreadTimestamps, as a challenge issuedAt or expiresAt under the
// shipped signature or under one made over the payload the verifier
// builds, gets the verdict, category and reason that ../python/verify.py
// gives the same file, apart from the quotes around a value in a reason.
// The cases are built from the valid fixture.
func TestEachTimestampGetsThePythonVerdict(t *testing.T) {
	const shipped = "2026-05-28T00:03:00Z"
	badSignature := "Ed25519 signature did not verify against the canonical 5-field payload"
	type timestampCase struct {
		value, signed string // the value and the form the verifier signs
		afterClock    bool
		problem       string // the message for a value the verifier does not read
	}
	var cases []timestampCase
	for _, tc := range readTimestamps {
		cases = append(cases, timestampCase{tc.value, tc.utc, tc.afterClock, ""})
	}
	for _, tc := range unreadTimestamps {
		cases = append(cases, timestampCase{tc.value, tc.value, false, strings.Replace(tc.problem, "{}", strconv.Quote(tc.value), 1)})
	}
	for _, tc := range cases {
		withMember := func(member string, sign bool) map[string]any {
			doc := validDoc(t)
			object(doc, "challengeResponse", "challenge")[member] = tc.value
			if sign {
				signChallenge(t, doc, map[string]string{member: tc.signed})
			}
			return doc
		}
		t.Run(fmt.Sprintf("expiresAt %q under the shipped signature", tc.value), func(t *testing.T) {
			if tc.signed == shipped {
				assertVerdict(t, withMember("expiresAt", false), "ACCEPT", "", "")
			} else {
				assertVerdict(t, withMember("expiresAt", false), "REJECT", "SIGNATURE_INVALID", badSignature)
			}
		})
		t.Run(fmt.Sprintf("issuedAt %q signed over %q", tc.value, tc.signed), func(t *testing.T) {
			assertVerdict(t, withMember("issuedAt", true), "ACCEPT", "", "")
		})
		t.Run(fmt.Sprintf("expiresAt %q signed over %q", tc.value, tc.signed), func(t *testing.T) {
			switch {
			case tc.problem != "":
				assertVerdict(t, withMember("expiresAt", true), "REJECT", "CHALLENGE_EXPIRED", "challenge.expiresAt is not RFC 3339: "+tc.problem)
			case tc.afterClock:
				assertVerdict(t, withMember("expiresAt", true), "ACCEPT", "", "")
			default:
				assertVerdict(t, withMember("expiresAt", true), "REJECT", "CHALLENGE_EXPIRED",
					"verifier clock 2026-05-28T00:00:00Z is not before challenge.expiresAt "+tc.signed)
			}
		})
	}
}

// TestClockOutsideYears1To9999IsRead: a verifier clock whose UTC time falls
// in year 0 or 10000 is read, as ../python/verify.py reads it.
func TestClockOutsideYears1To9999IsRead(t *testing.T) {
	withClock := func(value string) map[string]any {
		doc := validDoc(t)
		object(doc, "verifierState")["clockRfc3339"] = value
		return doc
	}
	assertVerdict(t, withClock("0001-01-01T00:00:00+01:00"), "ACCEPT", "", "")
	assertVerdict(t, withClock("9999-12-31T23:59:59-01:00"), "REJECT", "CHALLENGE_EXPIRED",
		"verifier clock 10000-01-01T00:59:59Z is not before challenge.expiresAt 2026-05-28T00:03:00Z")
}
