package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"sort"
	"strings"
	"testing"

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
