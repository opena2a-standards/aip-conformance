package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// prePublicationVersion is what proxy.golang.org answers for @latest and
// @main on github.com/opena2a-standards/aip-conformance/verifiers/go
// (measured 2026-10-18): the pseudo-version of the last commit at which
// verifiers/go/go.mod existed. That go.mod, prePublicationGoMod, declares
// the module path of the repository's former home. The go command resolves
// the longest module path first, so a lookup it answers with this version
// stops the run on the path mismatch before the root module is tried.
const (
	prePublicationVersion = "v0.0.0-20261017184837-d071466a3799"
	prePublicationInfo    = `{"Version":"v0.0.0-20261017184837-d071466a3799","Time":"2026-10-17T18:48:37Z"}`
	prePublicationGoMod   = "module github.com/opena2a-org/aip-conformance/verifiers/go\n\ngo 1.22.0\n"
)

// publishedRepository stands in for the GitHub repository after this commit
// lands and the tag publishedVersion is pushed. See stagePublishedRepository.
type publishedRepository struct {
	tmp      string   // the temporary directory everything below lives in
	work     string   // an empty directory outside any module, the user's cwd
	modcache string   // the GOMODCACHE in env
	env      []string // go command environment resolving publishedModule from the bare repository
}

// stagePublishedRepository creates a bare repository whose main branch is
// HEAD of the checkout at ../.. (the test binary runs with verifiers/go as
// its working directory), tagged publishedVersion, and returns an
// environment in which the go command resolves publishedModule from it:
// GOPROXY=direct makes the go command resolve modules from version control,
// and a git url.<base>.insteadOf rule in a private git configuration points
// https://github.com/opena2a-standards/aip-conformance at the bare
// repository. The go command then does what it does for a user, offline: it
// tries the module paths from .../verifiers/go up to the repository root and
// settles on the one whose go.mod it finds, resolves the version, builds the
// module zip from the commit's tracked files, and runs the verifier over the
// fixtures embedded in that zip. A checkout-local `go run .` exercises none
// of those steps.
//
// The run covers the committed tree only; uncommitted changes are not in it.
// Tests that stage the repository need git and go on PATH and skip under
// -short.
func stagePublishedRepository(t *testing.T) *publishedRepository {
	t.Helper()
	if testing.Short() {
		t.Skip("fetches, builds and runs the module through the go command; skipped with -short")
	}
	for _, tool := range []string{"git", "go"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not on PATH: %v", tool, err)
		}
	}

	tmp := t.TempDir()
	bare := filepath.Join(tmp, "aip.git")
	gitconfig := filepath.Join(tmp, "gitconfig")
	repo := &publishedRepository{
		tmp:      tmp,
		work:     filepath.Join(tmp, "work"),
		modcache: filepath.Join(tmp, "modcache"),
	}
	if err := os.MkdirAll(repo.work, 0o750); err != nil {
		t.Fatal(err)
	}

	// git rewrites the GitHub URL the go command derives from the module path
	// to the bare repository; GIT_CONFIG_GLOBAL and GIT_CONFIG_NOSYSTEM keep
	// the user's own git configuration out of the run.
	rule := fmt.Sprintf("[url %q]\n\tinsteadOf = https://%s\n", fileURL(bare), publishedModule)
	if err := os.WriteFile(gitconfig, []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	repo.env = append(os.Environ(),
		"GIT_CONFIG_GLOBAL="+gitconfig,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
		"GO111MODULE=on",
		"GOENV=off",
		"GOWORK=off",
		"GOTOOLCHAIN=local",
		"GOPROXY=direct",
		"GOSUMDB=off",
		// A fresh module cache forces the fetch; -modcacherw leaves it
		// writable so the temporary directory can be removed.
		"GOFLAGS=-modcacherw",
		"GOPATH="+filepath.Join(tmp, "gopath"),
		"GOMODCACHE="+repo.modcache,
	)
	bareEnv := append(slices.Clone(repo.env), "GIT_DIR="+bare)

	cmd := exec.Command("git", "init", "--quiet", "--bare")
	cmd.Env = bareEnv
	mustSucceed(t, cmd)
	cmd = exec.Command("git", "fetch", "--quiet", "--no-tags", "../..", "HEAD:refs/heads/main")
	cmd.Env = bareEnv
	mustSucceed(t, cmd)
	cmd = exec.Command("git", "symbolic-ref", "HEAD", "refs/heads/main")
	cmd.Env = bareEnv
	mustSucceed(t, cmd)
	// The tag the README's first command names, at the commit under test.
	cmd = exec.Command("git", "tag", publishedVersion, "refs/heads/main")
	cmd.Env = bareEnv
	mustSucceed(t, cmd)
	return repo
}

// fileURL returns the file:// URL of an absolute path.
func fileURL(path string) string {
	u := "file://" + filepath.ToSlash(path)
	if !strings.HasPrefix(u, "file:///") {
		u = "file:///" + filepath.ToSlash(path)
	}
	return u
}

// run executes cmd from the user's working directory with env and returns
// its standard output, standard error and error.
func (r *publishedRepository) run(cmd *exec.Cmd, env []string) (stdout, stderr string, err error) {
	var out, errOut strings.Builder
	cmd.Dir = r.work
	cmd.Env = env
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err = cmd.Run()
	return out.String(), errOut.String(), err
}

// assertPublishedRun checks a run of the README's first command: the go
// command fetched the module root at publishedVersion and no module under
// verifiers/ (the verifier is a package of the root module, not a module of
// its own), the first output line names that version, every fixtures/*.json
// file has a PASS line, and the summary counts them all.
func assertPublishedRun(t *testing.T, stdout, stderr string) {
	t.Helper()
	download := fmt.Sprintf("go: downloading %s %s\n", publishedModule, publishedVersion)
	if !strings.Contains(stderr, download) {
		t.Errorf("stderr lacks %q:\n%s", strings.TrimSpace(download), stderr)
	}
	if nested := "go: downloading " + publishedModule + "/verifiers"; strings.Contains(stderr, nested) {
		t.Errorf("stderr reports a module under verifiers/:\n%s", stderr)
	}
	names := checkoutFixtureNames(t)
	first, _, _ := strings.Cut(stdout, "\n")
	if want := fmt.Sprintf("fixtures: %d embedded in %s %s", len(names), publishedModule, publishedVersion); first != want {
		t.Errorf("first line %q, want %q", first, want)
	}
	for _, name := range names {
		if !strings.Contains(stdout, "PASS  "+embeddedFixtureDir+"/"+name+"\n") {
			t.Errorf("no PASS line for embedded %s in:\n%s", name, stdout)
		}
	}
	summary := fmt.Sprintf("summary: %d pass, 0 fail (%d fixtures)", len(names), len(names))
	if !strings.Contains(stdout, summary) {
		t.Errorf("missing %q in:\n%s", summary, stdout)
	}
}

// TestPublishedCommandRunsTheCommittedTree runs the README's first command,
//
//	go run github.com/opena2a-standards/aip-conformance/verifiers/go@<publishedVersion>
//
// through the go command itself against the staged repository, offline.
func TestPublishedCommandRunsTheCommittedTree(t *testing.T) {
	repo := stagePublishedRepository(t)
	cmd := exec.Command("go", "run", publishedModule+"/verifiers/go@"+publishedVersion)
	stdout, stderr, err := repo.run(cmd, repo.env)
	if err != nil {
		t.Fatalf("%s: %v\nstdout:\n%s\nstderr:\n%s", strings.Join(cmd.Args, " "), err, stdout, stderr)
	}
	assertPublishedRun(t, stdout, stderr)
}

// TestNamedVersionResolvesWhereLatestStopsOnThePrePublicationModule models
// the public module proxy. The proxy is the module cache's download
// directory, which has the proxy layout, filled by a direct run of the
// README's first command and then given what proxy.golang.org serves for
// the verifiers/go path: @latest and the version list answered with
// prePublicationVersion, whose go.mod declares another module path.
//
// Against that proxy, @latest fails the way it fails for a user, on the
// module path of the pre-publication module, while the README's first
// command, which names the version, reaches the root module and runs.
func TestNamedVersionResolvesWhereLatestStopsOnThePrePublicationModule(t *testing.T) {
	repo := stagePublishedRepository(t)
	cmd := exec.Command("go", "run", publishedModule+"/verifiers/go@"+publishedVersion)
	if stdout, stderr, err := repo.run(cmd, repo.env); err != nil {
		t.Fatalf("%s: %v\nstdout:\n%s\nstderr:\n%s", strings.Join(cmd.Args, " "), err, stdout, stderr)
	}

	proxy := filepath.Join(repo.modcache, "cache", "download")
	root := filepath.Join(proxy, filepath.FromSlash(publishedModule))
	nested := filepath.Join(root, "verifiers", "go")
	writeProxyFile(t, filepath.Join(root, "@latest"), `{"Version":"`+publishedVersion+`","Time":"2026-10-18T00:00:00Z"}`)
	writeProxyFile(t, filepath.Join(root, "@v", "list"), publishedVersion+"\n")
	writeProxyFile(t, filepath.Join(nested, "@latest"), prePublicationInfo)
	writeProxyFile(t, filepath.Join(nested, "@v", "list"), prePublicationVersion+"\n")
	writeProxyFile(t, filepath.Join(nested, "@v", prePublicationVersion+".info"), prePublicationInfo)
	writeProxyFile(t, filepath.Join(nested, "@v", prePublicationVersion+".mod"), prePublicationGoMod)
	writeProxyFile(t, filepath.Join(nested, "@v", prePublicationVersion+".zip"),
		moduleZip(t, publishedModule+"/verifiers/go@"+prePublicationVersion, map[string]string{
			"go.mod":    prePublicationGoMod,
			"verify.go": "package main\n\nfunc main() {}\n",
		}))

	// Each run starts from an empty module cache so nothing is served from
	// the cache the direct run filled; exec keeps the last value of a
	// repeated environment variable.
	proxyEnv := func(modcache string) []string {
		return append(slices.Clone(repo.env),
			"GOPROXY="+fileURL(proxy),
			"GOMODCACHE="+filepath.Join(repo.tmp, modcache),
		)
	}

	cmd = exec.Command("go", "run", publishedModule+"/verifiers/go@latest")
	stdout, stderr, err := repo.run(cmd, proxyEnv("modcache-latest"))
	if err == nil {
		t.Fatalf("%s succeeded against a proxy that answers @latest on verifiers/go with %s; the public proxy does not:\nstdout:\n%s",
			strings.Join(cmd.Args, " "), prePublicationVersion, stdout)
	}
	if want := "module declares its path as: github.com/opena2a-org/aip-conformance/verifiers/go"; !strings.Contains(stderr, want) {
		t.Errorf("%s failed for another reason than %q:\n%s", strings.Join(cmd.Args, " "), want, stderr)
	}

	cmd = exec.Command("go", "run", publishedModule+"/verifiers/go@"+publishedVersion)
	stdout, stderr, err = repo.run(cmd, proxyEnv("modcache-named"))
	if err != nil {
		t.Fatalf("%s: %v\nstdout:\n%s\nstderr:\n%s", strings.Join(cmd.Args, " "), err, stdout, stderr)
	}
	assertPublishedRun(t, stdout, stderr)
}

// writeProxyFile writes content at path, creating its directory and
// replacing a file the go command left there read-only.
func writeProxyFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// moduleZip returns a module zip holding files under the module's
// <path>@<version>/ prefix. The pre-publication module's zip must hold Go
// source: the go command looks for the package in the longest module path
// first, and only a module that holds it is loaded as far as its go.mod.
func moduleZip(t *testing.T, prefix string, files map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range files {
		f, err := w.Create(prefix + "/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// mustSucceed runs cmd, fails the test when it exits non-zero, and returns
// its standard output.
func mustSucceed(t *testing.T, cmd *exec.Cmd) string {
	t.Helper()
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(cmd.Args, " "), err, &stderr)
	}
	return string(out)
}
