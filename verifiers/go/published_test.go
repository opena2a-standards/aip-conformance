package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestPublishedCommandRunsTheCommittedTree runs the README's first command,
//
//	go run github.com/opena2a-standards/aip-conformance/verifiers/go@latest
//
// through the go command itself, offline. GOPROXY=direct makes the go command
// resolve the module from version control, and a git url.<base>.insteadOf
// rule points https://github.com/opena2a-standards/aip-conformance at a bare
// repository whose main branch is this checkout's HEAD commit. The go command
// then does what it does for a user: it tries the module paths from
// .../verifiers/go up to the repository root and settles on the one whose
// go.mod it finds, resolves @latest to a pseudo-version of the default branch
// (the bare repository carries no tags), builds the module zip from the
// commit's tracked files, and runs the verifier over the fixtures embedded in
// that zip. A checkout-local `go run .` exercises none of those steps.
//
// The run covers the committed tree only; uncommitted changes are not in it.
// The test needs git and go on PATH and skips under -short.
func TestPublishedCommandRunsTheCommittedTree(t *testing.T) {
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
	work := filepath.Join(tmp, "work")
	if err := os.MkdirAll(work, 0o750); err != nil {
		t.Fatal(err)
	}

	// git rewrites the GitHub URL the go command derives from the module path
	// to the bare repository; GIT_CONFIG_GLOBAL and GIT_CONFIG_NOSYSTEM keep
	// the user's own git configuration out of the run.
	fileURL := "file://" + filepath.ToSlash(bare)
	if !strings.HasPrefix(fileURL, "file:///") {
		fileURL = "file:///" + filepath.ToSlash(bare)
	}
	rule := fmt.Sprintf("[url %q]\n\tinsteadOf = https://%s\n", fileURL, publishedModule)
	if err := os.WriteFile(gitconfig, []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(),
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
		"GOMODCACHE="+filepath.Join(tmp, "modcache"),
	)
	bareEnv := append(slices.Clone(env), "GIT_DIR="+bare)

	// The bare repository stands in for the GitHub repository after this
	// commit lands: its main branch is HEAD of the checkout at ../.. (the
	// test binary runs with verifiers/go as its working directory).
	cmd := exec.Command("git", "init", "--quiet", "--bare")
	cmd.Env = bareEnv
	mustSucceed(t, cmd)
	cmd = exec.Command("git", "fetch", "--quiet", "--no-tags", "../..", "HEAD:refs/heads/main")
	cmd.Env = bareEnv
	mustSucceed(t, cmd)
	cmd = exec.Command("git", "symbolic-ref", "HEAD", "refs/heads/main")
	cmd.Env = bareEnv
	mustSucceed(t, cmd)

	// With no tags in reach, the go command names the commit
	// v0.0.0-<committer time, UTC>-<12-character hash>.
	cmd = exec.Command("git", "rev-parse", "HEAD")
	cmd.Env = env
	head := strings.TrimSpace(mustSucceed(t, cmd))
	cmd = exec.Command("git", "log", "-1", "--format=%ct", "HEAD")
	cmd.Env = env
	committed, err := strconv.ParseInt(strings.TrimSpace(mustSucceed(t, cmd)), 10, 64)
	if err != nil {
		t.Fatalf("parsing the HEAD committer time: %v", err)
	}
	if len(head) < 12 {
		t.Fatalf("HEAD hash %q is shorter than 12 characters", head)
	}
	version := fmt.Sprintf("v0.0.0-%s-%s", time.Unix(committed, 0).UTC().Format("20060102150405"), head[:12])

	// The user's command, from a directory outside any module.
	cmd = exec.Command("go", "run", publishedModule+"/verifiers/go@latest")
	cmd.Dir = work
	cmd.Env = env
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s: %v\nstdout:\n%s\nstderr:\n%s", strings.Join(cmd.Args, " "), err, &stdout, &stderr)
	}

	// The go command fetched the module root at the commit's pseudo-version
	// and nothing under verifiers/: the verifier is a package of the root
	// module, not a module of its own.
	download := fmt.Sprintf("go: downloading %s %s\n", publishedModule, version)
	if !strings.Contains(stderr.String(), download) {
		t.Errorf("stderr lacks %q:\n%s", strings.TrimSpace(download), &stderr)
	}
	if nested := "go: downloading " + publishedModule + "/verifiers"; strings.Contains(stderr.String(), nested) {
		t.Errorf("stderr reports a module under verifiers/:\n%s", &stderr)
	}

	// The verifier ran the fixtures embedded at that version.
	names := checkoutFixtureNames(t)
	out := stdout.String()
	first, _, _ := strings.Cut(out, "\n")
	if want := fmt.Sprintf("fixtures: %d embedded in %s %s", len(names), publishedModule, version); first != want {
		t.Errorf("first line %q, want %q", first, want)
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
