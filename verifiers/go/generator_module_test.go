package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// generatorModule is the module path of the fixture generator, a module of
// its own nested under the repository root.
const generatorModule = publishedModule + "/scripts/generate-fixtures"

// TestGeneratorModuleBuildsFromItsPublishedPath installs
//
//	go install github.com/opena2a-standards/aip-conformance/scripts/generate-fixtures@latest
//
// through the go command against the staged repository, offline. The go
// command refuses a module whose go.mod declares a path other than the one
// it was required as, so this fails when scripts/generate-fixtures/go.mod
// names any module path but generatorModule. The checkout form, `go run .`
// inside scripts/generate-fixtures, does not compare the two paths.
func TestGeneratorModuleBuildsFromItsPublishedPath(t *testing.T) {
	repo := stagePublishedRepository(t)
	gobin := filepath.Join(repo.tmp, "bin")
	cmd := exec.Command("go", "install", generatorModule+"@latest")
	stdout, stderr, err := repo.run(cmd, append(slices.Clone(repo.env), "GOBIN="+gobin))
	if err != nil {
		t.Fatalf("%s: %v\nstdout:\n%s\nstderr:\n%s", strings.Join(cmd.Args, " "), err, stdout, stderr)
	}
	if _, err := os.Stat(filepath.Join(gobin, "generate-fixtures")); err != nil {
		t.Errorf("%s left no generate-fixtures binary in GOBIN: %v\nstderr:\n%s", strings.Join(cmd.Args, " "), err, stderr)
	}
}
