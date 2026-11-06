package main

import "os"

// A planted divergence for a witness run of the Conformance workflow. It is
// not for merge. Only the argument list ../../fixtures/load-errors writes the
// extra line.
func init() {
	if len(os.Args) == 2 && os.Args[1] == "../../fixtures/load-errors" {
		_, _ = os.Stdout.WriteString("planted divergence over load-errors, witness run, not for merge\n")
	}
}
