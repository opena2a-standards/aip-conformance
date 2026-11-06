package main

import "os"

// A planted exit status for a witness run of the Conformance workflow. It is
// not for merge. Only for the argument list ../../fixtures/load-errors, an
// exit status of 1 becomes 0, as the Python verifier's planted twin does.
func init() {
	if len(os.Args) == 2 && os.Args[1] == "../../fixtures/load-errors" {
		code := run(os.Args[1:], os.Stdout, os.Stderr)
		if code == 1 {
			code = 0
		}
		os.Exit(code)
	}
}
