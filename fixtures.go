// Package aipconformance is the Go module root of the AIP conformance suite.
// It carries the fixture set so the reference verifier at verifiers/go can run
// it from the published module alone, with no checkout:
//
//	go run github.com/opena2a-standards/aip-conformance/verifiers/go@latest
//
// The embedded bytes are the fixtures/*.json files committed at the module
// version in use, the same files MANIFEST.sha256 pins.
package aipconformance

import "embed"

// Fixtures holds every fixtures/*.json file of this module version. The
// verifier walks it when invoked with no arguments.
//
//go:embed fixtures/*.json
var Fixtures embed.FS
