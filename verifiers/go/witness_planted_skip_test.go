package main

import "testing"

// TestWitnessPlantedSkip is a planted skip for a witness run of the
// Conformance workflow. It is not for merge.
func TestWitnessPlantedSkip(t *testing.T) {
	t.Skip("planted skip, witness run, not for merge")
}
