package main

import (
	"strconv"
	"strings"
	"testing"
)

// readTimestamps are timestamps both reference verifiers read, and the UTC
// form each verifier puts in the signed payload.
// verifiers/go/verify_test.go holds the same values and UTC forms as
// readTimestamps.
var readTimestamps = []struct{ value, utc string }{
	{"2026-05-28T00:03:00Z", "2026-05-28T00:03:00Z"},
	{"2026-05-28T02:33:00+02:30", "2026-05-28T00:03:00Z"},
	{"2026-05-27T23:03:00-01:00", "2026-05-28T00:03:00Z"},
	{"2026-05-28T00:03:00-00:00", "2026-05-28T00:03:00Z"},
	{"2026-05-28T00:03:00.999999999Z", "2026-05-28T00:03:00Z"},
	{"2026-05-28T00:00:00.000000001Z", "2026-05-28T00:00:00Z"},
	{"2026-05-28T00:00:00.0000000001Z", "2026-05-28T00:00:00Z"},
	{"2024-02-29T23:30:00-01:00", "2024-03-01T00:30:00Z"},
	{"0000-02-29T12:00:00Z", "0000-02-29T12:00:00Z"},
	// A UTC time outside years 1 to 9999.
	{"0001-01-01T00:00:00+01:00", "0000-12-31T23:00:00Z"},
	{"0000-01-01T00:00:00+23:59", "-0001-12-31T00:01:00Z"},
	{"9999-12-31T23:59:59-01:00", "10000-01-01T00:59:59Z"},
}

const timestampForm = "{} is not of the form YYYY-MM-DDThh:mm:ss[.fraction] followed by Z, +hh:mm or -hh:mm"

// unreadTimestamps are timestamps neither reference verifier reads, and the
// message each gives, with {} standing for the value as the verifier quotes
// it (%q in Go, repr in Python).
// verifiers/go/verify_test.go holds the same table as unreadTimestamps.
// time.Parse with the time.RFC3339 layout reads the one-digit hour, the
// comma before the fraction and the offsets +24:00 and +23:60.
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

// payload is canonicalChallengeResponsePayload of a challenge with the given
// issuedAt and expiresAt, or the value it panics with as refusal.
func payload(issuedAt, expiresAt string) (signed string, refusal any) {
	defer func() { refusal = recover() }()
	return string(canonicalChallengeResponsePayload(ChallengeBody{
		Challenge: "challenge",
		AgentDID:  "agent",
		Nonce:     "nonce",
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
		IssuerDID: "issuer",
	})), nil
}

// TestTimestampsAreSignedInTheUTCFormTheVerifiersRead: each timestamp of
// readTimestamps, as issuedAt and as expiresAt, enters the signed payload in
// the UTC form both reference verifiers put it in.
func TestTimestampsAreSignedInTheUTCFormTheVerifiersRead(t *testing.T) {
	for _, tc := range readTimestamps {
		want := "challenge|agent|nonce|" + tc.utc + "|" + tc.utc
		if got, refusal := payload(tc.value, tc.value); got != want || refusal != nil {
			t.Errorf("payload with issuedAt and expiresAt %q = %q (panic: %v), want %q", tc.value, got, refusal, want)
		}
	}
}

// TestTimestampsTheVerifiersDoNotReadAreRefused: the generator panics on each
// timestamp of unreadTimestamps, as issuedAt or as expiresAt, naming the
// problem the Go verifier gives for it.
func TestTimestampsTheVerifiersDoNotReadAreRefused(t *testing.T) {
	const shipped = "2026-05-28T00:03:00Z"
	for _, tc := range unreadTimestamps {
		want := "challenge issuedAt and expiresAt must be date-times the reference verifiers read: " +
			strings.Replace(tc.problem, "{}", strconv.Quote(tc.value), 1)
		if got, refusal := payload(tc.value, shipped); refusal != want {
			t.Errorf("payload with issuedAt %q = %q (panic: %v), want panic %q", tc.value, got, refusal, want)
		}
		if got, refusal := payload(shipped, tc.value); refusal != want {
			t.Errorf("payload with expiresAt %q = %q (panic: %v), want panic %q", tc.value, got, refusal, want)
		}
	}
}
