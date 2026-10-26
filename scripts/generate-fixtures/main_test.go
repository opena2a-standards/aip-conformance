package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// readTimestamps are timestamps both reference verifiers read, and the UTC
// form each verifier puts in the signed payload.
// verifiers/go/verify_test.go holds the same values and UTC forms as
// readTimestamps, which TestTimestampTablesAreTheGoVerifierTables checks.
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
// verifiers/go/verify_test.go holds the same table as unreadTimestamps,
// which TestTimestampTablesAreTheGoVerifierTables checks.
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
	// A year in fullwidth digits, characters outside ASCII that neither
	// reference verifier reads as digits.
	{"２０２６-05-28T00:03:00Z", timestampForm},
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

// TestTimestampTablesAreTheGoVerifierTables: readTimestamps holds the values
// and UTC forms of the readTimestamps table in verifiers/go/verify_test.go,
// and unreadTimestamps the values and problems of its unreadTimestamps
// table, entry for entry in the same order.
func TestTimestampTablesAreTheGoVerifierTables(t *testing.T) {
	verifier := goVerifierTables(t, "readTimestamps", "unreadTimestamps")
	var read, unread [][2]string
	for _, tc := range readTimestamps {
		read = append(read, [2]string{tc.value, tc.utc})
	}
	for _, tc := range unreadTimestamps {
		unread = append(unread, [2]string{tc.value, tc.problem})
	}
	for _, table := range []struct {
		name string
		here [][2]string
	}{{"readTimestamps", read}, {"unreadTimestamps", unread}} {
		there := verifier[table.name]
		for i := 0; i < max(len(table.here), len(there)); i++ {
			if i >= len(table.here) || i >= len(there) || table.here[i] != there[i] {
				t.Errorf("%s holds %d entries here and %d in verifiers/go/verify_test.go; at index %d it holds %s here and %s there",
					table.name, len(table.here), len(there), i, entryAt(table.here, i), entryAt(there, i))
				break
			}
		}
	}
}

// entryAt is entry i of table, quoted, or "no entry" past its end.
func entryAt(table [][2]string, i int) string {
	if i >= len(table) {
		return "no entry"
	}
	return fmt.Sprintf("%q", table[i])
}

// goVerifierTables parses verifiers/go/verify_test.go and returns, for each
// of names, the first two fields of each entry of the package-level table of
// that name. A field is a string literal or the name of a string constant
// the file declares.
func goVerifierTables(t *testing.T, names ...string) map[string][][2]string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join("..", "..", "verifiers", "go", "verify_test.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	consts := map[string]string{}
	vars := map[string]ast.Expr{}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gen.Specs {
			v, ok := spec.(*ast.ValueSpec)
			if !ok || len(v.Names) != 1 || len(v.Values) != 1 {
				continue
			}
			name, value := v.Names[0].Name, v.Values[0]
			if gen.Tok == token.VAR {
				vars[name] = value
			} else if lit, ok := value.(*ast.BasicLit); ok && gen.Tok == token.CONST && lit.Kind == token.STRING {
				consts[name], _ = strconv.Unquote(lit.Value)
			}
		}
	}
	field := func(e ast.Expr) (string, bool) {
		switch e := e.(type) {
		case *ast.BasicLit:
			s, err := strconv.Unquote(e.Value)
			return s, e.Kind == token.STRING && err == nil
		case *ast.Ident:
			s, ok := consts[e.Name]
			return s, ok
		}
		return "", false
	}
	tables := map[string][][2]string{}
	for _, name := range names {
		table, ok := vars[name].(*ast.CompositeLit)
		if !ok {
			t.Fatalf("verifiers/go/verify_test.go declares no table %s", name)
		}
		for _, elt := range table.Elts {
			entry, ok := elt.(*ast.CompositeLit)
			if !ok || len(entry.Elts) < 2 {
				t.Fatalf("%s: an entry of %s that is not a composite literal of two or more fields", fset.Position(elt.Pos()), name)
			}
			first, firstOK := field(entry.Elts[0])
			second, secondOK := field(entry.Elts[1])
			if !firstOK || !secondOK {
				t.Fatalf("%s: an entry of %s whose first two fields are not string literals or string constants", fset.Position(elt.Pos()), name)
			}
			tables[name] = append(tables[name], [2]string{first, second})
		}
	}
	return tables
}
