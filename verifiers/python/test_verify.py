"""Regression tests for verify.py: a fixture that writes one member name
twice in a JSON object outside challengeResponse fails to load, a member
spelled in another case is not read as the fixture member, and a fixture
whose verifierState the checks cannot use, or whose top-level value is not
a JSON object, prints one FAIL block, after which the run goes on to the
next fixture.

Run from this directory:
    python3 -m unittest -v test_verify
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Callable

import verify

FIXTURES = Path(__file__).resolve().parent.parent.parent / "fixtures"
REPLAY = FIXTURES / "challenge-response-replay.json"
VALID = FIXTURES / "challenge-response-valid.json"


def member_text(text: str, name: str) -> str:
    """The one member name written in text, as text: its quoted name, ": "
    and its value as written."""
    key = json.dumps(name) + ": "
    if text.count(key) != 1:
        raise AssertionError(f"the fixture writes {key} {text.count(key)} times, want once")
    start = text.index(key)
    _, end = json.JSONDecoder().raw_decode(text, start + len(key))
    return text[start:end]


def append_member(text: str, member: str) -> str:
    """text with member written as text after the last member of its
    top-level object."""
    if not text.endswith("\n}\n"):
        raise AssertionError("the fixture does not end with the } of its top-level object")
    return text[: -len("\n}\n")] + ",\n  " + member + "\n}\n"


def edited(text: str, edit: Callable[[dict], object]) -> str:
    """The fixture text with edit applied to its parsed document, written
    back as JSON."""
    doc = json.loads(text)
    edit(doc)
    return json.dumps(doc, indent=2) + "\n"


def run_main(*paths: Path) -> tuple[int, str, str]:
    """verify.main over the file paths, in order, with its exit code,
    standard output and standard error."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = verify.main(["verify.py", *map(str, paths)])
    return code, out.getvalue(), err.getvalue()


def run_text(text: str) -> tuple[Path, int, str, str]:
    """run_main over a file holding text, with the file's path."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "fixture.json"
        path.write_text(text, encoding="utf-8")
        return (path, *run_main(path))


class RepeatedWrapperMemberTest(unittest.TestCase):
    """A fixture that writes one member name twice in a JSON object outside
    challengeResponse fails to load, whatever the two copies hold, and counts
    as a fail with no verdict. The cases are built from the replay fixture,
    whose REJECT [NONCE_REPLAY] rests on verifierState.seenNonces. A member
    spelled in another case is another name: it repeats nothing and is not
    read as the member, so the verdict stays, as it does for the shipped
    fixture. ../go/verify_test.go builds the same cases and expects the same
    lines."""

    def setUp(self) -> None:
        self.text = REPLAY.read_text(encoding="utf-8")

    def test_repeated_member_is_a_load_error(self) -> None:
        state = member_text(self.text, "verifierState")
        seen = member_text(self.text, "seenNonces")
        members = json.loads(state.removeprefix('"verifierState": '))
        del members["seenNonces"]
        repeats = [
            (
                "verifierState twice, the later copy without seenNonces",
                append_member(self.text, '"verifierState": ' + json.dumps(members)),
                "verifierState",
            ),
            ("verifierState twice, both copies the same", append_member(self.text, state), "verifierState"),
            (
                "seenNonces twice in one verifierState",
                self.text.replace(seen, seen + ",\n    " + seen, 1),
                "verifierState.seenNonces",
            ),
            (
                "the empty name twice in the top-level object",
                append_member(append_member(self.text, '"": 1'), '"": 2'),
                "",
            ),
            (
                "two unpaired surrogate escapes, each decoded to U+FFFD",
                append_member(append_member(self.text, '"\\ud800": 1'), '"\\udbff": 2'),
                chr(0xFFFD),
            ),
        ]
        for name, text, member in repeats:
            with self.subTest(name):
                path, code, out, err = run_text(text)
                self.assertEqual(
                    out,
                    f"FAIL  {path}\n       parse error: {member}: duplicate member name\n\n"
                    "summary: 0 pass, 1 fail (1 fixtures)\n",
                )
                self.assertEqual(err, "")
                self.assertEqual(code, 1)

    def test_repeat_nested_past_the_recursion_limit(self) -> None:
        depth = sys.getrecursionlimit() + 100
        text = append_member(self.text, '"note": ' + "[" * depth + '{"a": 1, "a": 2}' + "]" * depth)
        try:
            json.loads(text)
        except RecursionError:
            self.skipTest("json.loads on this interpreter does not read the document")
        path, code, out, err = run_text(text)
        member = "note" + "[0]" * depth + ".a"
        self.assertEqual(
            out,
            f"FAIL  {path}\n       parse error: {member}: duplicate member name\n\n"
            "summary: 0 pass, 1 fail (1 fixtures)\n",
        )
        self.assertEqual(err, "")
        self.assertEqual(code, 1)

    def test_case_variant_and_shipped_fixture_keep_the_verdict(self) -> None:
        verdict = (
            "       expected: REJECT [NONCE_REPLAY]\n"
            "       observed: REJECT[NONCE_REPLAY: response.nonce was already seen by the verifier]\n\n"
            "summary: 1 pass, 0 fail (1 fixtures)\n"
        )
        with self.subTest("VerifierState after verifierState"):
            path, code, out, err = run_text(append_member(self.text, '"VerifierState": {"seenNonces": []}'))
            self.assertEqual(out, f"PASS  {path}\n" + verdict)
            self.assertEqual(err, "")
            self.assertEqual(code, 0)
        with self.subTest("the shipped fixture"):
            code, out, err = run_main(REPLAY)
            self.assertEqual(out, f"PASS  {REPLAY}\n" + verdict)
            self.assertEqual(err, "")
            self.assertEqual(code, 0)


class UnreadableFixtureTest(unittest.TestCase):
    """A fixture the verifier cannot read prints one FAIL block, and the run
    goes on to the next fixture and prints the summary line. A
    challengeResponse fixture with no verifierState, or with a verifierState
    member that a check reads and cannot use, is a fixture error naming the
    member; a file whose top-level value is not a JSON object fails to load;
    another error raised while checking a fixture is reported with its type.
    The cases are built from the valid fixture, whose ACCEPT reads every
    verifierState member the checks use, and each case runs before the
    shipped valid fixture, whose PASS block follows unchanged."""

    def setUp(self) -> None:
        self.text = VALID.read_text(encoding="utf-8")
        code, out, err = run_main(VALID)
        summary = "\nsummary: 1 pass, 0 fail (1 fixtures)\n"
        self.assertTrue(out.startswith(f"PASS  {VALID}\n") and out.endswith(summary), out)
        self.assertEqual((code, err), (0, ""))
        self.valid_block = out[: -len(summary)]

    def assert_fails_then_valid_passes(self, text: str, line: str) -> None:
        """A file holding text, run before the valid fixture, prints a FAIL
        block whose one line is line, then the valid fixture's PASS block and
        a summary of one pass and one fail."""
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "fixture.json"
            path.write_text(text, encoding="utf-8")
            code, out, err = run_main(path, VALID)
        self.assertEqual(
            out,
            f"FAIL  {path}\n       {line}\n"
            + self.valid_block
            + "\nsummary: 1 pass, 1 fail (2 fixtures)\n",
        )
        self.assertEqual(err, "")
        self.assertEqual(code, 1)

    def test_unusable_verifier_state_is_a_fixture_error(self) -> None:
        state = member_text(self.text, "verifierState")
        with self.assertRaises(ValueError) as unread:
            verify._parse_rfc3339("tomorrow")

        def bindings(d: dict) -> list:
            return d["verifierState"]["agentBindings"]

        def second_entry_without_agent_did(d: dict) -> None:
            bindings(d).insert(0, dict(bindings(d)[0], agentDid="did:opena2a:agent:not_bound"))
            del bindings(d)[1]["agentDid"]

        cases = [
            (
                "VerifierState in place of verifierState",
                self.text.replace(state, '"VerifierState"' + state.removeprefix('"verifierState"')),
                "verifierState: missing",
            ),
            ("no verifierState", edited(self.text, lambda d: d.pop("verifierState")), "verifierState: missing"),
            (
                "verifierState null",
                edited(self.text, lambda d: d.update(verifierState=None)),
                "verifierState: null, not an object",
            ),
            (
                "verifierState an array",
                edited(self.text, lambda d: d.update(verifierState=[d["verifierState"]])),
                "verifierState: an array, not an object",
            ),
            (
                "agentBindings a string",
                edited(self.text, lambda d: d["verifierState"].update(agentBindings="did:opena2a:agent:not_bound")),
                "verifierState.agentBindings: a string, not an array",
            ),
            (
                "an agentBindings entry null",
                edited(self.text, lambda d: d["verifierState"].update(agentBindings=[None])),
                "verifierState.agentBindings[0]: null, not an object",
            ),
            (
                "an agentBindings entry with no agentDid",
                edited(self.text, lambda d: bindings(d)[0].pop("agentDid")),
                "verifierState.agentBindings[0].agentDid: missing",
            ),
            (
                "a second agentBindings entry with no agentDid",
                edited(self.text, second_entry_without_agent_did),
                "verifierState.agentBindings[1].agentDid: missing",
            ),
            (
                "the bound entry with no publicKeyHex",
                edited(self.text, lambda d: bindings(d)[0].pop("publicKeyHex")),
                "verifierState.agentBindings[0].publicKeyHex: missing",
            ),
            (
                "the bound entry's publicKeyHex a number",
                edited(self.text, lambda d: bindings(d)[0].update(publicKeyHex=7)),
                "verifierState.agentBindings[0].publicKeyHex: a number, not a string",
            ),
            (
                "no clockRfc3339",
                edited(self.text, lambda d: d["verifierState"].pop("clockRfc3339")),
                "verifierState.clockRfc3339: missing",
            ),
            (
                "clockRfc3339 a number",
                edited(self.text, lambda d: d["verifierState"].update(clockRfc3339=1780000000)),
                "verifierState.clockRfc3339: a number, not a string",
            ),
            (
                "clockRfc3339 not a date-time",
                edited(self.text, lambda d: d["verifierState"].update(clockRfc3339="tomorrow")),
                f"verifierState.clockRfc3339: cannot be read as a date-time ({unread.exception})",
            ),
            (
                "seenNonces a number",
                edited(self.text, lambda d: d["verifierState"].update(seenNonces=7)),
                "verifierState.seenNonces: a number, not an array",
            ),
        ]
        for name, text, member in cases:
            with self.subTest(name):
                self.assert_fails_then_valid_passes(text, "fixture error: " + member)

    def test_top_level_value_that_is_not_an_object_fails_to_load(self) -> None:
        for text, kind in (("[]\n", "an array"), ("null\n", "null"), ('"fixture"\n', "a string")):
            with self.subTest(text.strip()):
                self.assert_fails_then_valid_passes(
                    text, f"parse error: the top-level value is {kind}, not an object"
                )

    def test_other_error_is_reported_with_its_type(self) -> None:
        text = edited(self.text, lambda d: d["challengeResponse"]["response"].pop("agentDid"))
        self.assert_fails_then_valid_passes(text, "error: KeyError: 'agentDid'")

    def test_signature_reject_does_not_read_verifier_state(self) -> None:
        """The signature check runs before any check reads verifierState, so
        a null verifierState under a signature that does not verify keeps
        the REJECT [SIGNATURE_INVALID] verdict."""

        def edit(d: dict) -> None:
            d["verifierState"] = None
            d["challengeResponse"]["challenge"]["issuedAt"] = "2026-05-27T23:59:00Z"
            d["expected"] = {"verifyResult": "REJECT", "rejectCategory": "SIGNATURE_INVALID"}

        path, code, out, err = run_text(edited(self.text, edit))
        self.assertEqual(
            out,
            f"PASS  {path}\n"
            "       expected: REJECT [SIGNATURE_INVALID]\n"
            "       observed: REJECT[SIGNATURE_INVALID: Ed25519 signature did not verify against the canonical 5-field payload]\n\n"
            "summary: 1 pass, 0 fail (1 fixtures)\n",
        )
        self.assertEqual(err, "")
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
