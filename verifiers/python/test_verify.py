"""Regression tests for verify.py: a fixture that writes one member name
twice in a JSON object outside challengeResponse fails to load, and a member
spelled in another case is not read as the fixture member.

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

import verify

REPLAY = Path(__file__).resolve().parent.parent.parent / "fixtures" / "challenge-response-replay.json"


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


def run_main(path: Path) -> tuple[int, str, str]:
    """verify.main over the one file path, with its exit code, standard
    output and standard error."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = verify.main(["verify.py", str(path)])
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


if __name__ == "__main__":
    unittest.main()
