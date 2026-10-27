#!/usr/bin/env python3
"""Regression tests for scripts/schema_validation.py: a member whose schema
names the date-time format fails its fixture when it holds a value that is
not an RFC 3339 date-time, a vendored schema that names a format the
script does not check stops the run, a REJECT fixture with no
reasonContains and a fixture of another result with one each fail, and a
fixture listed in EXEMPTIONS passes only when its listed error is its only
error.

The fixture tests point the script at a temporary directory holding edited
copies of shipped fixtures, and the format test at a temporary
directory holding edited copies of the schemas. The tracked files are never
modified. The tests need the jsonschema package and are skipped without it.

Usage:
    python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

if importlib.util.find_spec("jsonschema") is None:
    raise unittest.SkipTest("the jsonschema package is not installed")

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import schema_validation  # noqa: E402

VALID = REPO_ROOT / "fixtures" / "challenge-response-valid.json"

# The challenge and response members whose schemas name the date-time format.
DATE_TIME_MEMBERS = (
    ("challenge", "issuedAt"),
    ("challenge", "expiresAt"),
    ("response", "issuedAt"),
    ("response", "expiresAt"),
    ("response", "signedAt"),
)

DATE_TIMES = (
    "2026-05-28T00:03:00Z",
    "2026-05-28T02:33:00+02:30",
    "2026-05-28T00:03:00-00:00",
    "2026-05-28T00:03:00.5Z",
    "1963-06-19t08:30:06.283185z",  # T and Z in lower case
    "1998-12-31T23:59:60Z",  # a leap second
    "1998-12-31T15:59:60.123-08:00",  # a leap second, at 23:59:60 in UTC
    "2024-02-29T00:00:00Z",
    "2000-02-29T00:00:00Z",
    "0000-02-29T00:00:00Z",
)

NOT_DATE_TIMES = (
    "tomorrow",
    "not a time",
    "",
    "2026-05-28",
    "2026-05-28T00:03:00",
    "2026-05-28T00:03Z",
    "2026-05-28 00:03:00Z",
    "20260528T000300Z",
    "2026-W22-4T00:03:00Z",
    "2013-350T01:01:01Z",
    "2026-05-28T00:03:00+0000",
    "2026-05-28T00:03:00+00",
    "2026-05-28T0:03:00Z",
    "2026-5-28T00:03:00Z",
    "2026-05-28T00:03:00,5Z",
    "2026-05-28T00:03:00.Z",
    "2026-05-28T00:03:00+01:00Z",
    "2026-05-28T00:03:00Z\n",
    "2026-05-2৪T00:03:00Z",  # a Bengali digit four
    "2026-00-28T00:03:00Z",
    "2026-13-28T00:03:00Z",
    "2026-05-00T00:03:00Z",
    "2026-02-29T00:03:00Z",
    "1900-02-29T00:03:00Z",
    "1990-02-31T15:59:59.123-08:00",
    "2026-05-28T24:00:00Z",
    "2026-05-28T00:60:00Z",
    "1998-12-31T23:59:61Z",
    "1998-12-31T23:58:60Z",  # a leap second in another minute
    "1998-12-31T22:59:60Z",  # a leap second in another hour
    "2026-05-28T00:03:00+24:00",
    "2026-05-28T00:03:00+23:60",
)


def run_main() -> tuple[int, str]:
    """schema_validation.main with its exit code and standard output."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = schema_validation.main()
    return code, out.getvalue()


def run_on_valid_copy(*edits: tuple[str, str, str]) -> tuple[int, str]:
    """run_main over a fixtures directory holding the valid fixture with each
    (part, member, value) of edits set in its challengeResponse."""
    doc = json.loads(VALID.read_text(encoding="utf-8"))
    for part, member, value in edits:
        doc["challengeResponse"][part][member] = value
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / VALID.name).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        with mock.patch.object(schema_validation, "FIXTURES", Path(d)):
            return run_main()


class DateTimeFormatTest(unittest.TestCase):
    def test_values_that_are_not_date_times_fail_the_fixture(self) -> None:
        code, out = run_on_valid_copy(
            ("challenge", "issuedAt", "tomorrow"),
            ("response", "issuedAt", "tomorrow"),
            ("challenge", "expiresAt", "not a time"),
        )
        self.assertEqual(
            out,
            f"FAIL  {VALID.name}:\n"
            "      challenge $.issuedAt: 'tomorrow' is not a 'date-time'\n"
            "      challenge $.expiresAt: 'not a time' is not a 'date-time'\n"
            "      response $.issuedAt: 'tomorrow' is not a 'date-time'\n"
            "\nsummary: 0 pass, 1 fail (1 fixtures)\n",
        )
        self.assertEqual(code, 1)

    def test_each_date_time_member_is_checked(self) -> None:
        for part, member in DATE_TIME_MEMBERS:
            for value in ("2026-05-28T00:03Z", "2026-05-28T00:03:00"):
                with self.subTest(part=part, member=member, value=value):
                    code, out = run_on_valid_copy((part, member, value))
                    self.assertEqual(
                        out,
                        f"FAIL  {VALID.name}:\n"
                        f"      {part} $.{member}: {value!r} is not a 'date-time'\n"
                        "\nsummary: 0 pass, 1 fail (1 fixtures)\n",
                    )
                    self.assertEqual(code, 1)

    def test_shipped_fixtures_pass(self) -> None:
        code, out = run_main()
        transcripts = [
            p.name
            for p in sorted((REPO_ROOT / "fixtures").glob("*.json"))
            if json.loads(p.read_text(encoding="utf-8")).get("fixtureType") == "challengeResponse"
        ]
        self.assertTrue(transcripts)
        for name in transcripts:
            self.assertIn(f"PASS  {name}\n", out)
        self.assertNotIn("FAIL", out)
        self.assertEqual(code, 0)

    def test_is_date_time(self) -> None:
        for value in DATE_TIMES:
            with self.subTest(value=value):
                self.assertTrue(schema_validation.is_date_time(value))
        for value in NOT_DATE_TIMES:
            with self.subTest(value=value):
                self.assertFalse(schema_validation.is_date_time(value))
        # The type keyword, not the format, reports a value that is not a string.
        self.assertTrue(schema_validation.is_date_time(1780000000))


def run_on_docs(docs: dict) -> tuple[int, str]:
    """run_main over a fixtures directory holding each document of docs
    under its file name."""
    with tempfile.TemporaryDirectory() as d:
        for name, doc in docs.items():
            (Path(d) / name).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        with mock.patch.object(schema_validation, "FIXTURES", Path(d)):
            return run_main()


def shipped(name: str) -> dict:
    """The shipped fixture of that file name, decoded."""
    return json.loads((REPO_ROOT / "fixtures" / name).read_text(encoding="utf-8"))


NO_PIN = "expected.verifyResult is REJECT and expected.reasonContains is missing or empty: a REJECT fixture pins the reason"
CASE_VARIANT = "challenge-response-case-variant-member.json"
CASE_VARIANT_ERROR = "response $: Additional properties are not allowed ('public\N{KELVIN SIGN}ey' was unexpected)"


class ReasonContainsPinTest(unittest.TestCase):
    def test_reject_without_a_pin_fails(self) -> None:
        for expected in (
            {"verifyResult": "REJECT", "rejectCategory": "PARSE_ERROR"},
            {"verifyResult": "REJECT", "rejectCategory": "PARSE_ERROR", "reasonContains": ""},
        ):
            with self.subTest(expected=expected):
                doc = shipped(VALID.name)
                doc["expected"] = expected
                code, out = run_on_docs({VALID.name: doc})
                self.assertEqual(out, f"FAIL  {VALID.name}:\n      {NO_PIN}\n\nsummary: 0 pass, 1 fail (1 fixtures)\n")
                self.assertEqual(code, 1)

    def test_other_result_with_a_pin_fails(self) -> None:
        doc = shipped(VALID.name)
        doc["expected"] = {"verifyResult": "ACCEPT", "reasonContains": "nonce"}
        composition = shipped("trust-score-measured-six-factors-capped.json")
        composition["expected"]["reasonContains"] = "score"
        code, out = run_on_docs({VALID.name: doc, "trust-score-measured-six-factors-capped.json": composition})
        self.assertEqual(
            out,
            f"FAIL  {VALID.name}:\n"
            "      expected.verifyResult is ACCEPT and expected.reasonContains is set: only a REJECT fixture pins a reason\n"
            "FAIL  trust-score-measured-six-factors-capped.json:\n"
            "      expected.verifyResult is MEASURED and expected.reasonContains is set: only a REJECT fixture pins a reason\n"
            "\nsummary: 0 pass, 2 fail (2 fixtures)\n",
        )
        self.assertEqual(code, 1)

    def test_shipped_fixtures_follow_the_rule(self) -> None:
        for path in sorted((REPO_ROOT / "fixtures").glob("*.json")):
            with self.subTest(path.name):
                self.assertIsNone(schema_validation.pin_problem(shipped(path.name)))


class ListedExemptionTest(unittest.TestCase):
    def test_listed_fixture_passes_on_its_one_error(self) -> None:
        code, out = run_on_docs({CASE_VARIANT: shipped(CASE_VARIANT)})
        self.assertEqual(
            out,
            f"PASS  {CASE_VARIANT}\n      listed exemption: {CASE_VARIANT_ERROR}\n\nsummary: 1 pass, 0 fail (1 fixtures)\n",
        )
        self.assertEqual(code, 0)

    def test_listed_fixture_with_another_error_fails(self) -> None:
        doc = shipped(CASE_VARIANT)
        doc["challengeResponse"]["challenge"]["issuedAt"] = "tomorrow"
        code, out = run_on_docs({CASE_VARIANT: doc})
        self.assertEqual(
            out,
            f"FAIL  {CASE_VARIANT}:\n"
            "      challenge $.issuedAt: 'tomorrow' is not a 'date-time'\n"
            f"      {CASE_VARIANT_ERROR}\n"
            f"      listed exemption, not the only error: {CASE_VARIANT_ERROR}\n"
            "\nsummary: 0 pass, 1 fail (1 fixtures)\n",
        )
        self.assertEqual(code, 1)

    def test_unlisted_fixture_with_an_undefined_member_fails(self) -> None:
        code, out = run_on_valid_copy(("response", "issued_at", "2026-05-27T23:58:00Z"))
        self.assertEqual(
            out,
            f"FAIL  {VALID.name}:\n"
            "      response $: Additional properties are not allowed ('issued_at' was unexpected)\n"
            "\nsummary: 0 pass, 1 fail (1 fixtures)\n",
        )
        self.assertEqual(code, 1)


class UncheckedFormatTest(unittest.TestCase):
    def test_format_without_a_checker_stops_the_run(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            vendor = Path(d)
            for schema in schema_validation.VENDOR.glob("*.json"):
                shutil.copy(schema, vendor / schema.name)
            path = vendor / "challenge-body-v1.schema.json"
            schema = json.loads(path.read_text(encoding="utf-8"))
            schema["properties"]["issuerDid"] = {"type": "string", "format": "uri"}
            path.write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")
            with mock.patch.object(schema_validation, "VENDOR", vendor):
                code, out = run_main()
        self.assertEqual(
            out, "error: challenge-body-v1.schema.json names the format uri, which this script does not check\n"
        )
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
