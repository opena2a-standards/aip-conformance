"""Regression tests for verify.py: a fixture that writes one member name
twice in a JSON object outside challengeResponse fails to load, a member
spelled in another case is not read as the fixture member, a fixture
whose verifierState the checks cannot use, or whose top-level value is not
a JSON object, prints one FAIL block, after which the run goes on to the
next fixture, a verifierState agentBindings or seenNonces that is not an
array or null is a fixture error, a timestamp with no UTC offset is not
read in the machine's local time zone, a timestamp is read, signed and
compared as the Go verifier reads, signs and compares it, and the walk
that looks for a repeated member name stays within a memory bound over
10,000 nested arrays and a time bound over 9,999 nested arrays around
1,000,000 zeros.

Run from this directory:
    python3 -m unittest -v test_verify
"""

from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import sys
import tempfile
import time
import tracemalloc
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Iterator

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import verify

FIXTURES = Path(__file__).resolve().parent.parent.parent / "fixtures"
REPLAY = FIXTURES / "challenge-response-replay.json"
VALID = FIXTURES / "challenge-response-valid.json"
AGENT_BOUND_KEY = FIXTURES.parent / "vectors" / "agent-bound-key.json"

# The local time zones the time-zone tests run under, each with its UTC
# offset in hours on 2026-05-28: UTC, a zone behind it and a zone ahead of it.
TIME_ZONES = (("UTC", 0), ("America/Denver", -6), ("Asia/Tokyo", 9))


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


@contextlib.contextmanager
def local_time_zone(name: str) -> Iterator[None]:
    """The process's local time zone set to the zone name inside the block,
    as TZ=name sets it for a new process."""
    saved = os.environ.get("TZ")
    os.environ["TZ"] = name
    time.tzset()
    try:
        yield
    finally:
        if saved is None:
            del os.environ["TZ"]
        else:
            os.environ["TZ"] = saved
        time.tzset()


def sign_as_written(doc: dict, **signed: str) -> None:
    """Signs the challenge in doc with the agent's bound key over the
    canonical payload that holds issuedAt and expiresAt as written, or as
    the strings signed names for them (issuedAt=..., expiresAt=...)."""
    seed = bytes.fromhex(json.loads(AGENT_BOUND_KEY.read_text(encoding="utf-8"))["seedHex"])
    challenge = dict(doc["challengeResponse"]["challenge"], **signed)
    payload = "|".join(challenge[k] for k in ("challenge", "agentDid", "nonce", "issuedAt", "expiresAt"))
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(payload.encode("ascii"))
    doc["challengeResponse"]["response"]["signature"] = base64.b64encode(signature).decode("ascii").rstrip("=")


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


def nested_arrays(depth: int, inner: list) -> list:
    """inner inside depth - 1 more arrays: depth nested arrays in all."""
    value = inner
    for _ in range(depth - 1):
        value = [value]
    return value


class RepeatedMemberWalkCostTest(unittest.TestCase):
    """The repeated-member walk joins a whole path only for the member it
    returns. Over 10,000 nested arrays its peak traced memory stays under
    1 KB per level, and over 9,999 nested arrays around 1,000,000 zeros it
    takes under 5 times the CPU time of the walk over one array of the same
    zeros. Each document is the replay fixture as load_fixture reads it, with
    one more top-level member holding the arrays. ../go/verify_test.go bounds
    what the Go walk allocates over 9,999 nested arrays, empty and around
    1,000,000 zeros."""

    def walk(self, extra: list) -> Callable[[], None]:
        """A call of the walk over the replay fixture with one more
        top-level member, "extra", holding extra."""
        fixture = json.loads(REPLAY.read_text(encoding="utf-8"), object_pairs_hook=verify._JSONObject.from_pairs)
        doc = verify._JSONObject.from_pairs([*fixture.pairs, ("extra", extra)])
        return lambda: self.assertIsNone(verify._repeated_member("", doc, verify._PROTOCOL_MESSAGES))

    def test_deep_document_peak_memory(self) -> None:
        depth = 10_000
        walk = self.walk(nested_arrays(depth, []))
        tracemalloc.start()
        try:
            walk()
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        # When this bound was set the walk peaked at about 320 bytes per level
        # (Python 3.14.3), and a walk that holds the path of every enclosing
        # array at over 15,000.
        self.assertLess(peak, 1024 * depth, f"peak {peak} bytes over {depth} nested arrays")

    def test_wide_document_cpu_time(self) -> None:
        # 9,999 nested arrays around 1,000,000 zeros against one array of the
        # same zeros. The fastest of three runs of each is compared, and the
        # runs alternate, so that one slow spell on a loaded machine does not
        # decide the result. When this bound was set the nested walk took about
        # 1.1 times the flat one (Python 3.14.3), and a walk that writes out
        # the path of every value over 30 times.
        zeros = [0] * 1_000_000
        walks = {"flat": self.walk(zeros), "deep": self.walk(nested_arrays(9_999, zeros))}
        fastest = {name: float("inf") for name in walks}
        for _ in range(3):
            for name, walk in walks.items():
                start = time.process_time()
                walk()
                fastest[name] = min(fastest[name], time.process_time() - start)
        self.assertLess(fastest["deep"], 5 * fastest["flat"], f"fastest CPU seconds {fastest}")


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


class VerifierStateArrayOfAnotherTypeTest(unittest.TestCase):
    """A verifierState agentBindings or seenNonces that holds 0, false, ""
    or {} fails its fixture with a fixture error naming the member and the
    value's JSON type, before any check runs: under a signature that does
    not verify, and in a trustScoreComposition fixture, too. The cases are
    built from the replay fixture, whose REJECT [NONCE_REPLAY] rests on both
    members. ../go/verify_test.go builds the same cases and expects the
    same lines."""

    VALUES = ((0, "a number"), (False, "a boolean"), ("", "a string"), ({}, "an object"))

    def assert_fixture_error(self, text: str, line: str) -> None:
        path, code, out, err = run_text(text)
        self.assertEqual(out, f"FAIL  {path}\n       {line}\n\nsummary: 0 pass, 1 fail (1 fixtures)\n")
        self.assertEqual(err, "")
        self.assertEqual(code, 1)

    def test_value_that_is_not_an_array_or_null_is_a_fixture_error(self) -> None:
        replay = REPLAY.read_text(encoding="utf-8")

        def bad_signature(d: dict) -> None:
            d["challengeResponse"]["challenge"]["issuedAt"] = "2026-05-27T23:58:00Z"
            d["expected"]["rejectCategory"] = "SIGNATURE_INVALID"
            d["verifierState"]["seenNonces"] = 0

        def both(d: dict) -> None:
            d["verifierState"]["seenNonces"] = 0
            d["verifierState"]["agentBindings"] = 0

        cases = [
            (
                f"{member} {json.dumps(value)}",
                edited(replay, lambda d, m=member, v=value: d["verifierState"].update({m: v})),
                f"fixture error: verifierState.{member}: {kind}, not an array",
            )
            for member in ("agentBindings", "seenNonces")
            for value, kind in self.VALUES
        ] + [
            (
                "seenNonces 0 under a signature that does not verify",
                edited(replay, bad_signature),
                "fixture error: verifierState.seenNonces: a number, not an array",
            ),
            (
                "agentBindings and seenNonces both 0",
                edited(replay, both),
                "fixture error: verifierState.agentBindings: a number, not an array",
            ),
            (
                "seenNonces {} in a trustScoreComposition fixture",
                append_member(
                    (FIXTURES / "trust-score-measured-six-factors-capped.json").read_text(encoding="utf-8"),
                    '"verifierState": {"seenNonces": {}}',
                ),
                "fixture error: verifierState.seenNonces: an object, not an array",
            ),
        ]
        for name, text, line in cases:
            with self.subTest(name):
                self.assert_fixture_error(text, line)

    def test_checks_called_directly_raise_for_the_member(self) -> None:
        doc = json.loads(REPLAY.read_text(encoding="utf-8"))
        for member in ("agentBindings", "seenNonces"):
            for value, kind in self.VALUES:
                with self.subTest(f"{member} {json.dumps(value)}"):
                    vs = dict(doc["verifierState"], **{member: value})
                    with self.assertRaises(verify.FixtureError) as raised:
                        verify.verify_challenge_response(doc["challengeResponse"], vs)
                    self.assertEqual(str(raised.exception), f"verifierState.{member}: {kind}, not an array")


@unittest.skipUnless(hasattr(time, "tzset"), "time.tzset is not available on this platform")
class NoUtcOffsetTest(unittest.TestCase):
    """A date and time with no UTC offset, or a date alone, is not RFC 3339,
    and a fixture holding one prints the same lines under each of
    TIME_ZONES. As verifierState.clockRfc3339 it is a fixture error, as a
    clockRfc3339 the verifier cannot read is. A challenge issuedAt or
    expiresAt with no UTC offset, under the shipped signature, which is
    over the same value with Z appended, is rejected as SIGNATURE_INVALID,
    and an expiresAt the verifier does not read, under a signature made
    over it as written, is rejected as CHALLENGE_EXPIRED: for each challenge
    case, the verdict and category that ../go/verify.go gives the same
    file. The cases are built from the valid fixture."""

    def setUp(self) -> None:
        self.text = VALID.read_text(encoding="utf-8")

    def assert_same_in_each_time_zone(self, text: str, gate: str, lines: str) -> None:
        """A file holding text prints gate and the file's path, then lines,
        then the summary line, under each of TIME_ZONES."""
        passed = gate == "PASS"
        summary = f"\nsummary: {int(passed)} pass, {int(not passed)} fail (1 fixtures)\n"
        for zone, hours in TIME_ZONES:
            with self.subTest(zone=zone), local_time_zone(zone):
                self.assertEqual(datetime(2026, 5, 28).astimezone().utcoffset(), timedelta(hours=hours))
                path, code, out, err = run_text(text)
                self.assertEqual(out, f"{gate}  {path}\n{lines}{summary}")
                self.assertEqual(err, "")
                self.assertEqual(code, 0 if passed else 1)

    def test_clock_with_no_utc_offset_is_a_fixture_error(self) -> None:
        for clock in ("2026-05-28T00:00:00", "2026-05-28"):
            with self.subTest(clock=clock):
                self.assert_same_in_each_time_zone(
                    edited(self.text, lambda d: d["verifierState"].update(clockRfc3339=clock)),
                    "FAIL",
                    "       fixture error: verifierState.clockRfc3339: "
                    f"cannot be read as a date-time ({clock!r} has no UTC offset)\n",
                )

    def test_challenge_timestamp_the_verifier_does_not_read_gets_the_go_verdict(self) -> None:
        with self.assertRaises(ValueError) as unread:
            verify._parse_rfc3339("tomorrow")
        bad_signature = "Ed25519 signature did not verify against the canonical 5-field payload"
        # (member, value, signed as written, category, reason)
        cases = [
            ("expiresAt", "2026-05-28T00:03:00", False, "SIGNATURE_INVALID", bad_signature),
            ("issuedAt", "2026-05-27T23:58:00", False, "SIGNATURE_INVALID", bad_signature),
            (
                "expiresAt",
                "2026-05-28T00:03:00",
                True,
                "CHALLENGE_EXPIRED",
                "challenge.expiresAt is not RFC 3339: '2026-05-28T00:03:00' has no UTC offset",
            ),
            (
                "expiresAt",
                "2026-05-28",
                True,
                "CHALLENGE_EXPIRED",
                "challenge.expiresAt is not RFC 3339: '2026-05-28' has no UTC offset",
            ),
            (
                "expiresAt",
                "tomorrow",
                True,
                "CHALLENGE_EXPIRED",
                f"challenge.expiresAt is not RFC 3339: {unread.exception}",
            ),
        ]
        for member, value, signed, category, reason in cases:

            def edit(d: dict) -> None:
                d["challengeResponse"]["challenge"][member] = value
                if signed:
                    sign_as_written(d)
                d["expected"] = {"verifyResult": "REJECT", "rejectCategory": category}

            with self.subTest(member=member, value=value, signed=signed):
                self.assert_same_in_each_time_zone(
                    edited(self.text, edit),
                    "PASS",
                    f"       expected: REJECT [{category}]\n       observed: REJECT[{category}: {reason}]\n",
                )


# Timestamps both verifiers read: the value, the UTC form the verifier puts
# in the signed payload, and whether the time is after the valid fixture's
# verifier clock, 2026-05-28T00:00:00Z. ../go/verify_test.go holds the same
# table.
READ_TIMESTAMPS = (
    ("2026-05-28T00:03:00Z", "2026-05-28T00:03:00Z", True),
    ("2026-05-28T02:33:00+02:30", "2026-05-28T00:03:00Z", True),
    ("2026-05-27T23:03:00-01:00", "2026-05-28T00:03:00Z", True),
    ("2026-05-28T00:03:00-00:00", "2026-05-28T00:03:00Z", True),
    ("2026-05-28T00:03:00.999999999Z", "2026-05-28T00:03:00Z", True),
    ("2026-05-28T00:00:00.000000001Z", "2026-05-28T00:00:00Z", True),
    # A tenth digit of the fraction is cut, which leaves the clock itself.
    ("2026-05-28T00:00:00.0000000001Z", "2026-05-28T00:00:00Z", False),
    ("2024-02-29T23:30:00-01:00", "2024-03-01T00:30:00Z", False),
    ("0000-02-29T12:00:00Z", "0000-02-29T12:00:00Z", False),
    # A UTC time outside years 1 to 9999.
    ("0001-01-01T00:00:00+01:00", "0000-12-31T23:00:00Z", False),
    ("0000-01-01T00:00:00+23:59", "-0001-12-31T00:01:00Z", False),
    ("9999-12-31T23:59:59-01:00", "10000-01-01T00:59:59Z", True),
)

FORM = "{} is not of the form YYYY-MM-DDThh:mm:ss[.fraction] followed by Z, +hh:mm or -hh:mm"

# Timestamps neither verifier reads, which each puts in the signed payload
# as written, and the message each gives, with {} standing for the value as
# the verifier quotes it (repr here, %q in Go). ../go/verify_test.go holds
# the same table.
UNREAD_TIMESTAMPS = (
    ("2026-05-28T00:03Z", FORM),
    ("2026-05-28 00:03:00Z", FORM),
    ("20260528T000300Z", FORM),
    ("2026-W22-4T00:03:00Z", FORM),
    ("2026-05-28T00:03:00+0000", FORM),
    ("2026-05-28T00:03:00+00", FORM),
    ("2026-05-28T0:03:00Z", FORM),
    ("2026-05-28T00:03:00,5Z", FORM),
    ("2026-05-28t00:03:00z", FORM),
    ("2026-05-28T00:03:00.Z", FORM),
    ("2026-05-28T00:03:00Z\n", FORM),
    ("tomorrow", FORM),
    ("", FORM),
    ("2026-05-28T00:03:00", "{} has no UTC offset"),
    ("2026-05-28", "{} has no UTC offset"),
    ("2026-13-28T00:03:00Z", "the month of {} is out of range"),
    ("2026-02-29T00:03:00Z", "the day of {} is out of range"),
    ("2026-05-28T24:00:00Z", "the hour of {} is out of range"),
    ("2026-05-28T00:60:00Z", "the minute of {} is out of range"),
    ("2026-05-28T23:59:60Z", "the second of {} is out of range"),
    ("2026-05-28T00:03:00+24:00", "the UTC offset hour of {} is out of range"),
    ("2026-05-28T00:03:00+23:60", "the UTC offset minute of {} is out of range"),
)


class TimestampTest(unittest.TestCase):
    """A timestamp is read in the RFC 3339 form both verifiers read, as the
    same UTC time, and a timestamp outside it is signed as written: each
    case in READ_TIMESTAMPS and UNREAD_TIMESTAMPS gets the verdict and
    category that ../go/verify.go gives the same file, as a challenge
    issuedAt or expiresAt under the shipped signature or under one made
    over the payload the verifier builds. The cases are built from the
    valid fixture."""

    def setUp(self) -> None:
        self.text = VALID.read_text(encoding="utf-8")

    def assert_verdict(self, edit: Callable[[dict], object], verdict: str, category: str = "", reason: str = "") -> None:
        """A copy of the valid fixture edited by edit, expecting verdict and
        category, passes with that verdict and the reason."""

        def expect(d: dict) -> None:
            edit(d)
            d["expected"] = {"verifyResult": verdict, **({"rejectCategory": category} if category else {})}

        path, code, out, err = run_text(edited(self.text, expect))
        if verdict == "ACCEPT":
            lines = (
                "       expected: ACCEPT\n       observed: ACCEPT\n"
                "       signature: ed25519=true (verified against agentDid did:opena2a:agent:agent_conformance_test_001 bound key)\n"
            )
        else:
            lines = f"       expected: REJECT [{category}]\n       observed: REJECT[{category}: {reason}]\n"
        self.assertEqual(out, f"PASS  {path}\n{lines}\nsummary: 1 pass, 0 fail (1 fixtures)\n")
        self.assertEqual((code, err), (0, ""))

    def test_each_timestamp_is_read_as_in_go(self) -> None:
        for value, utc, _ in READ_TIMESTAMPS:
            with self.subTest(value=value):
                self.assertEqual(verify._normalize_rfc3339(value), utc)
        for value, problem in UNREAD_TIMESTAMPS:
            with self.subTest(value=value):
                self.assertEqual(verify._normalize_rfc3339(value), value)
                with self.assertRaises(ValueError) as unread:
                    verify._parse_rfc3339(value)
                self.assertEqual(str(unread.exception), problem.format(repr(value)))

    def test_each_timestamp_gets_the_go_verdict(self) -> None:
        bad_signature = "Ed25519 signature did not verify against the canonical 5-field payload"
        shipped = "2026-05-28T00:03:00Z"
        cases = [(value, utc, after, "") for value, utc, after in READ_TIMESTAMPS]
        cases += [(value, value, False, problem.format(repr(value))) for value, problem in UNREAD_TIMESTAMPS]
        for value, signed, after, problem in cases:

            def set_member(member: str, sign: bool = False) -> Callable[[dict], None]:
                def edit(d: dict) -> None:
                    d["challengeResponse"]["challenge"][member] = value
                    if sign:
                        sign_as_written(d, **{member: signed})

                return edit

            with self.subTest(value=value, member="expiresAt", signature="shipped"):
                if signed == shipped:
                    self.assert_verdict(set_member("expiresAt"), "ACCEPT")
                else:
                    self.assert_verdict(set_member("expiresAt"), "REJECT", "SIGNATURE_INVALID", bad_signature)
            with self.subTest(value=value, member="issuedAt", signature="over " + signed):
                self.assert_verdict(set_member("issuedAt", sign=True), "ACCEPT")
            with self.subTest(value=value, member="expiresAt", signature="over " + signed):
                if problem:
                    reason = f"challenge.expiresAt is not RFC 3339: {problem}"
                    self.assert_verdict(set_member("expiresAt", sign=True), "REJECT", "CHALLENGE_EXPIRED", reason)
                elif after:
                    self.assert_verdict(set_member("expiresAt", sign=True), "ACCEPT")
                else:
                    reason = f"verifier clock 2026-05-28T00:00:00Z is not before challenge.expiresAt {signed}"
                    self.assert_verdict(set_member("expiresAt", sign=True), "REJECT", "CHALLENGE_EXPIRED", reason)

    def test_clock_outside_years_1_to_9999_is_read(self) -> None:
        def clock(value: str) -> Callable[[dict], None]:
            return lambda d: d["verifierState"].update(clockRfc3339=value)

        self.assert_verdict(clock("0001-01-01T00:00:00+01:00"), "ACCEPT")
        self.assert_verdict(
            clock("9999-12-31T23:59:59-01:00"),
            "REJECT",
            "CHALLENGE_EXPIRED",
            "verifier clock 10000-01-01T00:59:59Z is not before challenge.expiresAt 2026-05-28T00:03:00Z",
        )


if __name__ == "__main__":
    unittest.main()
