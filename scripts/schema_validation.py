#!/usr/bin/env python3
"""Validate every fixture's challenge/response transcript against the vendored spec schemas.

The schemas are the machine-readable models published by agent-identity-protocol
(schemas/{challenge-body,response-body}-v1.schema.json), vendored under
schemas/vendor/agent-identity-protocol/ and byte-drift-gated in CI against the
pinned AIP_SPEC_REF.

Contract: every fixture's challengeResponse.challenge validates against the
challenge-body schema and challengeResponse.response against the response-body
schema, except a fixture listed in EXEMPTIONS. A listed fixture holds a body
member whose name AIP §5.1.1 or §5.1.2 does not give the body, which the
closed schemas (additionalProperties false) refuse by construction and both
reference verifiers reject before check 1 (PARSE_ERROR); it passes only when
the one schema error it is listed with is its only error. Any other schema
failure means fixtures and schemas have drifted apart.

Every fixture also follows the reasonContains pin rule: a fixture whose
expected.verifyResult is REJECT pins a non-empty expected.reasonContains, and
a fixture of any other result carries none. A fixture that breaks it fails,
with one line for the rule.

The format keyword is checked: a member whose schema names the date-time
format must hold an RFC 3339 date-time (is_date_time). Under draft 2020-12
jsonschema checks format only through a format checker passed to it, and
its own date-time check needs a package CI does not install, so the check
is defined here. A schema that names a format FORMAT_CHECKER does not check
stops the run (exit 2) rather than leaving that format unchecked.
"""

import json
import pathlib
import re
import sys

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ImportError:
    print("error: the 'jsonschema' package is required (pip install jsonschema)")
    sys.exit(2)

ROOT = pathlib.Path(__file__).resolve().parent.parent
VENDOR = ROOT / "schemas" / "vendor" / "agent-identity-protocol"
FIXTURES = ROOT / "fixtures"

# RFC 3339 §5.6 date-time, the date-time format of JSON Schema draft 2020-12.
# The note to §5.6 lets T and Z be written in lower case.
DATE_TIME = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]+)?"
    r"(?:[Zz]|([+-])([0-9]{2}):([0-9]{2}))"
)


def is_date_time(value: object) -> bool:
    """Whether value is an RFC 3339 date-time: the §5.6 form, matched in
    full, with the month, the day for the month and year, the hour, minute
    and second, and the offset in range. A second of 60 is in range only
    where the time, moved to UTC by its offset, is 23:59, the minute in
    which RFC 3339 §5.7 places a leap second. A value that is not a string
    passes, as the format keyword applies to strings alone."""
    if not isinstance(value, str):
        return True
    m = DATE_TIME.fullmatch(value)
    if m is None:
        return False
    year, month, day, hour, minute, second = (int(g) for g in m.group(1, 2, 3, 4, 5, 6))
    sign, offset_hour, offset_minute = m.group(7), int(m.group(8) or 0), int(m.group(9) or 0)
    if month == 2:
        days = 29 if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0) else 28
    else:
        days = 30 if month in (4, 6, 9, 11) else 31
    if not (1 <= month <= 12 and 1 <= day <= days):
        return False
    if hour > 23 or minute > 59 or second > 60 or offset_hour > 23 or offset_minute > 59:
        return False
    if second == 60:
        offset = (offset_hour * 60 + offset_minute) * (-1 if sign == "-" else 1)
        return (hour * 60 + minute - offset) % (24 * 60) == 23 * 60 + 59
    return True


FORMAT_CHECKER = FormatChecker(formats=())
FORMAT_CHECKER.checks("date-time")(is_date_time)

# The fixtures that fail the closed body schemas by construction, each with
# the one schema error it is listed with: the body, the JSON path and the
# message.
EXEMPTIONS = {
    "challenge-response-case-variant-member.json": (
        "response", "$", "Additional properties are not allowed ('public\N{KELVIN SIGN}ey' was unexpected)",
    ),
    "challenge-response-undefined-member-non-ascii.json": (
        "response", "$", "Additional properties are not allowed ('\N{LATIN SMALL LETTER DOTLESS I}ssuedAt' was unexpected)",
    ),
    "challenge-response-undefined-member-ascii.json": (
        "response", "$", "Additional properties are not allowed ('issued_at' was unexpected)",
    ),
}


def pin_problem(doc: dict) -> str | None:
    """The line for a fixture that breaks the reasonContains pin rule, or
    None: a REJECT fixture pins a non-empty expected.reasonContains, and a
    fixture of any other result carries none."""
    expected = doc.get("expected") or {}
    verdict = expected.get("verifyResult")
    pinned = bool(expected.get("reasonContains"))
    if verdict == "REJECT" and not pinned:
        return "expected.verifyResult is REJECT and expected.reasonContains is missing or empty: a REJECT fixture pins the reason"
    if verdict != "REJECT" and pinned:
        return f"expected.verifyResult is {verdict} and expected.reasonContains is set: only a REJECT fixture pins a reason"
    return None


class UncheckedFormatError(Exception):
    """A vendored schema names a format FORMAT_CHECKER does not check."""


def formats_named(node: object) -> set:
    """The values of the format keywords in a schema document."""
    found = set()
    if isinstance(node, dict):
        if isinstance(node.get("format"), str):
            found.add(node["format"])
        node = list(node.values())
    if isinstance(node, list):
        for item in node:
            found |= formats_named(item)
    return found


def load(name: str) -> Draft202012Validator:
    schema = json.loads((VENDOR / name).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    unchecked = formats_named(schema) - set(FORMAT_CHECKER.checkers)
    if unchecked:
        raise UncheckedFormatError(
            f"{name} names the format {', '.join(sorted(unchecked))}, which this script does not check"
        )
    return Draft202012Validator(schema, format_checker=FORMAT_CHECKER)


def main() -> int:
    try:
        v_challenge = load("challenge-body-v1.schema.json")
        v_response = load("response-body-v1.schema.json")
    except UncheckedFormatError as e:
        print(f"error: {e}")
        return 2

    failures = 0
    fixtures = sorted(FIXTURES.glob("*.json"))
    if not fixtures:
        print("error: no fixtures found")
        return 1

    for path in fixtures:
        doc = json.loads(path.read_text(encoding="utf-8"))
        pin = pin_problem(doc)
        if doc.get("fixtureType", "challengeResponse") != "challengeResponse":
            if pin:
                print(f"FAIL  {path.name}:\n      {pin}")
                failures += 1
            else:
                print(f"SKIP  {path.name}: fixtureType={doc.get('fixtureType')} carries no §5.1 transcript")
            continue
        transcript = doc.get("challengeResponse")
        if not transcript or "challenge" not in transcript or "response" not in transcript:
            print(f"FAIL  {path.name}: missing challengeResponse.challenge/.response")
            failures += 1
            continue
        errs = [
            ("challenge", e.json_path, e.message) for e in v_challenge.iter_errors(transcript["challenge"])
        ] + [
            ("response", e.json_path, e.message) for e in v_response.iter_errors(transcript["response"])
        ]
        exemption = EXEMPTIONS.get(path.name)
        exempt = exemption is not None and errs == [exemption]
        problems = [pin] if pin else []
        if not exempt:
            problems += [f"{part} {json_path}: {message}" for part, json_path, message in errs]
            if exemption is not None:
                part, json_path, message = exemption
                problems.append(f"listed exemption, not the only error: {part} {json_path}: {message}")
        if problems:
            print(f"FAIL  {path.name}:")
            for problem in problems:
                print(f"      {problem}")
            failures += 1
        else:
            print(f"PASS  {path.name}")
            if exempt:
                part, json_path, message = exemption
                print(f"      listed exemption: {part} {json_path}: {message}")

    print(f"\nsummary: {len(fixtures) - failures} pass, {failures} fail ({len(fixtures)} fixtures)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
