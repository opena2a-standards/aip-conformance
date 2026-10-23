#!/usr/bin/env python3
"""Validate every fixture's challenge/response transcript against the vendored spec schemas.

The schemas are the machine-readable models published by agent-identity-protocol
(schemas/{challenge-body,response-body}-v1.schema.json), vendored under
schemas/vendor/agent-identity-protocol/ and byte-drift-gated in CI against the
pinned AIP_SPEC_REF.

Contract: every fixture's challengeResponse.challenge validates against the
challenge-body schema and challengeResponse.response against the response-body
schema. All current REJECT fixtures are crypto/state rejects (replay, stale
challenge, wrong key), so they are shape-valid by design; a schema failure
means fixtures and schemas have drifted apart.

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
        if doc.get("fixtureType", "challengeResponse") != "challengeResponse":
            print(f"SKIP  {path.name}: fixtureType={doc.get('fixtureType')} carries no §5.1 transcript")
            continue
        transcript = doc.get("challengeResponse")
        if not transcript or "challenge" not in transcript or "response" not in transcript:
            print(f"FAIL  {path.name}: missing challengeResponse.challenge/.response")
            failures += 1
            continue
        errs = [
            ("challenge", e) for e in v_challenge.iter_errors(transcript["challenge"])
        ] + [
            ("response", e) for e in v_response.iter_errors(transcript["response"])
        ]
        if errs:
            print(f"FAIL  {path.name}:")
            for part, err in errs:
                print(f"      {part} {err.json_path}: {err.message}")
            failures += 1
        else:
            print(f"PASS  {path.name}")

    print(f"\nsummary: {len(fixtures) - failures} pass, {failures} fail ({len(fixtures)} fixtures)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
