"""Reference verifier for the AIP v1.0.0-draft §5.1 challenge-response
conformance fixtures.

Walks every *.json file in a directory (or individual fixture files),
reconstructs the canonical signing payload, verifies the Ed25519
signature, and applies the AIP §5.1 step-5 checks against the fixture's
pinned verifierState.

Exit code is 0 if every fixture's observed result matches the expected
result AND the rejection category matches (when declared).

Outside the two §5.1 bodies (challengeResponse.challenge and
challengeResponse.response) a fixture's members are read under their exact
names (VerifierState is not verifierState), and a fixture that writes one
member name twice in the same JSON object fails to load on both verifiers,
which counts as a fail (exit code 1).

A file whose top-level value is not a JSON object fails to load. A
challengeResponse fixture that carries its challengeResponse payload and no
verifierState member, or whose verifierState holds a value that a check
reads and cannot use (FixtureError lists them), prints a FAIL block naming
the member:

    FAIL  <path>
           fixture error: verifierState.agentBindings[0].agentDid: missing

A fixture of any fixtureType whose verifierState is an object holding an
agentBindings, seenNonces or trustedIssuers that is not an array or null,
or a trustedIssuers array with an entry that is not a string, null
included, prints that FAIL block before any check runs, with the line the
Go verifier prints for it:

    FAIL  <path>
           fixture error: verifierState.seenNonces: a number, not an array

The line for an entry names the first one that is not a string, as in

           fixture error: verifierState.trustedIssuers[1]: a number, not a string

Any other error raised while checking a fixture prints a FAIL block with
the error's type and message. Each of these counts as a fail, and the run
goes on to the next fixture and prints the summary line.

Canonical signing form (5 fields, pipe-delimited) -- MUST mirror
scripts/generate-fixtures/main.go canonicalChallengeResponsePayload
VERBATIM:

    challenge | agentDid | nonce | issuedAt | expiresAt

The signed bytes are that string encoded as UTF-8, as the Go verifier
encodes it, and a fixture file is read as UTF-8, not in the locale's
encoding, as the Go verifier reads it.

A timestamp is read as a date-time in the RFC 3339 form _RFC3339_DATE_TIME
matches, the form the Go verifier reads: issuedAt and expiresAt go into the
payload as that time in UTC, written YYYY-MM-DDThh:mm:ssZ (_emit_rfc3339),
and a value not in that form goes in as written.
"""

from __future__ import annotations

import base64
import json
import re
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Iterator, List, NamedTuple, Optional, Set, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


# ---------------------------------------------------------------------------
# canonicalization (MUST match generator)
# ---------------------------------------------------------------------------

def canonical_challenge_response_payload(cb: dict) -> bytes:
    """The bytes the signature covers: the five fields of the challenge body
    cb joined by "|" and encoded as UTF-8, as the Go verifier encodes them,
    so a field holding a character outside ASCII goes in as its UTF-8
    bytes."""
    return "{}|{}|{}|{}|{}".format(
        cb["challenge"],
        cb["agentDid"],
        cb["nonce"],
        _normalize_rfc3339(cb["issuedAt"]),
        _normalize_rfc3339(cb["expiresAt"]),
    ).encode("utf-8")


def _normalize_rfc3339(s: str) -> str:
    try:
        t = _parse_rfc3339(s)
    except ValueError:
        # A value _parse_rfc3339 does not read, such as a date-time with no
        # UTC offset, goes into the payload as written, as the Go verifier's
        # normalizeRFC3339 returns a value its parseRFC3339 does not read.
        return s
    return _emit_rfc3339(t)


def _b64_no_pad_decode(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.b64decode(s + pad)


# ---------------------------------------------------------------------------
# verification
# ---------------------------------------------------------------------------

@dataclass
class Result:
    verdict: str               # "ACCEPT" or "REJECT"
    reject_category: str = ""  # populated on REJECT
    reason: str = ""
    signatures_note: str = ""


class FixtureError(ValueError):
    """A fixture member the verifier reads is missing or holds a value that
    the check reading it cannot use. str() is "<member>: <problem>", with the
    member named as _repeated_member names it, for example
    "verifierState.agentBindings[0].agentDid: missing". It is raised for a
    challengeResponse fixture that carries a challengeResponse payload and no
    verifierState member, and by the §5.1 checks for verifierState and for
    the agentBindings, publicKeyHex, clockRfc3339, seenNonces and
    trustedIssuers members they read from it and for each trustedIssuers
    entry. The checks read verifierState only after the signature check
    passes, except that an agentBindings, seenNonces or trustedIssuers that
    is not an array or null, or a trustedIssuers entry that is not a string,
    fails any fixture before its checks run (_check_verifier_state_arrays)."""

    def __init__(self, member: str, problem: str) -> None:
        super().__init__(f"{member}: {problem}")


def _json_type(value: Any) -> str:
    """The JSON type of a value json.loads returned, as a FAIL line names it."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "a boolean"
    if isinstance(value, (int, float)):
        return "a number"
    if isinstance(value, str):
        return "a string"
    if isinstance(value, list):
        return "an array"
    return "an object"


def _member(obj: dict, label: str, name: str) -> Any:
    """The value of the member name in obj, the JSON object named label (the
    empty label for the top level), or FixtureError naming the member when
    obj has no member of that name."""
    if name not in obj:
        raise FixtureError(f"{label}.{name}" if label else name, "missing")
    return obj[name]


# The five challenge fields a response echoes, in the order of the canonical
# signing form, whose challenge-body values the signature covers.
_ECHOED_FIELDS = ("challenge", "agentDid", "nonce", "issuedAt", "expiresAt")


def _string_member(body: Any, name: str) -> Any:
    """The member name of a §5.1 body as the Go verifier's encoding/json reads
    it into a string field: a missing member and null read as the empty
    string."""
    value = body.get(name)
    return "" if value is None else value


def verify_challenge_response(cr: dict, vs: Any) -> Result:
    """Apply the AIP §5.1 step-5 checks in order. First failing check wins.
    vs is the fixture's verifierState; a member of it that a check reads and
    cannot use raises FixtureError.

      1. Each of the five fields the response echoes (challenge, agentDid,
         nonce, issuedAt, expiresAt) equals the challenge body's, compared as
         written, and the signature is valid for the challenge body's
         canonical payload under publicKey
      2. publicKey matches the key bound to the challenge body's agentDid
      3. Challenge not expired (verifier clock < challenge.expiresAt)
      4. The challenge body's nonce is not in verifierState.seenNonces
      5. The challenge body's issuerDid is in verifierState.trustedIssuers"""

    response = cr["response"]
    challenge = cr["challenge"]

    # (1) The response echoes the challenge body, whose canonical payload the
    # signature covers, and the signature verifies
    for name in _ECHOED_FIELDS:
        if _string_member(response, name) != _string_member(challenge, name):
            return Result("REJECT", "SIGNATURE_INVALID", f"response.{name} does not match challenge.{name}")
    try:
        pub_bytes = _b64_no_pad_decode(response["publicKey"])
    except Exception as e:
        return Result("REJECT", "SIGNATURE_INVALID",
                      f"response.publicKey is not valid base64-no-padding: {e}")
    if len(pub_bytes) != 32:
        return Result("REJECT", "SIGNATURE_INVALID",
                      f"response.publicKey decoded to {len(pub_bytes)} bytes, expected 32")

    try:
        sig_bytes = _b64_no_pad_decode(response["signature"])
    except Exception as e:
        return Result("REJECT", "SIGNATURE_INVALID",
                      f"response.signature is not valid base64-no-padding: {e}")
    if len(sig_bytes) != 64:
        return Result("REJECT", "SIGNATURE_INVALID",
                      f"response.signature decoded to {len(sig_bytes)} bytes, expected 64")

    canonical = canonical_challenge_response_payload(challenge)
    try:
        Ed25519PublicKey.from_public_bytes(pub_bytes).verify(sig_bytes, canonical)
    except InvalidSignature:
        return Result("REJECT", "SIGNATURE_INVALID",
                      "Ed25519 signature did not verify against the canonical 5-field payload")

    # (2) publicKey matches the key bound to challenge.agentDid
    agent_did = _string_member(challenge, "agentDid")
    found = _lookup_agent_binding(vs, agent_did)
    if found is None:
        return Result("REJECT", "UNTRUSTED_KEY",
                      f"challenge.agentDid {agent_did} has no agentBinding in verifierState")
    binding, bound = found
    bound_key = _member(bound, binding, "publicKeyHex")
    bound_pub_hex = pub_bytes.hex()
    if bound_pub_hex != bound_key:
        # The reason quotes bound_key[:16]. The slice raises for null, a
        # boolean, a number or an object, so those are a fixture error; a
        # string or an array slices, and the fixture is rejected here.
        if not isinstance(bound_key, (str, list)):
            raise FixtureError(f"{binding}.publicKeyHex", f"{_json_type(bound_key)}, not a string")
        return Result(
            "REJECT", "UNTRUSTED_KEY",
            f"response.publicKey does not match bound key for agentDid {agent_did} "
            f"(got {bound_pub_hex[:16]}..., bound is {bound_key[:16]}...)",
        )

    # (3) Challenge not expired
    clock = _verifier_clock(vs)
    try:
        expires_at = _parse_rfc3339(challenge["expiresAt"])
    except ValueError as e:
        return Result("REJECT", "CHALLENGE_EXPIRED", f"challenge.expiresAt is not RFC 3339: {e}")
    if not (clock < expires_at):
        return Result(
            "REJECT", "CHALLENGE_EXPIRED",
            f"verifier clock {_emit_rfc3339(clock)} is not before challenge.expiresAt {_emit_rfc3339(expires_at)}",
        )

    # (4) challenge.nonce not in seenNonces
    if _string_member(challenge, "nonce") in _array_member(vs, "seenNonces"):
        return Result("REJECT", "NONCE_REPLAY",
                      "challenge.nonce was already seen by the verifier")

    # (5) challenge.issuerDid is a trusted issuer
    issuer_did = _string_member(challenge, "issuerDid")
    if issuer_did not in _array_member(vs, "trustedIssuers"):
        return Result("REJECT", "UNTRUSTED_ISSUER",
                      f"challenge.issuerDid {issuer_did} is not in verifierState.trustedIssuers")

    return Result(
        verdict="ACCEPT",
        signatures_note=f"signature: ed25519=true (verified against agentDid {agent_did} bound key)",
    )


def _lookup_agent_binding(vs: Any, agent_did: Any) -> Optional[Tuple[str, dict]]:
    """The first verifierState.agentBindings entry whose agentDid is
    agent_did, with the member name of that entry, or None when no entry is.
    A missing or null agentBindings holds no entry. FixtureError names the
    member when verifierState is not an object, when agentBindings is a
    value that is not an array or null, or when an entry read before one
    matches is not an object or has no agentDid."""
    if not isinstance(vs, dict):
        raise FixtureError("verifierState", f"{_json_type(vs)}, not an object")
    for i, b in enumerate(_array_member(vs, "agentBindings")):
        entry = f"verifierState.agentBindings[{i}]"
        if not isinstance(b, dict):
            raise FixtureError(entry, f"{_json_type(b)}, not an object")
        if _member(b, entry, "agentDid") == agent_did:
            return entry, b
    return None


def _array_member(vs: dict, name: str) -> list:
    """The array verifierState.name, the empty array when vs has no member
    of that name or holds null there, or FixtureError naming the member when
    it holds any other value, such as 0, false, an empty string or an empty
    object. The Go verifier's encoding/json decodes a missing or null member
    into an empty slice and fails to decode the others. For a name in
    _STRING_ARRAYS, FixtureError names the first entry of the array that is
    not a string, null included, as in verifierState.trustedIssuers[1]."""
    value = vs.get(name)
    if value is None:
        return []
    if not isinstance(value, list):
        raise FixtureError(f"verifierState.{name}", f"{_json_type(value)}, not an array")
    if name in _STRING_ARRAYS:
        for i, entry in enumerate(value):
            if not isinstance(entry, str):
                raise FixtureError(f"verifierState.{name}[{i}]", f"{_json_type(entry)}, not a string")
    return value


def _check_verifier_state_arrays(f: dict) -> None:
    """FixtureError naming the first of verifierState.agentBindings,
    verifierState.seenNonces and verifierState.trustedIssuers, in that order,
    that holds a value that is not an array or null, or the first entry of
    one of them in _STRING_ARRAYS that is not a string, each member's
    entries checked after its value, when verifierState is an object. It is
    checked before any other fixture check, for every fixtureType, as the Go
    verifier's parseFixture checks it (verifierStateArrays)."""
    vs = f.get("verifierState")
    if isinstance(vs, dict):
        for name in _VERIFIER_STATE_ARRAYS:
            _array_member(vs, name)


def _verifier_clock(vs: dict) -> _Instant:
    """verifierState.clockRfc3339 as a UTC time, or FixtureError naming the
    member when it is missing, is not a string, or is a string that
    _parse_rfc3339 cannot read."""
    clock = _member(vs, "verifierState", "clockRfc3339")
    if not isinstance(clock, str):
        raise FixtureError("verifierState.clockRfc3339", f"{_json_type(clock)}, not a string")
    try:
        return _parse_rfc3339(clock)
    except ValueError as e:
        raise FixtureError("verifierState.clockRfc3339", f"cannot be read as a date-time ({e})") from None


# The RFC 3339 date-time form both verifiers read; the Go verifier's
# rfc3339DateTime holds the same pattern. A four-digit year and two-digit
# month, day, hour, minute and second, an optional fraction of a second
# after a period, and Z or a UTC offset of the form +hh:mm or -hh:mm, with T
# and Z in upper case. Matched with fullmatch, so no trailing newline.
_RFC3339_DATE_TIME = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:\.([0-9]+))?(?:Z|([+-])([0-9]{2}):([0-9]{2}))"
)

# A date alone, or a date and time with no UTC offset (the Go verifier's
# noUTCOffset).
_NO_UTC_OFFSET = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}(?:T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?)?")

# The proleptic Gregorian calendar repeats every 400 years, which hold this
# many days. date covers years 1 to 9999; _parse_rfc3339 reads year 0, and
# its UTC offset can move a time into year -1 or 10000.
_DAYS_IN_400_YEARS = 146097
_UNIX_EPOCH_ORDINAL = date(1970, 1, 1).toordinal()


class _Instant(NamedTuple):
    """A UTC time as seconds since 1970-01-01T00:00:00Z and nanoseconds
    into the second, the parts a Go time.Time compares by; instants compare
    as tuples. A datetime cannot hold a time in year 0 or 10000."""

    seconds: int
    nanos: int


def _days_in_month(year: int, month: int) -> int:
    """The days in month (1 to 12) of year in the proleptic Gregorian
    calendar."""
    if month == 2:
        return 29 if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0) else 28
    return 30 if month in (4, 6, 9, 11) else 31


def _parse_rfc3339(s: str) -> _Instant:
    """s as a UTC time, or ValueError when s is not an RFC 3339 date-time
    in the form _RFC3339_DATE_TIME matches. The month, day (by the month
    and year), hour, minute, second and offset must be in range, which
    leaves out a second of 60, an hour of 24 and an offset hour of 24.
    The fraction is cut to nanoseconds. The Go verifier's parseRFC3339
    reads the same values as the same times, with the same messages, Go
    quoting the value as %q does."""
    m = _RFC3339_DATE_TIME.fullmatch(s)
    if m is None:
        if _NO_UTC_OFFSET.fullmatch(s):
            raise ValueError(f"{s!r} has no UTC offset")
        raise ValueError(f"{s!r} is not of the form YYYY-MM-DDThh:mm:ss[.fraction] followed by Z, +hh:mm or -hh:mm")
    year, month, day, hour, minute, second = (int(g) for g in m.group(1, 2, 3, 4, 5, 6))
    sign, offset_hour, offset_minute = m.group(8), int(m.group(9) or 0), int(m.group(10) or 0)
    for field, value, low, high in (
        ("month", month, 1, 12),
        ("day", day, 1, _days_in_month(year, month)),
        ("hour", hour, 0, 23),
        ("minute", minute, 0, 59),
        ("second", second, 0, 59),
        ("UTC offset hour", offset_hour, 0, 23),
        ("UTC offset minute", offset_minute, 0, 59),
    ):
        if not low <= value <= high:
            raise ValueError(f"the {field} of {s!r} is out of range")
    # Year 0 has the calendar of year 400.
    days = date(year or 400, month, day).toordinal() - (_DAYS_IN_400_YEARS if year == 0 else 0) - _UNIX_EPOCH_ORDINAL
    offset = (offset_hour * 60 + offset_minute) * 60 * (-1 if sign == "-" else 1)
    nanos = int((m.group(7) or "").ljust(9, "0")[:9])
    return _Instant(days * 86400 + hour * 3600 + minute * 60 + second - offset, nanos)


def _emit_rfc3339(t: _Instant) -> str:
    """t in UTC as YYYY-MM-DDThh:mm:ssZ, without its fraction of a second:
    the Go verifier's t.UTC().Format(time.RFC3339), which writes year -1 as
    -0001 and year 10000 as 10000."""
    days, second = divmod(t.seconds, 86400)
    ordinal, years = days + _UNIX_EPOCH_ORDINAL, 0
    if ordinal < 1:
        ordinal, years = ordinal + _DAYS_IN_400_YEARS, -400
    elif ordinal > date.max.toordinal():
        ordinal, years = ordinal - _DAYS_IN_400_YEARS, 400
    d = date.fromordinal(ordinal)
    year = d.year + years
    year_text = f"-{-year:04d}" if year < 0 else f"{year:04d}"
    return f"{year_text}-{d.month:02d}-{d.day:02d}T{second // 3600:02d}:{second // 60 % 60:02d}:{second % 60:02d}Z"


# ---------------------------------------------------------------------------
# fixture loading (MUST match the Go verifier's parseFixture)
# ---------------------------------------------------------------------------

# The fixture members that hold the protocol messages under test: the two §5.1
# bodies inside challengeResponse, each by the member names on its path from
# the top-level object. Their values are not walked for repeated member names;
# challengeResponse itself is fixture format, walked like the rest of the
# fixture. The Go verifier's protocolMessages holds the same paths.
_PROTOCOL_MESSAGES = (("challengeResponse", "challenge"), ("challengeResponse", "response"))

# The verifierState members that hold an array, in the order
# _check_verifier_state_arrays checks them. The Go verifier's
# verifierStateArrays holds the same names in the same order.
_VERIFIER_STATE_ARRAYS = ("agentBindings", "seenNonces", "trustedIssuers")

# The _VERIFIER_STATE_ARRAYS members whose entries must be strings. The Go
# verifier's encoding/json fails to decode an entry that is a number, a
# boolean, an array or an object into the string it reads, and decodes a
# null entry as the empty string. The Go verifier's stringArrays holds the
# same names.
_STRING_ARRAYS = frozenset({"trustedIssuers"})

# An unpaired UTF-16 surrogate, which json.loads keeps when a JSON string
# escapes one with no partner beside it ("\ud800"). The Go verifier's
# encoding/json decodes each to U+FFFD, so names that differ only there are
# one name to it; _repeated_member compares and names members the same way.
_UNPAIRED_SURROGATE = re.compile("[\ud800-\udfff]")


class _JSONObject(dict):
    """A JSON object as load_fixture reads it: the dict json.loads builds, in
    which the last occurrence of a repeated member name wins, with pairs
    holding every member in document order, repeats included."""

    pairs: List[Tuple[str, Any]]

    @classmethod
    def from_pairs(cls, pairs: List[Tuple[str, Any]]) -> _JSONObject:
        obj = cls(pairs)
        obj.pairs = pairs
        return obj


def _repeated_member(label: str, value: Any, skip: Tuple[Tuple[str, ...], ...] = ()) -> Optional[str]:
    """The first member name, in document order, that a JSON object in value
    writes twice, or None when no object repeats a name. The member is named
    object.member and array[index], and a top-level member with an empty
    label by its bare name, as the Go verifier's repeatedMember names it.
    Names are compared as encoding/json unescapes them (_UNPAIRED_SURROGATE)
    and never folded, so VerifierState does not repeat verifierState. The
    value at a path in skip, the member names that lead to it from value, is
    not walked. A skip path is compared name by name, not as the joined path,
    so a top-level member named challengeResponse.challenge is walked. Each
    path in skip holds at least one name."""
    # An explicit stack rather than recursion, so a deeply nested document
    # cannot raise RecursionError here. Each entry walks one array or object:
    # an iterator over its (index or name, value) pairs, the member names seen
    # so far (None for an array), its index or member name in the array or
    # object that holds it (None for the first entry), and the rest of each
    # skip path that begins with the member names leading to it. A path grows
    # with its nesting depth, so the walk writes out a whole path only for the
    # member it returns.
    stack: List[Tuple[Iterator[Tuple[Any, Any]], Optional[Set[str]], Any, Tuple[Tuple[str, ...], ...]]] = []

    def enter(item: Any, key: Any, rest: Tuple[Tuple[str, ...], ...]) -> None:
        if isinstance(item, list):
            stack.append((iter(enumerate(item)), None, key, rest))
        elif isinstance(item, dict):
            pairs = item.pairs if isinstance(item, _JSONObject) else item.items()
            stack.append((iter(pairs), set(), key, rest))

    enter(value, None, skip)
    while stack:
        members, seen, _, rest = stack[-1]
        step = next(members, None)
        if step is None:
            stack.pop()
            continue
        key, item = step
        if seen is None:
            if not isinstance(item, (list, dict)):
                continue  # an element that is not an array or object has no members
            enter(item, key, ())  # a skip path names members only, so it leads to no element
            continue
        name = _UNPAIRED_SURROGATE.sub(chr(0xFFFD), key)
        if name in seen:
            return _member_path(label, [entry[2] for entry in stack[1:]] + [name])
        seen.add(name)
        item_rest = tuple(path[1:] for path in rest if path[0] == name) if rest else ()
        if () not in item_rest:
            enter(item, name, item_rest)
    return None


def _member_path(label: str, keys: List[Any]) -> str:
    """label followed by each key: [index] for an array index, .name for a
    member name, or the bare name after an empty path, as the Go verifier's
    pathSegment.appendTo writes them."""
    path = label
    for key in keys:
        if isinstance(key, int):
            path += f"[{key}]"
        elif path:
            path += "." + key
        else:
            path = key
    return path


def load_fixture(path: Path) -> dict:
    """Reads a fixture file as UTF-8, as the Go verifier reads it, not in
    the locale's encoding. A JSON object outside the two §5.1 bodies that
    writes one member name twice raises ValueError naming the member: the
    verifier state, expected outcome or body it carries has no single
    reading, and json.loads would keep the later copy alone where the Go
    verifier's encoding/json keeps a member the later copy omits. Members are
    read under their exact names, as the Go verifier reads them outside the
    two bodies. A file whose top-level value is not a JSON object raises
    ValueError naming the value's JSON type."""
    f = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_JSONObject.from_pairs)
    repeated = _repeated_member("", f, _PROTOCOL_MESSAGES)
    if repeated is not None:
        raise ValueError(f"{repeated}: duplicate member name")
    if not isinstance(f, dict):
        raise ValueError(f"the top-level value is {_json_type(f)}, not an object")
    return f


# ---------------------------------------------------------------------------
# fixture walking + reporting
# ---------------------------------------------------------------------------

def collect_fixture_paths(args: List[str]) -> List[Path]:
    out: List[Path] = []
    for a in args:
        p = Path(a)
        if not p.exists():
            print(f"cannot stat {a}: no such path", file=sys.stderr)
            continue
        if p.is_dir():
            out.extend(sorted(p.glob("*.json")))
        else:
            out.append(p)
    return out


# ---------------------------------------------------------------------------
# AIP §6.1 trust-score composition (MUST match the Go verifier)
# ---------------------------------------------------------------------------

def _round4(v: float) -> float:
    return round(v * 10000) / 10000


@dataclass
class Composition:
    verdict: str               # "MEASURED" or "UNSCORED"
    score: float = 0.0
    included_weight: float = 0.0
    unscored_reason: str = ""


# AIP §6.1 included-weight threshold: below it the agent is unscored. The section
# is the one home of this number.
UNSCORED_THRESHOLD = 0.50


def compose_trust_score(payload: dict) -> Composition:
    """Apply AIP §6.1 to the fixture's factor inputs: a factor with confidence 0 or
    no score is excluded and its weight redistributed proportionally (renormalised
    over the included weight); the published value is capped at the neutral-imputed
    composite (every excluded factor scored 0.5). When the included weight is below
    the threshold the agent is unscored: no composite is published (score null),
    the reason is insufficient_data."""
    weighted_sum = 0.0
    included_weight = 0.0
    excluded_weight = 0.0
    for f in payload["factors"]:
        w = f["weight"] / 100
        if f.get("confidence", 0) <= 0 or f.get("score") is None:
            excluded_weight += w
            continue
        included_weight += w
        weighted_sum += w * f["score"] * f["confidence"]
    if _round4(included_weight) < UNSCORED_THRESHOLD:
        return Composition(
            verdict="UNSCORED",
            included_weight=_round4(included_weight),
            unscored_reason="insufficient_data",
        )
    renormalised = weighted_sum / included_weight if included_weight > 0 else 0.0
    imputed = weighted_sum + excluded_weight * 0.5
    return Composition(
        verdict="MEASURED",
        score=_round4(min(renormalised, imputed)),
        included_weight=_round4(included_weight),
    )


def run_composition(path: Path, f: dict) -> bool:
    payload = f.get("trustScoreComposition")
    exp = (f.get("expected") or {}).get("composition")
    if not payload or not exp:
        print(f"FAIL  {path}\n       trustScoreComposition payload or expected.composition missing")
        return False
    r = compose_trust_score(payload)
    expected_verdict = f["expected"]["verifyResult"]

    expected_detail = f"{expected_verdict} [scoreStatus={exp['scoreStatus']}"
    expected_detail += " score=null" if exp.get("score") is None else f" score={exp['score']:.4f}"
    expected_detail += f" includedWeight={exp['includedWeight']:.4f}"
    if exp.get("unscoredReason"):
        expected_detail += f" unscoredReason={exp['unscoredReason']}"
    expected_detail += "]"

    if r.verdict == "UNSCORED":
        observed_detail = f"UNSCORED[score=null unscoredReason={r.unscored_reason} includedWeight={r.included_weight:.4f}]"
    else:
        observed_detail = f"MEASURED[score={r.score:.4f} includedWeight={r.included_weight:.4f}]"

    ok = r.verdict == expected_verdict and _round4(r.included_weight) == _round4(exp["includedWeight"])
    if ok and r.verdict == "MEASURED":
        ok = exp.get("score") is not None and _round4(r.score) == _round4(exp["score"])
    if ok and r.verdict == "UNSCORED":
        ok = exp.get("score") is None and (not exp.get("unscoredReason") or exp["unscoredReason"] == r.unscored_reason)
    gate = "PASS" if ok else "FAIL"
    print(f"{gate}  {path}\n       expected: {expected_detail}\n       observed: {observed_detail}")
    return ok


def run_fixture(path: Path) -> bool:
    """Checks one fixture file and prints its PASS, FAIL or SKIP block;
    returns False for FAIL. A file that fails to load, a FixtureError and any
    other error raised while checking the fixture each print a FAIL block, so
    that main goes on to the next fixture."""
    try:
        f = load_fixture(path)
    except Exception as e:
        print(f"FAIL  {path}\n       parse error: {e}")
        return False
    try:
        return _check_fixture(path, f)
    except FixtureError as e:
        print(f"FAIL  {path}\n       fixture error: {e}")
    except Exception as e:
        print(f"FAIL  {path}\n       error: {type(e).__name__}: {e}")
    return False


def _check_fixture(path: Path, f: dict) -> bool:
    """run_fixture's checks of the loaded fixture f."""
    _check_verifier_state_arrays(f)
    if f.get("fixtureType") == "trustScoreComposition":
        return run_composition(path, f)
    if f.get("fixtureType") != "challengeResponse":
        print(f"SKIP  {path}\n       fixtureType={f.get('fixtureType')} (this verifier handles challengeResponse and trustScoreComposition)")
        return True

    if not f.get("challengeResponse"):
        print(f"FAIL  {path}\n       challengeResponse payload missing")
        return False

    r = verify_challenge_response(f["challengeResponse"], _member(f, "", "verifierState"))
    expected = f["expected"]["verifyResult"]
    observed_detail = r.verdict
    if r.verdict == "REJECT":
        observed_detail = f"REJECT[{r.reject_category}: {r.reason}]"

    expected_reject_suffix = ""
    if expected == "REJECT" and f["expected"].get("rejectCategory"):
        expected_reject_suffix = f" [{f['expected']['rejectCategory']}]"

    if r.verdict != expected:
        print(f"FAIL  {path}\n       expected: {expected}{expected_reject_suffix}\n       observed: {observed_detail}")
        return False

    if expected == "REJECT":
        want_cat = f["expected"].get("rejectCategory") or ""
        if want_cat and r.reject_category != want_cat:
            print(f"FAIL  {path}\n       expected: REJECT [{want_cat}]\n       observed: REJECT [{r.reject_category}: {r.reason}]")
            return False
        want_reason = (f["expected"].get("reasonContains") or "").lower()
        if want_reason and want_reason not in r.reason.lower():
            print(f"FAIL  {path}\n       expected reason to contain: {want_reason!r}\n       observed reason: {r.reason}")
            return False

    print(f"PASS  {path}\n       expected: {expected}{expected_reject_suffix}\n       observed: {observed_detail}")
    if r.signatures_note:
        print(f"       {r.signatures_note}")
    return True


def main(argv: List[str]) -> int:
    if len(argv) < 2:
        print("usage: verify.py <fixture-dir-or-file> [...]", file=sys.stderr)
        return 2

    paths = collect_fixture_paths(argv[1:])
    if not paths:
        print("no fixtures found", file=sys.stderr)
        return 2

    pass_count = fail_count = 0
    for p in paths:
        if run_fixture(p):
            pass_count += 1
        else:
            fail_count += 1

    print(f"\nsummary: {pass_count} pass, {fail_count} fail ({len(paths)} fixtures)")
    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
