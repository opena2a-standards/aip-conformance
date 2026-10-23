"""Reference verifier for the AIP v1.0.0-draft §5.1 challenge-response
conformance fixtures.

Walks every *.json file in a directory (or individual fixture files),
reconstructs the canonical signing payload, verifies the Ed25519
signature, and applies the AIP §5.1 step-5 checks against the fixture's
pinned verifierState.

Exit code is 0 if every fixture's observed result matches the expected
result AND the rejection category matches (when declared).

Outside challengeResponse a fixture's members are read under their exact
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

Any other error raised while checking a fixture prints a FAIL block with
the error's type and message. Each of these counts as a fail, and the run
goes on to the next fixture and prints the summary line.

Canonical signing form (5 fields, pipe-delimited) -- MUST mirror
scripts/generate-fixtures/main.go canonicalChallengeResponsePayload
VERBATIM:

    challenge | agentDid | nonce | issuedAt | expiresAt
"""

from __future__ import annotations

import base64
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, List, Optional, Set, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


# ---------------------------------------------------------------------------
# canonicalization (MUST match generator)
# ---------------------------------------------------------------------------

def canonical_challenge_response_payload(cb: dict) -> bytes:
    return "{}|{}|{}|{}|{}".format(
        cb["challenge"],
        cb["agentDid"],
        cb["nonce"],
        _normalize_rfc3339(cb["issuedAt"]),
        _normalize_rfc3339(cb["expiresAt"]),
    ).encode("ascii")


def _normalize_rfc3339(s: str) -> str:
    try:
        dt = _parse_rfc3339(s)
    except ValueError:
        # A value _parse_rfc3339 does not read, such as a date-time with no
        # UTC offset, goes into the payload as written, as the Go verifier's
        # normalizeRFC3339 returns a value time.Parse does not read.
        return s
    # Re-emit as RFC 3339 with Z suffix (no microseconds), matching Go's
    # time.Format(time.RFC3339) on a UTC time.
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


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
    the agentBindings, publicKeyHex, clockRfc3339 and seenNonces members
    they read from it. The checks read verifierState only after the
    signature check passes."""

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


def verify_challenge_response(cr: dict, vs: Any) -> Result:
    """Apply the AIP §5.1 step-5 checks in order. First failing check wins.
    vs is the fixture's verifierState; a member of it that a check reads and
    cannot use raises FixtureError."""

    response = cr["response"]
    challenge = cr["challenge"]

    # (1) Signature verification
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

    # (2) publicKey matches bound key for response.agentDid
    found = _lookup_agent_binding(vs, response["agentDid"])
    if found is None:
        return Result("REJECT", "UNTRUSTED_KEY",
                      f"response.agentDid {response['agentDid']} has no agentBinding in verifierState")
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
            f"response.publicKey does not match bound key for agentDid {response['agentDid']} "
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

    # (4) Nonce not in seenNonces
    seen = vs.get("seenNonces") or []
    try:
        replayed = response["nonce"] in seen
    except TypeError:
        # The lookup raises when seenNonces is true or a number other than
        # 0, a non-empty string and the nonce is not a string, or a
        # non-empty object and the nonce is an array or an object.
        raise FixtureError("verifierState.seenNonces", f"{_json_type(seen)}, not an array") from None
    if replayed:
        return Result("REJECT", "NONCE_REPLAY",
                      "response.nonce was already seen by the verifier")

    return Result(
        verdict="ACCEPT",
        signatures_note=f"signature: ed25519=true (verified against agentDid {response['agentDid']} bound key)",
    )


def _lookup_agent_binding(vs: Any, agent_did: Any) -> Optional[Tuple[str, dict]]:
    """The first verifierState.agentBindings entry whose agentDid is
    agent_did, with the member name of that entry, or None when no entry is.
    An agentBindings that Python reads as false (missing, null, false, 0, or
    an empty string, array or object) holds no entry. FixtureError names the
    member when verifierState is not an object, when agentBindings is any
    other value that is not an array, or when an entry read before one
    matches is not an object or has no agentDid."""
    if not isinstance(vs, dict):
        raise FixtureError("verifierState", f"{_json_type(vs)}, not an object")
    bindings = vs.get("agentBindings") or []
    if not isinstance(bindings, list):
        raise FixtureError("verifierState.agentBindings", f"{_json_type(bindings)}, not an array")
    for i, b in enumerate(bindings):
        entry = f"verifierState.agentBindings[{i}]"
        if not isinstance(b, dict):
            raise FixtureError(entry, f"{_json_type(b)}, not an object")
        if _member(b, entry, "agentDid") == agent_did:
            return entry, b
    return None


def _verifier_clock(vs: dict) -> datetime:
    """verifierState.clockRfc3339 as a UTC datetime, or FixtureError naming
    the member when it is missing, is not a string, or is a string that
    _parse_rfc3339 cannot read."""
    clock = _member(vs, "verifierState", "clockRfc3339")
    if not isinstance(clock, str):
        raise FixtureError("verifierState.clockRfc3339", f"{_json_type(clock)}, not a string")
    try:
        return _parse_rfc3339(clock)
    except (ValueError, OverflowError) as e:
        raise FixtureError("verifierState.clockRfc3339", f"cannot be read as a date-time ({e})") from None


def _parse_rfc3339(s: str) -> datetime:
    """s as a UTC datetime, or ValueError when datetime.fromisoformat does
    not read s or s has no UTC offset. fromisoformat reads a date and time
    with no offset, or a date alone, as a naive datetime, which astimezone
    would take to be in the machine's local time zone. RFC 3339 requires
    the offset, and the Go verifier's time.Parse does not read such a
    value."""
    # Python's datetime.fromisoformat handles "Z" only from 3.11+.
    dt = datetime.fromisoformat((s[:-1] + "+00:00") if s.endswith("Z") else s)
    if dt.tzinfo is None:
        raise ValueError(f"{s!r} has no UTC offset")
    return dt.astimezone(timezone.utc)


def _emit_rfc3339(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# fixture loading (MUST match the Go verifier's parseFixture)
# ---------------------------------------------------------------------------

# The fixture member that holds the protocol messages under test. Its value is
# not walked for repeated member names. The Go verifier's protocolMessages
# holds the same name.
_PROTOCOL_MESSAGES = frozenset({"challengeResponse"})

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


def _repeated_member(label: str, value: Any, skip: frozenset = frozenset()) -> Optional[str]:
    """The first member name, in document order, that a JSON object in value
    writes twice, or None when no object repeats a name. The member is named
    object.member and array[index], and a top-level member with an empty
    label by its bare name, as the Go verifier's repeatedMember names it.
    Names are compared as encoding/json unescapes them (_UNPAIRED_SURROGATE)
    and never folded, so VerifierState does not repeat verifierState. The
    value of a member whose path is in skip is not walked."""
    # An explicit stack rather than recursion, so a deeply nested document
    # cannot raise RecursionError here. Each entry walks one array or object:
    # an iterator over its (index or name, value) pairs, the member names seen
    # so far (None for an array), its piece of the path (label for the first
    # entry, then [index], .name, or the bare name after an empty path), and
    # its path cut to one character more than the longest path in skip, which
    # is enough to tell whether the path is empty and whether skip holds it.
    # A path grows with its nesting depth, so the walk joins the pieces on the
    # stack into a whole path only for the member it returns.
    longest = max(map(len, skip), default=0)
    stack: List[Tuple[Iterator[Tuple[Any, Any]], Optional[Set[str]], str, str]] = []

    def enter(item: Any, piece: str, head: str) -> None:
        if isinstance(item, list):
            stack.append((iter(enumerate(item)), None, piece, head))
        elif isinstance(item, dict):
            pairs = item.pairs if isinstance(item, _JSONObject) else item.items()
            stack.append((iter(pairs), set(), piece, head))

    enter(value, label, label[: longest + 1])
    while stack:
        members, seen, _, head = stack[-1]
        step = next(members, None)
        if step is None:
            stack.pop()
            continue
        key, item = step
        if seen is None:
            if not isinstance(item, (list, dict)):
                continue  # an element that is not an array or object has no members
            piece = f"[{key}]"
        else:
            name = _UNPAIRED_SURROGATE.sub(chr(0xFFFD), key)
            piece = f".{name}" if head else name
            if name in seen:
                return "".join(entry[2] for entry in stack) + piece
            seen.add(name)
        item_head = head if len(head) > longest else (head + piece)[: longest + 1]
        if item_head not in skip:
            enter(item, piece, item_head)
    return None


def load_fixture(path: Path) -> dict:
    """Reads a fixture file. A JSON object outside the value of
    challengeResponse that writes one member name twice raises ValueError
    naming the member: the verifier state or expected outcome it carries has
    no single reading, and json.loads would keep the later copy alone where
    the Go verifier's encoding/json keeps a member the later copy omits.
    Members are read under their exact names, as the Go verifier reads them
    outside challengeResponse. A file whose top-level value is not a JSON
    object raises ValueError naming the value's JSON type."""
    f = json.loads(path.read_text(), object_pairs_hook=_JSONObject.from_pairs)
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
