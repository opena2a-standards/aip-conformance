"""Reference verifier for the AIP v1.0.0-draft §5.1 challenge-response
conformance fixtures.

Walks every *.json file in a directory (or individual fixture files),
reconstructs the canonical signing payload, verifies the Ed25519
signature, and applies the AIP §5.1 step-5 checks against the fixture's
pinned verifierState.

Exit code is 0 if every fixture's observed result matches the expected
result AND the rejection category matches (when declared).

Canonical signing form (5 fields, pipe-delimited) -- MUST mirror
scripts/generate-fixtures/main.go canonicalChallengeResponsePayload
VERBATIM:

    challenge | agentDid | nonce | issuedAt | expiresAt
"""

from __future__ import annotations

import base64
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

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
    # Python's datetime.fromisoformat handles "Z" only from 3.11+.
    if s.endswith("Z"):
        s2 = s[:-1] + "+00:00"
    else:
        s2 = s
    dt = datetime.fromisoformat(s2).astimezone(timezone.utc)
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


def verify_challenge_response(cr: dict, vs: dict) -> Result:
    """Apply the AIP §5.1 step-5 checks in order. First failing check wins."""

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
    bound = _lookup_agent_binding(vs, response["agentDid"])
    if bound is None:
        return Result("REJECT", "UNTRUSTED_KEY",
                      f"response.agentDid {response['agentDid']} has no agentBinding in verifierState")
    bound_pub_hex = pub_bytes.hex()
    if bound_pub_hex != bound["publicKeyHex"]:
        return Result(
            "REJECT", "UNTRUSTED_KEY",
            f"response.publicKey does not match bound key for agentDid {response['agentDid']} "
            f"(got {bound_pub_hex[:16]}..., bound is {bound['publicKeyHex'][:16]}...)",
        )

    # (3) Challenge not expired
    clock = _parse_rfc3339(vs["clockRfc3339"])
    expires_at = _parse_rfc3339(challenge["expiresAt"])
    if not (clock < expires_at):
        return Result(
            "REJECT", "CHALLENGE_EXPIRED",
            f"verifier clock {_emit_rfc3339(clock)} is not before challenge.expiresAt {_emit_rfc3339(expires_at)}",
        )

    # (4) Nonce not in seenNonces
    seen = vs.get("seenNonces") or []
    if response["nonce"] in seen:
        return Result("REJECT", "NONCE_REPLAY",
                      "response.nonce was already seen by the verifier")

    return Result(
        verdict="ACCEPT",
        signatures_note=f"signature: ed25519=true (verified against agentDid {response['agentDid']} bound key)",
    )


def _lookup_agent_binding(vs: dict, agent_did: str) -> Optional[dict]:
    for b in vs.get("agentBindings") or []:
        if b["agentDid"] == agent_did:
            return b
    return None


def _parse_rfc3339(s: str) -> datetime:
    return datetime.fromisoformat((s[:-1] + "+00:00") if s.endswith("Z") else s).astimezone(timezone.utc)


def _emit_rfc3339(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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
    try:
        f = json.loads(path.read_text())
    except Exception as e:
        print(f"FAIL  {path}\n       parse error: {e}")
        return False

    if f.get("fixtureType") == "trustScoreComposition":
        return run_composition(path, f)
    if f.get("fixtureType") != "challengeResponse":
        print(f"SKIP  {path}\n       fixtureType={f.get('fixtureType')} (this verifier handles challengeResponse and trustScoreComposition)")
        return True

    if not f.get("challengeResponse"):
        print(f"FAIL  {path}\n       challengeResponse payload missing")
        return False

    r = verify_challenge_response(f["challengeResponse"], f["verifierState"])
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
