#!/usr/bin/env python3
"""Generate (or verify) the machine-readable conformance profile.

`conformance.json` maps every requirement this suite tests to the fixture
that tests it and the pinned expected outcome. The requirement entries are
DERIVED from the fixtures themselves (each fixture carries its spec
references and expected block), so the profile cannot drift from the fixture
set: regeneration is deterministic and CI verifies the committed file matches.

The verifier status rows in docs/ecosystem.md pin a `<pass> / <total> PASS`
count by hand, so both modes also compare those rows with the fixture count
and exit 1 when a row pins a different number.

Usage:
    python3 scripts/conformance_profile.py            # (re)write conformance.json
    python3 scripts/conformance_profile.py --check    # exit 1 if the committed file or a status row is stale
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT = REPO_ROOT / "conformance.json"
ECOSYSTEM = REPO_ROOT / "docs" / "ecosystem.md"

# Status cell of a verifier row in docs/ecosystem.md: `<pass> / <total> PASS`.
STATUS_RE = re.compile(r"^(\d+) / (\d+) PASS$")

# --- suite metadata (hand-maintained; everything under `requirements` is derived) ---
SUITE = {
    "$schema": "https://specs.opena2a.org/schemas/conformance-profile-v1.json",
    "suite": "aip-conformance",
    "spec": {
        "id": "AIP",
        "name": "Agent Identity Protocol",
        "version": "1.0.0-draft",
        "ref": "https://github.com/opena2a-standards/agent-identity-protocol/blob/main/AIP-SPEC.md",
    },
    "fixtureManifest": "MANIFEST.sha256",
    "verifiers": [
        {
            "language": "go",
            "path": "verifiers/go",
            "coverage": "AIP §5.1 challenge-response transcript verification (Ed25519, stdlib crypto) and §6.1 trust-score composition (unscored state, redistribution, anti-gaming ceiling)",
        },
        {
            "language": "python",
            "path": "verifiers/python",
            "coverage": "AIP §5.1 challenge-response transcript verification (Ed25519 via cryptography) and §6.1 trust-score composition (unscored state, redistribution, anti-gaming ceiling)",
        },
    ],
    "coveredTransitively": [
        {
            "specSection": "§6.4 W3C Verifiable Credential AgentTrustCredential",
            "via": "https://github.com/opena2a-standards/atx-conformance",
            "note": "ATX is the agent-specific VC that ATP §4.6 carves out; no fixtures in this repo exercise §6.4 directly",
        },
        {
            "specSection": "§5 signed /authorize response",
            "via": "https://github.com/opena2a-standards/atp-conformance",
            "note": "same canonical signing form and Ed25519/hybrid path as the ATP trust proof",
        },
    ],
    "notCovered": [
        {
            "item": "§4 signed capability grant artifact",
            "reason": "canonical form underspecified in AIP v1.0.0-draft; fixtures require spec work first",
        },
        {
            "item": "runtime surfaces (authorization enforcement, audit-log emission, drift detection)",
            "reason": "not byte-stable artifacts; out of scope for an offline fixture suite",
        },
    ],
}


def fixture_paths() -> list[Path]:
    return sorted((REPO_ROOT / "fixtures").glob("*.json"))


def build() -> dict:
    requirements = []
    for path in fixture_paths():
        fx = json.loads(path.read_text())
        expected = fx["expected"]
        outcome = expected["verifyResult"]
        if expected.get("rejectCategory"):
            outcome = f"REJECT[{expected['rejectCategory']}]"
        requirements.append(
            {
                "fixture": f"fixtures/{path.name}",
                "name": fx["name"],
                "fixtureType": fx.get("fixtureType", "challengeResponse"),
                "level": "MUST",
                "specRefs": fx["spec"],
                "expected": outcome,
                "description": fx["description"],
            }
        )
    profile = dict(SUITE)
    profile["requirements"] = requirements
    return profile


def verifier_status_drift() -> list[str]:
    """Compare the verifier status rows in docs/ecosystem.md with the fixture set.

    Each verifier in SUITE has a row in the implementations table whose
    Implementation cell names the verifier path and says `(this repo)`, and
    whose Status cell reads `<pass> / <total> PASS`. CI runs every verifier
    over every fixture and fails on any FAIL line, so the only current value
    for that cell is `N / N PASS` with N the number of fixtures. Returns one
    message per missing row or per row that pins a different number.
    """
    expected = len(fixture_paths())
    if not ECOSYSTEM.exists():
        return ["docs/ecosystem.md missing"]
    status_by_path: dict[str, str] = {}
    for line in ECOSYSTEM.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 3 or "(this repo)" not in cells[0]:
            continue
        for verifier in SUITE["verifiers"]:
            if verifier["path"] in cells[0]:
                status_by_path[verifier["path"]] = cells[2]
    problems = []
    for verifier in SUITE["verifiers"]:
        path = verifier["path"]
        status = status_by_path.get(path)
        if status is None:
            problems.append(f"docs/ecosystem.md: no status row for {path}")
            continue
        match = STATUS_RE.match(status)
        if not match or int(match.group(1)) != expected or int(match.group(2)) != expected:
            problems.append(
                f"docs/ecosystem.md: {path} status reads {status!r}; "
                f"the fixture set has {expected} fixtures, so the row must read "
                f"'{expected} / {expected} PASS'"
            )
    return problems


def main() -> int:
    rendered = json.dumps(build(), indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        if not OUT.exists():
            print("conformance.json missing; run scripts/conformance_profile.py")
            return 1
        if OUT.read_text() != rendered:
            print("conformance.json is stale; run scripts/conformance_profile.py")
            return 1
        print("conformance.json is current")
    else:
        OUT.write_text(rendered)
        print(f"wrote conformance.json ({len(build()['requirements'])} requirements)")
    drift = verifier_status_drift()
    for problem in drift:
        print(problem)
    if drift:
        return 1
    print(
        "docs/ecosystem.md verifier status rows match the fixture set "
        f"({len(fixture_paths())} fixtures)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
