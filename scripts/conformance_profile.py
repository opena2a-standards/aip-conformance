#!/usr/bin/env python3
"""Generate (or verify) the machine-readable conformance profile.

`conformance.json` maps every requirement this suite tests to the fixture
that tests it and the pinned expected outcome. The requirement entries are
DERIVED from the fixtures themselves (each fixture carries its spec
references and expected block), so the profile cannot drift from the fixture
set: regeneration is deterministic and CI verifies the committed file matches.

Usage:
    python3 scripts/conformance_profile.py            # (re)write conformance.json
    python3 scripts/conformance_profile.py --check    # exit 1 if committed file is stale
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT = REPO_ROOT / "conformance.json"

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
            "coverage": "AIP §5.1 challenge-response transcript verification (Ed25519, stdlib crypto)",
        },
        {
            "language": "python",
            "path": "verifiers/python",
            "coverage": "AIP §5.1 challenge-response transcript verification (Ed25519 via cryptography)",
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


def build() -> dict:
    requirements = []
    for path in sorted((REPO_ROOT / "fixtures").glob("*.json")):
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
        return 0
    OUT.write_text(rendered)
    print(f"wrote conformance.json ({len(build()['requirements'])} requirements)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
