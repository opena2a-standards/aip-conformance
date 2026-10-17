#!/usr/bin/env python3
"""Generate (or verify) the machine-readable conformance profile.

`conformance.json` maps every requirement this suite tests to the fixture
that tests it and the pinned expected outcome. The requirement entries are
DERIVED from the fixtures themselves (each fixture carries its spec
references and expected block), so the profile cannot drift from the fixture
set: regeneration is deterministic and CI verifies the committed file matches.

Two kinds of row in docs/ecosystem.md pin numbers by hand: the verifier
status rows pin a `<pass> / <total> PASS` count, and this repository's row in
the sibling-repositories table pins the suite version, a fixture count per
spec section and a verifier count. Both modes also compare those rows with
the fixture set, the verifier list and the version README.md declares on its
status line, and exit 1 when a row pins a different value.

Usage:
    python3 scripts/conformance_profile.py            # (re)write conformance.json
    python3 scripts/conformance_profile.py --check    # exit 1 if the committed file or an ecosystem.md row is stale
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT = REPO_ROOT / "conformance.json"
ECOSYSTEM = REPO_ROOT / "docs" / "ecosystem.md"
README = REPO_ROOT / "README.md"

# Status cell of a verifier row in docs/ecosystem.md: `<pass> / <total> PASS`.
STATUS_RE = re.compile(r"^(\d+) / (\d+) PASS$")
# The suite version README.md declares on its status line: `**Status: vX.Y`.
README_VERSION_RE = re.compile(r"\*\*Status: v(\d+(?:\.\d+)+)")
# The spec section a fixture's spec reference opens with: `§X.Y ...`.
SECTION_RE = re.compile(r"^§(\d+(?:\.\d+)*)")
# The values the sibling-repositories row pins in its Status cell: the
# version it opens with, each `<count> §X.Y` fixture group, `<count> verifiers`.
SIBLING_VERSION_RE = re.compile(r"^v(\d+(?:\.\d+)+):")
SIBLING_GROUP_RE = re.compile(r"(?<![\d.])(\d+) §(\d+(?:\.\d+)*)")
SIBLING_VERIFIERS_RE = re.compile(r"(?<![\d.])(\d+) verifiers?\b")

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


def section_key(section: str) -> tuple[int, ...]:
    return tuple(int(part) for part in section.split("."))


def fixture_sections() -> dict[str, int]:
    """Count the fixtures per spec section, read from each fixture's spec references.

    A fixture counts once for every distinct `§X.Y` its references open
    with. The result is ordered by section number.
    """
    counts: dict[str, int] = {}
    for path in fixture_paths():
        fx = json.loads(path.read_text())
        sections = set()
        for ref in fx["spec"]:
            match = SECTION_RE.match(ref["section"])
            if match:
                sections.add(match.group(1))
        for section in sections:
            counts[section] = counts.get(section, 0) + 1
    return {s: counts[s] for s in sorted(counts, key=section_key)}


def describe_groups(groups: dict[str, int]) -> str:
    if not groups:
        return "no fixture group"
    return " and ".join(
        f"{groups[s]} §{s} fixtures" for s in sorted(groups, key=section_key)
    )


def readme_version() -> str | None:
    """Return the suite version README.md declares on its status line, or None."""
    if not README.exists():
        return None
    match = README_VERSION_RE.search(README.read_text(encoding="utf-8"))
    return match.group(1) if match else None


def sibling_row_drift() -> list[str]:
    """Compare this repository's sibling-repositories row in docs/ecosystem.md with the tree.

    The row whose Repo cell reads `aip-conformance (this repo)` pins, by
    hand, the suite version it opens with (`vX.Y:`), one `<count> §X.Y`
    fixture group per spec section, and `<count> verifiers`. The version
    must be the one README.md declares on its `**Status:` line, the groups
    must be exactly the sections the fixtures cite with their fixture
    counts, and the verifier count must equal the number of verifiers in
    SUITE. Returns one message per missing row or per pinned value that
    differs.
    """
    if not ECOSYSTEM.exists():
        return ["docs/ecosystem.md missing"]
    repo_cell = f"{SUITE['suite']} (this repo)"
    status = None
    for line in ECOSYSTEM.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) == 3 and cells[0].replace("`", "") == repo_cell:
            status = cells[2]
    if status is None:
        return [f"docs/ecosystem.md: no sibling-repositories row for {repo_cell}"]

    problems = []
    declared = readme_version()
    if declared is None:
        problems.append("README.md: no `**Status: vX.Y` line to take the suite version from")
    else:
        match = SIBLING_VERSION_RE.match(status)
        pinned = match.group(1) if match else None
        if pinned != declared:
            problems.append(
                f"docs/ecosystem.md: {repo_cell} row pins "
                f"{'v' + pinned if pinned else 'no version'}; README.md declares "
                f"v{declared}, so the row must open with 'v{declared}:'"
            )

    expected_groups = fixture_sections()
    pinned_groups = {
        section: int(count) for count, section in SIBLING_GROUP_RE.findall(status)
    }
    if pinned_groups != expected_groups:
        problems.append(
            f"docs/ecosystem.md: {repo_cell} row pins {describe_groups(pinned_groups)}; "
            f"the fixture set has {describe_groups(expected_groups)}"
        )

    verifiers = len(SUITE["verifiers"])
    match = SIBLING_VERIFIERS_RE.search(status)
    if match is None or int(match.group(1)) != verifiers:
        problems.append(
            f"docs/ecosystem.md: {repo_cell} row pins "
            f"{match.group(0) if match else 'no verifier count'}; "
            f"the suite has {verifiers} verifiers"
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
    drift = verifier_status_drift() + sibling_row_drift()
    for problem in drift:
        print(problem)
    if drift:
        return 1
    print(
        "docs/ecosystem.md verifier status rows and sibling row match the fixture set "
        f"({len(fixture_paths())} fixtures) and README.md (v{readme_version()})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
