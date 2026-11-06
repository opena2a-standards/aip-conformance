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

The other rows of the sibling-repositories table describe suites this
repository holds no copy of, so no count they pin can be checked here. Both
modes exit 1 when one of those rows holds a standalone number followed, in
the same clause, by `fixtures` or `verifiers` (`8 fixtures`, `25 conformance
fixtures`, `2 verifiers`; PINNED_COUNT_RE has the exact form).

Three places cite the AIP spec version by hand: README.md, the `AIP spec`
row of the table in docs/versioning.md, and the Spec cell of this
repository's row in the sibling-repositories table. Both modes compare each
with `spec.version`, the version this script writes to conformance.json, and
exit 1 when one names another version, when README.md holds no citation,
when docs/versioning.md has no `AIP spec` row, or when that Spec cell cites
no version (AIP_VERSION_RE has a citation's exact form).

The spec text is not part of this repository, and neither mode reads it
unless `--spec-src DIR` names a checkout of the AIP spec repository. With
it, both modes also read each line of DIR/AIP-SPEC.md that opens with
`**Version:**`, and exit 1 when one declares a version other than
`spec.version` or names no version, when no line opens with `**Version:**`,
or when DIR holds no AIP-SPEC.md.

Usage:
    python3 scripts/conformance_profile.py            # (re)write conformance.json
    python3 scripts/conformance_profile.py --check    # exit 1 if the committed file, an ecosystem.md row or a cited AIP spec version is stale
    python3 scripts/conformance_profile.py --check --spec-src DIR    # also exit 1 if DIR/AIP-SPEC.md declares a version other than spec.version
    python3 scripts/conformance_profile.py --help     # print this help and exit; writes nothing

An unrecognized argument also writes nothing: it prints the usage line and
an error to stderr and exits 2.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT = REPO_ROOT / "conformance.json"
ECOSYSTEM = REPO_ROOT / "docs" / "ecosystem.md"
VERSIONING = REPO_ROOT / "docs" / "versioning.md"
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
# The heading of the sibling-repositories table in docs/ecosystem.md.
SIBLINGS_HEADING = "## Sibling repositories"
# A fixture or verifier count in another sibling's row: a number that does
# not continue a word, path, hyphenated name, `§X.Y` reference or version,
# followed by `fixtures` or `verifiers` before the next comma, semicolon,
# parenthesis or cell border.
PINNED_COUNT_RE = re.compile(
    r"(?<![\w.§/-])\d+[^,;()|]*?\b(?:fixtures?|verifiers?)\b", re.IGNORECASE
)
# A markdown link, reduced to its text when a row's Repo cell is named.
LINK_RE = re.compile(r"\[([^\]]*)\]\([^)]*\)")
# A version as a citation names one: a number followed by parts that each
# open with `.`, `-` or `+` (`1.0.0-draft`, `1.2`, `1.0.0-rc.1`), so
# punctuation that ends the sentence or the link is not read into it.
VERSION = r"\d+(?:[.+-][0-9A-Za-z]+)*"
# An AIP spec version citation in README.md or in a Spec cell: `AIP vX.Y.Z`,
# also written `(AIP) vX.Y.Z`, `AIP-SPEC vX.Y.Z`, `AIP spec vX.Y.Z` or
# `AIP specification vX.Y.Z`, with any whitespace before `spec` and the `v`.
AIP_VERSION_RE = re.compile(rf"\bAIP(?:\)|-SPEC|\s+spec(?:ification)?)?\s+v({VERSION})")
# The Component cell of the AIP spec row in the docs/versioning.md table.
VERSIONING_COMPONENT = "AIP spec"
# The file of a checkout of the AIP spec repository that holds the spec text,
# and the line it declares that text's version on: `**Version:** X.Y.Z`.
SPEC_FILE = "AIP-SPEC.md"
SPEC_VERSION_PREFIX = "**Version:**"
SPEC_VERSION_LINE_RE = re.compile(rf"{re.escape(SPEC_VERSION_PREFIX)}[ \t]+({VERSION})")

# --- suite metadata (hand-maintained; everything under `requirements` is derived) ---
SUITE = {
    "$schema": "https://specs.opena2a.org/schemas/conformance-profile-v1.json",
    "suite": "aip-conformance",
    "spec": {
        "id": "AIP",
        "name": "Agent Identity Protocol",
        "version": "1.2.0-draft",
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
            "reason": "canonical form underspecified in AIP v1.2.0-draft; fixtures require spec work first",
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
    for that cell is `N / N PASS` with N the number of fixtures. Every such
    row is compared, so a second row for the same verifier cannot hide a
    stale one. Returns one message per missing row or per row that pins a
    different number.
    """
    expected = len(fixture_paths())
    if not ECOSYSTEM.exists():
        return ["docs/ecosystem.md missing"]
    rows_by_path: dict[str, list[tuple[int, str]]] = {
        verifier["path"]: [] for verifier in SUITE["verifiers"]
    }
    for lineno, line in enumerate(ECOSYSTEM.read_text(encoding="utf-8").splitlines(), 1):
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 3 or "(this repo)" not in cells[0]:
            continue
        for path, rows in rows_by_path.items():
            if path in cells[0]:
                rows.append((lineno, cells[2]))
    problems = []
    for path, rows in rows_by_path.items():
        if not rows:
            problems.append(f"docs/ecosystem.md: no status row for {path}")
        for lineno, status in rows:
            match = STATUS_RE.match(status)
            if not match or int(match.group(1)) != expected or int(match.group(2)) != expected:
                problems.append(
                    f"docs/ecosystem.md:{lineno}: {path} status reads {status!r}; "
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


def other_sibling_row_counts() -> list[str]:
    """Report the fixture and verifier counts the other sibling rows pin.

    Every row of the sibling-repositories table in docs/ecosystem.md other
    than `aip-conformance (this repo)` describes a suite this repository
    holds no copy of, so nothing here can tell whether a count in that row
    is current. Such a row pins no count: it names the sibling's verifiers
    and leaves the fixture count to the sibling's README. Returns one
    message per row that holds a count PINNED_COUNT_RE matches, and one if
    the table's heading is missing.
    """
    if not ECOSYSTEM.exists():
        return ["docs/ecosystem.md missing"]
    repo_cell = f"{SUITE['suite']} (this repo)"
    in_section = found = False
    problems = []
    for lineno, line in enumerate(ECOSYSTEM.read_text(encoding="utf-8").splitlines(), 1):
        if line.startswith("## "):
            in_section = line.strip() == SIBLINGS_HEADING
            found = found or in_section
            continue
        if not in_section or not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        name = LINK_RE.sub(r"\1", cells[0]).replace("`", "")
        if name == repo_cell:
            continue
        counts = [match.group(0) for match in PINNED_COUNT_RE.finditer(line)]
        if counts:
            problems.append(
                f"docs/ecosystem.md:{lineno}: {name} row pins "
                f"{', '.join(repr(count) for count in counts)}; this repository holds "
                "no copy of that suite to check a count against, so the row must pin "
                "none: name its verifiers and leave the fixture count to its README"
            )
    if not found:
        problems.append(f"docs/ecosystem.md: no '{SIBLINGS_HEADING}' section")
    return problems


def table_rows(doc: Path) -> list[tuple[int, list[str]]]:
    """Return the line number and the stripped cells of each table row in `doc`."""
    rows = []
    for lineno, line in enumerate(doc.read_text(encoding="utf-8").splitlines(), 1):
        if line.startswith("|"):
            rows.append((lineno, [cell.strip() for cell in line.strip().strip("|").split("|")]))
    return rows


def spec_version_drift() -> list[str]:
    """Compare the AIP spec version the docs cite with the one conformance.json pins.

    SUITE["spec"]["version"] is written to conformance.json as `spec.version`.
    Three places cite that version by hand:

    - README.md: each citation AIP_VERSION_RE matches must name it, and the
      file must hold at least one.
    - docs/versioning.md: each table row whose Component cell reads
      `AIP spec` must have a Version cell that reads `v<version>` and nothing
      else, and the file must hold at least one such row.
    - docs/ecosystem.md: in each row whose Repo cell reads
      `aip-conformance (this repo)`, the Spec cell must hold at least one
      citation and each must name it. When the file or the row is missing,
      sibling_row_drift reports that and this function adds nothing.

    Returns one message per citation or Version cell that names another
    version, and one per place that cites none. A pinned version that is
    not of the form VERSION could be named by no citation, so it is reported
    alone and nothing is compared.
    """
    pinned = SUITE["spec"]["version"]
    if not re.fullmatch(VERSION, pinned):
        return [
            f"scripts/conformance_profile.py: SUITE pins spec.version {pinned!r}, which no "
            "citation can name: a citation is read as a number followed by parts that "
            "each open with '.', '-' or '+', as in '1.0.0-draft'"
        ]
    pins = f"conformance.json pins spec.version {pinned}"
    problems = []

    text = README.read_text(encoding="utf-8") if README.exists() else ""
    citations = list(AIP_VERSION_RE.finditer(text))
    if not citations:
        problems.append(
            f"README.md: no 'AIP vX.Y.Z' citation; {pins}, "
            f"so the README must cite 'AIP v{pinned}'"
        )
    for match in citations:
        if match.group(1) != pinned:
            lineno = text.count("\n", 0, match.start(1)) + 1
            problems.append(
                f"README.md:{lineno}: cites AIP v{match.group(1)}; {pins}, "
                f"so the citation must read 'v{pinned}'"
            )

    if not VERSIONING.exists():
        problems.append("docs/versioning.md missing")
    else:
        version_cells = [
            (lineno, cells[1])
            for lineno, cells in table_rows(VERSIONING)
            if len(cells) >= 2 and cells[0] == VERSIONING_COMPONENT
        ]
        if not version_cells:
            problems.append(
                f"docs/versioning.md: no '{VERSIONING_COMPONENT}' row; {pins}, so the "
                f"version pinning table needs the row '{VERSIONING_COMPONENT} | v{pinned}'"
            )
        for lineno, cell in version_cells:
            if cell != f"v{pinned}":
                problems.append(
                    f"docs/versioning.md:{lineno}: {VERSIONING_COMPONENT} row pins {cell!r}; "
                    f"{pins}, so its Version cell must read 'v{pinned}'"
                )

    repo_cell = f"{SUITE['suite']} (this repo)"
    for lineno, cells in table_rows(ECOSYSTEM) if ECOSYSTEM.exists() else []:
        if len(cells) != 3 or cells[0].replace("`", "") != repo_cell:
            continue
        cited = AIP_VERSION_RE.findall(cells[1])
        if not cited:
            problems.append(
                f"docs/ecosystem.md:{lineno}: {repo_cell} row cites no AIP version in "
                f"its Spec cell; {pins}, so the cell must cite 'AIP v{pinned}'"
            )
        for version in cited:
            if version != pinned:
                problems.append(
                    f"docs/ecosystem.md:{lineno}: {repo_cell} row cites AIP v{version}; "
                    f"{pins}, so the citation must read 'v{pinned}'"
                )
    return problems


def spec_source_drift(spec_src: Path) -> list[str]:
    """Compare spec.version with the version a checkout of the AIP spec declares.

    `spec_src` is a checkout of the AIP spec repository. Its AIP-SPEC.md
    declares the version of its text on a line that opens with
    `**Version:**`. Every such line is read, so a second one cannot hide a
    stale one, and the version it names is read as a citation's is
    (VERSION) and compared whole with SUITE["spec"]["version"].

    Returns one message when the checkout holds no AIP-SPEC.md, when no line
    opens with `**Version:**`, and per such line that names no version or
    another version. A pinned version that is not of the form VERSION is
    reported alone by spec_version_drift, so nothing is compared here.
    """
    pinned = SUITE["spec"]["version"]
    if not re.fullmatch(VERSION, pinned):
        return []
    pins = f"conformance.json pins spec.version {pinned}"
    spec = spec_src / SPEC_FILE
    if not spec.is_file():
        return [
            f"{spec}: no such file; --spec-src names a checkout of the AIP spec "
            f"repository, whose {SPEC_FILE} declares its version on a "
            f"'{SPEC_VERSION_PREFIX}' line"
        ]
    lines = [
        (lineno, line)
        for lineno, line in enumerate(spec.read_text(encoding="utf-8").splitlines(), 1)
        if line.startswith(SPEC_VERSION_PREFIX)
    ]
    if not lines:
        return [f"{spec}: no line opens with '{SPEC_VERSION_PREFIX}'; {pins}"]
    problems = []
    for lineno, line in lines:
        match = SPEC_VERSION_LINE_RE.match(line)
        if match is None:
            problems.append(f"{spec}:{lineno}: {line!r} names no version; {pins}")
        elif match.group(1) != pinned:
            problems.append(
                f"{spec}:{lineno}: declares version {match.group(1)}; {pins}; when this "
                "checkout holds the spec text the fixtures test, SUITE in "
                f"scripts/conformance_profile.py must pin '{match.group(1)}'"
            )
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        allow_abbrev=False,
    )
    ap.add_argument(
        "--check",
        action="store_true",
        help=(
            "write nothing; exit 1 if the committed file, an ecosystem.md row or a "
            "cited AIP spec version is stale"
        ),
    )
    ap.add_argument(
        "--spec-src",
        metavar="DIR",
        type=Path,
        help=(
            "a checkout of the AIP spec repository; also exit 1 if its AIP-SPEC.md "
            "declares a version other than spec.version"
        ),
    )
    args = ap.parse_args()

    rendered = json.dumps(build(), indent=2, ensure_ascii=False) + "\n"
    if args.check:
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
    drift = (
        verifier_status_drift()
        + sibling_row_drift()
        + other_sibling_row_counts()
        + spec_version_drift()
        + (spec_source_drift(args.spec_src) if args.spec_src is not None else [])
    )
    for problem in drift:
        print(problem)
    if drift:
        return 1
    print(
        "docs/ecosystem.md verifier status rows and sibling row match the fixture set "
        f"({len(fixture_paths())} fixtures) and README.md (v{readme_version()}); "
        "the other sibling rows pin no '<n> fixtures' or '<n> verifiers' count"
    )
    print(
        "README.md, the docs/versioning.md AIP spec row and the docs/ecosystem.md "
        f"sibling row cite AIP v{SUITE['spec']['version']}, the spec.version "
        "conformance.json pins"
    )
    if args.spec_src is not None:
        print(
            f"{args.spec_src / SPEC_FILE} declares version {SUITE['spec']['version']}, "
            "the spec.version conformance.json pins"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
