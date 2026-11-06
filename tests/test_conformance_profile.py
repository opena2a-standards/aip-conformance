#!/usr/bin/env python3
"""Regression tests for scripts/conformance_profile.py: the docs/ecosystem.md
row gates, the AIP spec version gate, the --spec-src comparison and the
command-line arguments.

The gate tests write an edited copy of docs/ecosystem.md, README.md or
docs/versioning.md to a temporary directory and point the gates at the copy;
the --spec-src tests write an AIP-SPEC.md to a temporary directory and name
that directory; the command-line tests point the script's output at a
conformance.json path in a temporary directory. The tracked files are never
modified.

Usage:
    python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import contextlib
import io
import re
import sys
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import conformance_profile  # noqa: E402

GO = "verifiers/go"
ATX = "atx-conformance"
ATP = "atp-conformance"
SIBLINGS_HEADING = "## Sibling repositories"
# An AIP spec version no document in this repository cites.
OTHER_VERSION = "9.9.9-draft"


def run_check(lines: list[str], gate: Callable[[], list[str]]) -> tuple[list[str], int, str]:
    """Run one gate, then `conformance_profile.py --check`, over an edited copy of the doc."""
    with tempfile.TemporaryDirectory() as tmp:
        doc = Path(tmp) / "ecosystem.md"
        doc.write_text("\n".join(lines) + "\n", encoding="utf-8")
        out = io.StringIO()
        with mock.patch.object(conformance_profile, "ECOSYSTEM", doc), mock.patch.object(
            sys, "argv", ["conformance_profile.py", "--check"]
        ), contextlib.redirect_stdout(out):
            problems = gate()
            code = conformance_profile.main()
    return problems, code, out.getvalue()


class StatusRowGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.n = len(conformance_profile.fixture_paths())
        self.lines = conformance_profile.ECOSYSTEM.read_text(encoding="utf-8").splitlines()
        self.go_index = next(
            i
            for i, line in enumerate(self.lines)
            if GO in line and "(this repo)" in line
        )
        current = f"| {self.n} / {self.n} PASS |"
        self.assertTrue(self.lines[self.go_index].endswith(current))
        self.stale = self.n - 1
        self.stale_row = self.lines[self.go_index].replace(
            current, f"| {self.stale} / {self.stale} PASS |"
        )

    def run_gate(self, lines: list[str]) -> tuple[list[str], int, str]:
        return run_check(lines, conformance_profile.verifier_status_drift)

    def assert_stale_row_reported(self, lines: list[str], lineno: int) -> None:
        drift, code, out = self.run_gate(lines)
        self.assertEqual(len(drift), 1, drift)
        self.assertTrue(
            drift[0].startswith(
                f"docs/ecosystem.md:{lineno}: {GO} status reads "
                f"'{self.stale} / {self.stale} PASS'"
            ),
            drift[0],
        )
        self.assertEqual(code, 1)
        self.assertIn(drift[0], out)

    def test_current_doc_passes(self) -> None:
        drift, code, _ = self.run_gate(self.lines)
        self.assertEqual(drift, [])
        self.assertEqual(code, 0)

    def test_stale_duplicate_above_current_row_is_reported(self) -> None:
        lines = list(self.lines)
        lines.insert(self.go_index, self.stale_row)
        self.assert_stale_row_reported(lines, lineno=self.go_index + 1)

    def test_stale_duplicate_below_current_row_is_reported(self) -> None:
        lines = list(self.lines)
        lines.insert(self.go_index + 1, self.stale_row)
        self.assert_stale_row_reported(lines, lineno=self.go_index + 2)

    def test_missing_row_is_reported(self) -> None:
        lines = list(self.lines)
        del lines[self.go_index]
        drift, code, _ = self.run_gate(lines)
        self.assertEqual(drift, [f"docs/ecosystem.md: no status row for {GO}"])
        self.assertEqual(code, 1)


class SiblingCountGateTest(unittest.TestCase):
    """The sibling-repositories rows for other suites pin no fixture or verifier count."""

    def setUp(self) -> None:
        self.lines = conformance_profile.ECOSYSTEM.read_text(encoding="utf-8").splitlines()

    def row_index(self, repo: str) -> int:
        return next(i for i, line in enumerate(self.lines) if line.startswith(f"| [`{repo}`]"))

    def with_status(self, repo: str, status: str) -> list[str]:
        """Return the doc lines with the Status cell of `repo`'s row replaced."""
        lines = list(self.lines)
        index = self.row_index(repo)
        repo_cell, spec_cell, _ = lines[index].strip().strip("|").split("|")
        lines[index] = f"|{repo_cell}|{spec_cell}| {status} |"
        return lines

    def run_gate(self, lines: list[str]) -> tuple[list[str], int, str]:
        return run_check(lines, conformance_profile.other_sibling_row_counts)

    def assert_reported(self, lines: list[str], lineno: int, repo: str, counts: list[str]) -> None:
        problems, code, out = self.run_gate(lines)
        pinned = ", ".join(repr(count) for count in counts)
        self.assertEqual(len(problems), 1, problems)
        self.assertTrue(
            problems[0].startswith(f"docs/ecosystem.md:{lineno}: {repo} row pins {pinned};"),
            problems[0],
        )
        self.assertEqual(code, 1)
        self.assertIn(problems[0], out)

    def test_current_doc_passes(self) -> None:
        problems, code, _ = self.run_gate(self.lines)
        self.assertEqual(problems, [])
        self.assertEqual(code, 0)

    def test_stale_atx_row_is_reported(self) -> None:
        lines = self.with_status(ATX, "8 fixtures, 2 verifiers, `MANIFEST.sha256` pinned")
        self.assert_reported(lines, self.row_index(ATX) + 1, ATX, ["8 fixtures", "2 verifiers"])

    def test_stale_atp_row_is_reported(self) -> None:
        lines = self.with_status(
            ATP,
            "4 fixtures (discovery, trust-proof baseline, trust-proof hybrid, "
            "Signed Tree Head), 2 verifiers, `MANIFEST.sha256` pinned",
        )
        self.assert_reported(lines, self.row_index(ATP) + 1, ATP, ["4 fixtures", "2 verifiers"])

    def test_count_with_words_before_fixtures_is_reported(self) -> None:
        lines = self.with_status(ATX, "25 conformance fixtures, Go and Python verifiers")
        self.assert_reported(lines, self.row_index(ATX) + 1, ATX, ["25 conformance fixtures"])

    def test_count_in_verifier_summary_is_reported(self) -> None:
        lines = self.with_status(ATP, "verifiers report `summary: 14 pass, 0 fail (14 fixtures)`")
        self.assert_reported(lines, self.row_index(ATP) + 1, ATP, ["14 fixtures"])

    def test_added_sibling_row_is_checked(self) -> None:
        lines = list(self.lines)
        index = self.row_index(ATP) + 1
        lines.insert(
            index,
            "| [`example-conformance`](https://example.org/example-conformance) "
            "| Example v1 | 12 fixtures, Go and Python verifiers |",
        )
        self.assert_reported(lines, index + 1, "example-conformance", ["12 fixtures"])

    def test_this_repo_row_is_left_to_its_own_gate(self) -> None:
        row = next(
            line for line in self.lines if line.startswith("| `aip-conformance` (this repo) |")
        )
        self.assertTrue(conformance_profile.PINNED_COUNT_RE.search(row), row)
        problems, code, _ = self.run_gate(self.lines)
        self.assertEqual(problems, [])
        self.assertEqual(code, 0)

    def test_section_refs_versions_and_digests_are_not_counts(self) -> None:
        lines = self.with_status(
            ATX, "Go and Python verifiers, `MANIFEST.sha256` pinned; covers AIP §6.4 for ATX v1.1"
        )
        problems, code, _ = self.run_gate(lines)
        self.assertEqual(problems, [])
        self.assertEqual(code, 0)

    def test_missing_section_is_reported(self) -> None:
        self.assertIn(SIBLINGS_HEADING, self.lines)
        lines = ["## Sibling suites" if line == SIBLINGS_HEADING else line for line in self.lines]
        problems, code, _ = self.run_gate(lines)
        self.assertEqual(problems, [f"docs/ecosystem.md: no '{SIBLINGS_HEADING}' section"])
        self.assertEqual(code, 1)


class SpecVersionGateTest(unittest.TestCase):
    """README.md, the docs/versioning.md `AIP spec` row and this repository's
    sibling-repositories row cite the AIP spec version conformance.json pins."""

    def setUp(self) -> None:
        self.pinned = conformance_profile.SUITE["spec"]["version"]
        self.assertNotEqual(self.pinned, OTHER_VERSION)
        self.pins = f"conformance.json pins spec.version {self.pinned}"
        self.readme = conformance_profile.README.read_text(encoding="utf-8")
        self.versioning = (REPO_ROOT / "docs" / "versioning.md").read_text(encoding="utf-8")
        self.ecosystem = conformance_profile.ECOSYSTEM.read_text(encoding="utf-8")
        self.readme_citation = f"(AIP) v{self.pinned}"
        self.versioning_row = f"| AIP spec | v{self.pinned} |"
        self.sibling_cell = f"| AIP v{self.pinned} identity protocol |"
        self.assertIn(self.readme_citation, self.readme)
        self.assertEqual(self.versioning.count(self.versioning_row), 1)
        self.assertEqual(self.ecosystem.count(self.sibling_cell), 1)

    @staticmethod
    def line_of(text: str, needle: str) -> int:
        """Return the 1-based number of the line `needle` first starts on."""
        return text.count("\n", 0, text.index(needle)) + 1

    def check(self, attr: str, text: str) -> tuple[int, list[str]]:
        """Run `conformance_profile.py --check` with the script's `attr` path
        pointed at a temporary file holding `text`. Return the exit code and
        the lines printed after `conformance.json is current`."""
        with tempfile.TemporaryDirectory() as tmp:
            doc = Path(tmp) / "doc.md"
            doc.write_text(text, encoding="utf-8")
            out = io.StringIO()
            with mock.patch.object(conformance_profile, attr, doc), mock.patch.object(
                sys, "argv", ["conformance_profile.py", "--check"]
            ), contextlib.redirect_stdout(out):
                code = conformance_profile.main()
        lines = out.getvalue().splitlines()
        self.assertEqual(lines[0], "conformance.json is current")
        return code, lines[1:]

    def readme_problems(self, text: str) -> list[str]:
        """Return what the gate reports about a README.md holding `text`."""
        with tempfile.TemporaryDirectory() as tmp:
            readme = Path(tmp) / "README.md"
            readme.write_text(text, encoding="utf-8")
            with mock.patch.object(conformance_profile, "README", readme):
                problems = conformance_profile.spec_version_drift()
        return [problem for problem in problems if problem.startswith("README.md")]

    def stale_readme_message(self, text: str) -> str:
        return (
            f"README.md:{self.line_of(text, OTHER_VERSION)}: cites AIP v{OTHER_VERSION}; "
            f"{self.pins}, so the citation must read 'v{self.pinned}'"
        )

    def test_current_docs_pass(self) -> None:
        code, lines = self.check("README", self.readme)
        self.assertEqual(code, 0, lines)
        self.assertEqual(
            lines[-1],
            "README.md, the docs/versioning.md AIP spec row and the docs/ecosystem.md "
            f"sibling row cite AIP v{self.pinned}, the spec.version conformance.json pins",
        )

    def test_readme_citing_another_version_is_reported(self) -> None:
        text = self.readme.replace(self.readme_citation, f"(AIP) v{OTHER_VERSION}", 1)
        code, lines = self.check("README", text)
        self.assertEqual(code, 1, lines)
        self.assertEqual(lines, [self.stale_readme_message(text)])

    def test_a_later_citation_in_each_form_is_reported(self) -> None:
        """A citation after a current one is compared too, in each form the
        gate reads, with a line break before the version included."""
        for form in (
            "AIP v{}",
            "(AIP) v{}",
            "AIP-SPEC v{}",
            "AIP spec v{}",
            "AIP specification v{}",
            "(AIP)\nv{}",
            "AIP\nspec\nv{}",
        ):
            with self.subTest(form=form):
                text = f"{self.readme}\nThe fixtures follow {form.format(OTHER_VERSION)}.\n"
                code, lines = self.check("README", text)
                self.assertEqual(code, 1, lines)
                self.assertEqual(lines, [self.stale_readme_message(text)])

    def test_readme_with_no_citation_is_reported(self) -> None:
        text = re.sub(r"\s+v" + re.escape(self.pinned), "", self.readme)
        self.assertNotEqual(text, self.readme)
        code, lines = self.check("README", text)
        self.assertEqual(code, 1, lines)
        self.assertEqual(
            lines,
            [
                f"README.md: no 'AIP vX.Y.Z' citation; {self.pins}, "
                f"so the README must cite 'AIP v{self.pinned}'"
            ],
        )

    def test_write_mode_reports_a_stale_citation_in_each_place(self) -> None:
        """With no argument the script writes the profile, then reports the same lines."""
        readme = self.readme.replace(self.readme_citation, f"(AIP) v{OTHER_VERSION}", 1)
        versioning = self.versioning.replace(
            self.versioning_row, f"| AIP spec | v{OTHER_VERSION} |"
        )
        ecosystem = self.ecosystem.replace(
            self.sibling_cell, f"| AIP v{OTHER_VERSION} identity protocol |"
        )
        for attr, text, expected in (
            ("README", readme, self.stale_readme_message(readme)),
            (
                "VERSIONING",
                versioning,
                f"docs/versioning.md:{self.line_of(versioning, OTHER_VERSION)}: AIP spec row "
                f"pins 'v{OTHER_VERSION}'; {self.pins}, "
                f"so its Version cell must read 'v{self.pinned}'",
            ),
            (
                "ECOSYSTEM",
                ecosystem,
                f"docs/ecosystem.md:{self.line_of(ecosystem, OTHER_VERSION)}: aip-conformance "
                f"(this repo) row cites AIP v{OTHER_VERSION}; {self.pins}, "
                f"so the citation must read 'v{self.pinned}'",
            ),
        ):
            with self.subTest(attr=attr), tempfile.TemporaryDirectory() as tmp:
                doc = Path(tmp) / "doc.md"
                doc.write_text(text, encoding="utf-8")
                profile = Path(tmp) / "conformance.json"
                out = io.StringIO()
                with mock.patch.object(conformance_profile, attr, doc), mock.patch.object(
                    conformance_profile, "OUT", profile
                ), mock.patch.object(
                    sys, "argv", ["conformance_profile.py"]
                ), contextlib.redirect_stdout(out):
                    code = conformance_profile.main()
                    written = profile.exists()
                self.assertEqual(code, 1, out.getvalue())
                self.assertTrue(written)
                lines = out.getvalue().splitlines()
                self.assertTrue(lines[0].startswith("wrote conformance.json"), lines)
                self.assertEqual(lines[1:], [expected])

    def test_a_pinned_version_no_citation_can_name_is_reported_alone(self) -> None:
        for pinned in ("1.2.0-draft (2026-10-06)", "draft-04", "1.2.0-", ""):
            with self.subTest(pinned=pinned), mock.patch.dict(
                conformance_profile.SUITE["spec"], {"version": pinned}
            ):
                self.assertEqual(
                    conformance_profile.spec_version_drift(),
                    [
                        f"scripts/conformance_profile.py: SUITE pins spec.version {pinned!r}, "
                        "which no citation can name: a citation is read as a number followed "
                        "by parts that each open with '.', '-' or '+', as in '1.0.0-draft'"
                    ],
                )

    def test_missing_readme_is_reported_as_holding_no_citation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            conformance_profile, "README", Path(tmp) / "README.md"
        ):
            problems = conformance_profile.spec_version_drift()
        self.assertEqual(
            problems,
            [
                f"README.md: no 'AIP vX.Y.Z' citation; {self.pins}, "
                f"so the README must cite 'AIP v{self.pinned}'"
            ],
        )

    def test_missing_versioning_doc_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            conformance_profile, "VERSIONING", Path(tmp) / "versioning.md"
        ):
            problems = conformance_profile.spec_version_drift()
        self.assertEqual(problems, ["docs/versioning.md missing"])

    def test_missing_sibling_row_or_doc_is_left_to_the_sibling_row_gate(self) -> None:
        row_removed = "".join(
            line
            for line in self.ecosystem.splitlines(keepends=True)
            if self.sibling_cell not in line
        )
        self.assertNotEqual(row_removed, self.ecosystem)
        with tempfile.TemporaryDirectory() as tmp:
            doc = Path(tmp) / "ecosystem.md"
            doc.write_text(row_removed, encoding="utf-8")
            for path, reported in (
                (
                    doc,
                    "docs/ecosystem.md: no sibling-repositories row for "
                    "aip-conformance (this repo)",
                ),
                (Path(tmp) / "absent.md", "docs/ecosystem.md missing"),
            ):
                with self.subTest(reported=reported), mock.patch.object(
                    conformance_profile, "ECOSYSTEM", path
                ):
                    self.assertEqual(conformance_profile.spec_version_drift(), [])
                    self.assertEqual(conformance_profile.sibling_row_drift(), [reported])

    def test_a_version_is_compared_whole(self) -> None:
        """The pinned version with a part removed or a part added is another version."""
        shorter = self.pinned[: max(self.pinned.rfind(sep) for sep in ".+-")]
        self.assertTrue(shorter)
        longer = [self.pinned + more for more in (".1", "-2", "+errata", "2")]
        for cited in (shorter, *longer):
            with self.subTest(cited=cited):
                self.assertEqual(
                    self.readme_problems(f"Fixtures for AIP v{cited}\n"),
                    [
                        f"README.md:1: cites AIP v{cited}; {self.pins}, "
                        f"so the citation must read 'v{self.pinned}'"
                    ],
                )

    def test_punctuation_after_a_citation_is_not_part_of_the_version(self) -> None:
        for tail in (".", ",", ";", ":", ")", "](https://example.org).", " and later", "\n"):
            with self.subTest(tail=tail):
                self.assertEqual(
                    self.readme_problems(f"Fixtures for AIP v{self.pinned}{tail}\n"), []
                )

    def test_versioning_row_pinning_another_version_is_reported(self) -> None:
        text = self.versioning.replace(self.versioning_row, f"| AIP spec | v{OTHER_VERSION} |")
        code, lines = self.check("VERSIONING", text)
        self.assertEqual(code, 1, lines)
        self.assertEqual(
            lines,
            [
                f"docs/versioning.md:{self.line_of(text, OTHER_VERSION)}: AIP spec row pins "
                f"'v{OTHER_VERSION}'; {self.pins}, so its Version cell must read 'v{self.pinned}'"
            ],
        )

    def test_versioning_cell_holding_more_than_the_version_is_reported(self) -> None:
        text = self.versioning.replace(
            self.versioning_row, f"| AIP spec | v{self.pinned} (draft) |"
        )
        code, lines = self.check("VERSIONING", text)
        self.assertEqual(code, 1, lines)
        self.assertEqual(
            lines,
            [
                f"docs/versioning.md:{self.line_of(text, '| AIP spec |')}: AIP spec row pins "
                f"'v{self.pinned} (draft)'; {self.pins}, "
                f"so its Version cell must read 'v{self.pinned}'"
            ],
        )

    def test_stale_duplicate_versioning_row_is_reported_in_either_order(self) -> None:
        current = next(
            line for line in self.versioning.splitlines() if line.startswith(self.versioning_row)
        )
        stale = current.replace(self.versioning_row, f"| AIP spec | v{OTHER_VERSION} |")
        for pair in (f"{stale}\n{current}", f"{current}\n{stale}"):
            with self.subTest(stale_first=pair.startswith(stale)):
                text = self.versioning.replace(current, pair)
                code, lines = self.check("VERSIONING", text)
                self.assertEqual(code, 1, lines)
                self.assertEqual(
                    lines,
                    [
                        f"docs/versioning.md:{self.line_of(text, OTHER_VERSION)}: AIP spec row "
                        f"pins 'v{OTHER_VERSION}'; {self.pins}, "
                        f"so its Version cell must read 'v{self.pinned}'"
                    ],
                )

    def test_missing_versioning_row_is_reported(self) -> None:
        text = "".join(
            line
            for line in self.versioning.splitlines(keepends=True)
            if not line.startswith(self.versioning_row)
        )
        self.assertNotIn("| AIP spec |", text)
        code, lines = self.check("VERSIONING", text)
        self.assertEqual(code, 1, lines)
        self.assertEqual(
            lines,
            [
                f"docs/versioning.md: no 'AIP spec' row; {self.pins}, so the version "
                f"pinning table needs the row 'AIP spec | v{self.pinned}'"
            ],
        )

    def test_sibling_row_citing_another_version_is_reported(self) -> None:
        text = self.ecosystem.replace(
            self.sibling_cell, f"| AIP v{OTHER_VERSION} identity protocol |"
        )
        code, lines = self.check("ECOSYSTEM", text)
        self.assertEqual(code, 1, lines)
        self.assertEqual(
            lines,
            [
                f"docs/ecosystem.md:{self.line_of(text, OTHER_VERSION)}: aip-conformance "
                f"(this repo) row cites AIP v{OTHER_VERSION}; {self.pins}, "
                f"so the citation must read 'v{self.pinned}'"
            ],
        )

    def test_sibling_row_citing_no_version_is_reported(self) -> None:
        cell = "| AIP identity protocol |"
        text = self.ecosystem.replace(self.sibling_cell, cell)
        code, lines = self.check("ECOSYSTEM", text)
        self.assertEqual(code, 1, lines)
        self.assertEqual(
            lines,
            [
                f"docs/ecosystem.md:{self.line_of(text, cell)}: aip-conformance (this repo) "
                f"row cites no AIP version in its Spec cell; {self.pins}, "
                f"so the cell must cite 'AIP v{self.pinned}'"
            ],
        )

    def test_stale_duplicate_sibling_row_is_reported_in_either_order(self) -> None:
        current = next(
            line for line in self.ecosystem.splitlines() if self.sibling_cell in line
        )
        stale = current.replace(
            self.sibling_cell, f"| AIP v{OTHER_VERSION} identity protocol |"
        )
        for pair in (f"{stale}\n{current}", f"{current}\n{stale}"):
            with self.subTest(stale_first=pair.startswith(stale)):
                text = self.ecosystem.replace(current, pair)
                code, lines = self.check("ECOSYSTEM", text)
                self.assertEqual(code, 1, lines)
                self.assertEqual(
                    lines,
                    [
                        f"docs/ecosystem.md:{self.line_of(text, OTHER_VERSION)}: "
                        f"aip-conformance (this repo) row cites AIP v{OTHER_VERSION}; "
                        f"{self.pins}, so the citation must read 'v{self.pinned}'"
                    ],
                )

    def test_a_moved_pin_is_reported_in_each_of_the_three_places(self) -> None:
        """With another spec.version pinned, the unedited docs are each reported."""
        with mock.patch.dict(conformance_profile.SUITE["spec"], {"version": OTHER_VERSION}):
            problems = conformance_profile.spec_version_drift()
        pins = f"conformance.json pins spec.version {OTHER_VERSION}"
        for expected in (
            f"README.md:{self.line_of(self.readme, self.readme_citation)}: cites AIP "
            f"v{self.pinned}; {pins}, so the citation must read 'v{OTHER_VERSION}'",
            f"docs/versioning.md:{self.line_of(self.versioning, self.versioning_row)}: AIP spec "
            f"row pins 'v{self.pinned}'; {pins}, so its Version cell must read 'v{OTHER_VERSION}'",
            f"docs/ecosystem.md:{self.line_of(self.ecosystem, self.sibling_cell)}: "
            f"aip-conformance (this repo) row cites AIP v{self.pinned}; {pins}, "
            f"so the citation must read 'v{OTHER_VERSION}'",
        ):
            self.assertIn(expected, problems)
        self.assertEqual(
            sorted({problem.split(":")[0] for problem in problems}),
            ["README.md", "docs/ecosystem.md", "docs/versioning.md"],
        )


class SpecSourceTest(unittest.TestCase):
    """--spec-src DIR compares spec.version with the version DIR/AIP-SPEC.md declares."""

    # The lines AIP-SPEC.md opens with, ahead of its `**Version:**` line.
    HEADER = (
        "# OpenA2A Agent Identity Protocol (OpenA2A AIP)\n"
        "\n"
        "## An Open Standard for AI Agent Identity, Capabilities, and Trust\n"
        "\n"
    )

    def setUp(self) -> None:
        self.pinned = conformance_profile.SUITE["spec"]["version"]
        self.assertNotEqual(self.pinned, OTHER_VERSION)
        self.pins = f"conformance.json pins spec.version {self.pinned}"

    def spec_text(self, *version_lines: str) -> str:
        """An AIP-SPEC.md that opens as the spec does, with `version_lines` from line 5 on."""
        lines = "".join(f"{line}\n" for line in version_lines)
        return f"{self.HEADER}{lines}**Authors:** OpenA2A\n"

    def run_main(self, text: str | None, *args: str) -> tuple[int, list[str], Path, bool]:
        """Run main() with `args`, then `--spec-src` naming a temporary
        directory whose AIP-SPEC.md holds `text`, or that holds no AIP-SPEC.md
        when `text` is None. Without `--check`, the profile is written to a
        temporary path. Return the exit code, the printed lines, the
        AIP-SPEC.md path and whether the profile was written there."""
        with tempfile.TemporaryDirectory() as tmp:
            spec_src = Path(tmp) / "spec"
            spec_src.mkdir()
            spec = spec_src / "AIP-SPEC.md"
            if text is not None:
                spec.write_text(text, encoding="utf-8")
            profile = Path(tmp) / "conformance.json"
            out = io.StringIO()
            with contextlib.ExitStack() as stack:
                if "--check" not in args:
                    stack.enter_context(mock.patch.object(conformance_profile, "OUT", profile))
                stack.enter_context(
                    mock.patch.object(
                        sys, "argv", ["conformance_profile.py", *args, "--spec-src", str(spec_src)]
                    )
                )
                stack.enter_context(contextlib.redirect_stdout(out))
                code = conformance_profile.main()
            written = profile.exists()
        return code, out.getvalue().splitlines(), spec, written

    def mismatch(self, spec: Path, lineno: int, declared: str) -> str:
        return (
            f"{spec}:{lineno}: declares version {declared}; {self.pins}; when this "
            "checkout holds the spec text the fixtures test, SUITE in "
            f"scripts/conformance_profile.py must pin '{declared}'"
        )

    def test_checkout_declaring_the_pinned_version_passes(self) -> None:
        code, lines, spec, _ = self.run_main(
            self.spec_text(f"**Version:** {self.pinned}"), "--check"
        )
        self.assertEqual(code, 0, lines)
        self.assertEqual(lines[0], "conformance.json is current")
        self.assertEqual(
            lines[-1],
            f"{spec} declares version {self.pinned}, the spec.version conformance.json pins",
        )

    def test_checkout_declaring_another_version_is_reported(self) -> None:
        code, lines, spec, _ = self.run_main(
            self.spec_text(f"**Version:** {OTHER_VERSION}"), "--check"
        )
        self.assertEqual(code, 1, lines)
        self.assertEqual(
            lines, ["conformance.json is current", self.mismatch(spec, 5, OTHER_VERSION)]
        )

    def test_a_version_is_compared_whole(self) -> None:
        shorter = re.sub(r"[.+-][0-9A-Za-z]+$", "", self.pinned)
        self.assertNotEqual(shorter, self.pinned)
        for declared in (f"{self.pinned}.1", f"{self.pinned}-rc", f"{self.pinned}+build", shorter):
            with self.subTest(declared=declared):
                code, lines, spec, _ = self.run_main(
                    self.spec_text(f"**Version:** {declared}"), "--check"
                )
                self.assertEqual(code, 1, lines)
                self.assertEqual(lines[1:], [self.mismatch(spec, 5, declared)])

    def test_text_after_the_version_is_not_part_of_it(self) -> None:
        for line in (
            f"**Version:** {self.pinned} (dated 2026-10-06)",
            f"**Version:** {self.pinned}.",
            f"**Version:**\t{self.pinned}",
        ):
            with self.subTest(line=line):
                code, lines, _, _ = self.run_main(self.spec_text(line), "--check")
                self.assertEqual(code, 0, lines)

    def test_each_version_line_is_compared(self) -> None:
        """A second `**Version:**` line is read too, after or before a current one."""
        for first, second, stale_lineno in (
            (self.pinned, OTHER_VERSION, 6),
            (OTHER_VERSION, self.pinned, 5),
        ):
            with self.subTest(first=first, second=second):
                code, lines, spec, _ = self.run_main(
                    self.spec_text(f"**Version:** {first}", f"**Version:** {second}"), "--check"
                )
                self.assertEqual(code, 1, lines)
                self.assertEqual(lines[1:], [self.mismatch(spec, stale_lineno, OTHER_VERSION)])

    def test_checkout_with_no_version_line_is_reported(self) -> None:
        for text in (self.spec_text(), self.spec_text(f"Version: {self.pinned}")):
            with self.subTest(text=text):
                code, lines, spec, _ = self.run_main(text, "--check")
                self.assertEqual(code, 1, lines)
                self.assertEqual(
                    lines[1:], [f"{spec}: no line opens with '**Version:**'; {self.pins}"]
                )

    def test_version_line_naming_no_version_is_reported(self) -> None:
        for line in (
            "**Version:** draft",
            "**Version:**",
            f"**Version:**{self.pinned}",
            f"**Version:** v{self.pinned}",
        ):
            with self.subTest(line=line):
                code, lines, spec, _ = self.run_main(self.spec_text(line), "--check")
                self.assertEqual(code, 1, lines)
                self.assertEqual(lines[1:], [f"{spec}:5: {line!r} names no version; {self.pins}"])

    def test_directory_without_aip_spec_md_is_reported(self) -> None:
        code, lines, spec, _ = self.run_main(None, "--check")
        self.assertEqual(code, 1, lines)
        self.assertEqual(
            lines[1:],
            [
                f"{spec}: no such file; --spec-src names a checkout of the AIP spec "
                "repository, whose AIP-SPEC.md declares its version on a '**Version:**' line"
            ],
        )

    def test_write_mode_compares_too(self) -> None:
        """With no --check the script writes the profile, then reports the same line."""
        code, lines, spec, written = self.run_main(self.spec_text(f"**Version:** {OTHER_VERSION}"))
        self.assertEqual(code, 1, lines)
        self.assertTrue(written)
        self.assertTrue(lines[0].startswith("wrote conformance.json"), lines)
        self.assertEqual(lines[1:], [self.mismatch(spec, 5, OTHER_VERSION)])

    def test_a_pinned_version_no_line_can_name_is_left_to_the_citation_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(
            conformance_profile.SUITE["spec"], {"version": "draft-04"}
        ):
            (Path(tmp) / "AIP-SPEC.md").write_text(
                self.spec_text(f"**Version:** {OTHER_VERSION}"), encoding="utf-8"
            )
            self.assertEqual(conformance_profile.spec_source_drift(Path(tmp)), [])


class CommandLineTest(unittest.TestCase):
    def run_main(self, *args: str) -> tuple[object, str, str, bool]:
        """Run main() with `args`; return the exit code, stdout, stderr and
        whether conformance.json was written."""
        with tempfile.TemporaryDirectory() as tmp:
            profile = Path(tmp) / "conformance.json"
            out, err = io.StringIO(), io.StringIO()
            with mock.patch.object(conformance_profile, "OUT", profile), mock.patch.object(
                sys, "argv", ["conformance_profile.py", *args]
            ), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                try:
                    code = conformance_profile.main()
                except SystemExit as exit_:
                    code = exit_.code
            return code, out.getvalue(), err.getvalue(), profile.exists()

    def test_no_argument_writes_the_profile(self) -> None:
        code, out, _, written = self.run_main()
        self.assertEqual(code, 0, out)
        self.assertTrue(written)
        self.assertIn("wrote conformance.json", out)

    def test_help_prints_the_usage_text_and_writes_nothing(self) -> None:
        for flag in ("--help", "-h"):
            with self.subTest(flag=flag):
                code, out, _, written = self.run_main(flag)
                self.assertEqual(code, 0)
                self.assertIn(conformance_profile.__doc__.strip(), out)
                self.assertFalse(written)

    def test_help_names_the_spec_src_option(self) -> None:
        code, out, _, written = self.run_main("--help")
        self.assertEqual(code, 0)
        self.assertIn("--spec-src DIR", out)
        self.assertFalse(written)

    def test_spec_src_without_a_directory_exits_2(self) -> None:
        code, out, err, written = self.run_main("--check", "--spec-src")
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("argument --spec-src: expected one argument", err)
        self.assertFalse(written)

    def test_unrecognized_argument_prints_the_usage_and_exits_2(self) -> None:
        for arg in ("--chekc", "--che", "check"):
            with self.subTest(arg=arg):
                code, out, err, written = self.run_main(arg)
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                # The usage line's program name depends on how Python was
                # started (3.14 names the interpreter under `-m`), and 3.14
                # may color the line; color codes do not split the fragments
                # matched here.
                self.assertIn("usage: ", err)
                self.assertIn("--check", err)
                self.assertIn(f"unrecognized arguments: {arg}", err)
                self.assertFalse(written)


if __name__ == "__main__":
    unittest.main()
