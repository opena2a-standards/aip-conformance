#!/usr/bin/env python3
"""Regression tests for the docs/ecosystem.md row gates in
scripts/conformance_profile.py.

Each test writes an edited copy of docs/ecosystem.md to a temporary
directory and points the gates at the copy, so the tracked doc is never
modified.

Usage:
    python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import contextlib
import io
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


if __name__ == "__main__":
    unittest.main()
