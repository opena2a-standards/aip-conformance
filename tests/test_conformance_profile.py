#!/usr/bin/env python3
"""Regression tests for the docs/ecosystem.md status-row gate in
scripts/conformance_profile.py.

Each test writes an edited copy of docs/ecosystem.md to a temporary
directory and points the gate at the copy, so the tracked doc is never
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
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import conformance_profile  # noqa: E402

GO = "verifiers/go"


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
        with tempfile.TemporaryDirectory() as tmp:
            doc = Path(tmp) / "ecosystem.md"
            doc.write_text("\n".join(lines) + "\n", encoding="utf-8")
            out = io.StringIO()
            with mock.patch.object(conformance_profile, "ECOSYSTEM", doc), mock.patch.object(
                sys, "argv", ["conformance_profile.py", "--check"]
            ), contextlib.redirect_stdout(out):
                drift = conformance_profile.verifier_status_drift()
                code = conformance_profile.main()
        return drift, code, out.getvalue()

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


if __name__ == "__main__":
    unittest.main()
