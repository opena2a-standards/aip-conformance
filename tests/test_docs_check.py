#!/usr/bin/env python3
"""Regression tests for the go run ref check in scripts/docs_check.py.

Each test builds a throwaway git repository in a temporary directory (one
commit and one lightweight tag, written with plumbing commands), writes a
README.md fixture text into it and runs the check against that repository.
Every git command, the check's own included, reads no user or system git
configuration. The tracked files are never read or modified, so the tests
hold in a shallow checkout.

Usage:
    python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import docs_check  # noqa: E402

MODULE = "github.com/opena2a-standards/aip-conformance"
TAG = "v1.2.3"
IDENTITY = "docs check test"
EMAIL = "docs-check@example.invalid"
DATE = "2026-01-01T00:00:00Z"
GIT_ENV = {
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": IDENTITY,
    "GIT_AUTHOR_EMAIL": EMAIL,
    "GIT_AUTHOR_DATE": DATE,
    "GIT_COMMITTER_NAME": IDENTITY,
    "GIT_COMMITTER_EMAIL": EMAIL,
    "GIT_COMMITTER_DATE": DATE,
}
# Set when git runs a hook; each would point the commands at another repository.
REPOSITORY_ENV = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
)


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, input="", check=True, capture_output=True, text=True
    ).stdout.strip()


def command(ref: str, path: str = "/verifiers/go") -> str:
    return f"go run {MODULE}{path}@{ref}"


class GoRunRefCheckTest(unittest.TestCase):
    def setUp(self) -> None:
        env = mock.patch.dict(os.environ, GIT_ENV)
        env.start()
        self.addCleanup(env.stop)
        for name in REPOSITORY_ENV:
            os.environ.pop(name, None)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / "repo"
        self.root.mkdir()
        git(self.root, "init", "-q", "--object-format=sha1", "--initial-branch=main")
        self.tree = git(self.root, "mktree")
        self.commit = git(self.root, "commit-tree", "--no-gpg-sign", "-m", "first", self.tree)
        git(self.root, "update-ref", "refs/heads/main", self.commit)
        git(self.root, "update-ref", f"refs/tags/{TAG}", self.commit)

    def check(self, root: Path, readme: str, docs: dict[str, str] | None = None) -> list[str]:
        (root / "README.md").write_text(readme, encoding="utf-8")
        for name, text in (docs or {}).items():
            (root / "docs").mkdir(exist_ok=True)
            (root / "docs" / name).write_text(text, encoding="utf-8")
        return docs_check.check_go_run_refs(root)

    def test_tag_the_repository_lacks_fails(self) -> None:
        problems = self.check(self.root, f"Run it:\n\n```bash\n{command('v9.9.9')}\n```\n")
        self.assertEqual(len(problems), 1, problems)
        self.assertTrue(problems[0].startswith("README.md:4: "), problems)
        self.assertIn(f"`{command('v9.9.9')}`", problems[0])
        self.assertNotIn("shallow", problems[0])

    def test_full_commit_in_the_repository_passes(self) -> None:
        self.assertEqual(len(self.commit), 40)
        self.assertEqual(self.check(self.root, f"```bash\n{command(self.commit)}\n```\n"), [])

    def test_tag_in_the_repository_passes(self) -> None:
        text = f"`{command(TAG)}` runs the suite, as does {command(TAG)}.\n"
        self.assertEqual(self.check(self.root, text), [])

    def test_latest_passes(self) -> None:
        self.assertEqual(self.check(self.root, command("latest", "/cmd/aip-verify") + "\n"), [])

    def test_full_hex_that_names_no_commit_fails(self) -> None:
        missing = "0123456789abcdef" * 2 + "01234567"
        self.assertEqual(len(self.tree), 40)
        problems = self.check(self.root, f"{command(self.tree)}\n{command(missing)}\n")
        self.assertEqual([p.split(": ")[0] for p in problems], ["README.md:1", "README.md:2"])

    def test_abbreviated_commit_and_branch_fail(self) -> None:
        problems = self.check(self.root, f"{command(self.commit[:12])}\n{command('main')}\n")
        self.assertEqual([p.split(": ")[0] for p in problems], ["README.md:1", "README.md:2"])

    def test_every_command_form_on_this_module_is_read(self) -> None:
        text = (
            f"go run -mod=mod {MODULE}/verifiers/go@v9.9.9\n"
            f"go run {MODULE}@v9.9.9\n"
            f"go run \\\n  {MODULE}/verifiers/go@v9.9.9 ./fixtures\n"
        )
        problems = self.check(self.root, text)
        self.assertEqual(
            [p.split(": ")[0] for p in problems], ["README.md:1", "README.md:2", "README.md:3"]
        )

    def test_docs_pages_are_read_with_their_line(self) -> None:
        problems = self.check(
            self.root, command(TAG) + "\n", {"guide.md": f"# Guide\n\n`{command('v9.9.9')}`\n"}
        )
        self.assertEqual(len(problems), 1, problems)
        self.assertTrue(problems[0].startswith("docs/guide.md:3: "), problems)

    def test_other_modules_are_not_read(self) -> None:
        text = (
            "go run github.com/opena2a-standards/atx-conformance/cmd/atx-verify@v9.9.9\n"
            f"go run {MODULE}-extra/verifiers/go@v9.9.9\n"
        )
        self.assertEqual(self.check(self.root, text), [])

    def test_ref_outside_a_shallow_clone_fails_and_says_the_clone_is_shallow(self) -> None:
        second = git(
            self.root, "commit-tree", "--no-gpg-sign", "-p", self.commit, "-m", "second", self.tree
        )
        git(self.root, "update-ref", "refs/heads/main", second)
        clone = self.root.parent / "clone"
        git(self.root.parent, "clone", "-q", "--depth", "1", self.root.as_uri(), str(clone))
        self.assertEqual(git(clone, "rev-parse", "--is-shallow-repository"), "true")

        problems = self.check(clone, f"{command(self.commit)}\n{command(TAG)}\n{command(second)}\n")
        self.assertEqual([p.split(": ")[0] for p in problems], ["README.md:1", "README.md:2"])
        for problem in problems:
            self.assertIn("shallow", problem)


if __name__ == "__main__":
    unittest.main()
