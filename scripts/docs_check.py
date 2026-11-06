#!/usr/bin/env python3
"""Check the documentation's fixture counts, repository layout and go run refs against the tree.

Three kinds of statement in the docs drift as the tree changes, so this
script checks each against the tree:

1. Fixture counts in README.md and docs/*.md. A verifier summary
   (`N pass, M fail`, optionally followed by `(K fixtures)`) must add up to
   the number of `*.json` files in fixtures/, the same glob both verifiers
   walk; `N conformance fixtures` and the Go verifier's first output line,
   `fixtures: N embedded in`, must equal that number.
2. The repository layout block in docs/how-it-works.md. Every tracked file
   outside dot-directories and dotfiles must sit under one of its entries,
   and every entry must name a tracked file or directory.
3. The ref of every `go run github.com/opena2a-standards/aip-conformance/<path>@<ref>`
   command in README.md and docs/*.md. The ref must be `latest`, a full
   40-hex commit id that `git cat-file -e <ref>^{commit}` finds, or a tag
   that `git tag -l <ref>` prints: the module proxy answers a tag this
   repository does not have with `unknown revision`. Commit ids and tags are
   read from this clone, so the check reports when the clone is shallow.

Usage:
    python3 scripts/docs_check.py    # exit 0 when current; else list each stale statement, exit 1
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LAYOUT_DOC = REPO_ROOT / "docs" / "how-it-works.md"

SUMMARY = re.compile(r"(\d+)\s+pass,\s+(\d+)\s+fail(?:\s+\((\d+)\s+fixtures?\))?")
NAMED_COUNT = re.compile(r"(\d+)\s+conformance\s+fixtures?")
EMBEDDED_COUNT = re.compile(r"fixtures:\s+(\d+)\s+embedded\s+in\b")
LAYOUT_BLOCK = re.compile(r"^## Repository layout\n+```[^\n]*\n(.*?)^```", re.M | re.S)
GO_RUN = re.compile(
    r"\bgo\s+run\s+(?:(?:-\S+|\\)\s+)*"
    r"(?P<target>github\.com/opena2a-standards/aip-conformance(?:/[^\s@`]*)?)@(?P<ref>[^\s`]+)"
)
FULL_COMMIT = re.compile(r"[0-9a-f]{40}")
TAG_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+/-]*")
REF_TRAILER = ".,;:!?)]}>'\"*"  # sentence punctuation after a ref outside a code span


def tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return [p for p in out.split("\0") if p]


def check_counts(fixture_count: int) -> list[str]:
    problems = []
    docs = [REPO_ROOT / "README.md", *sorted((REPO_ROOT / "docs").glob("*.md"))]
    for doc in docs:
        rel = doc.relative_to(REPO_ROOT)
        text = doc.read_text(encoding="utf-8")
        for m in SUMMARY.finditer(text):
            passed, failed, total = int(m[1]), int(m[2]), m[3]
            if passed + failed != fixture_count or (
                total is not None and int(total) != fixture_count
            ):
                problems.append((rel, text.count("\n", 0, m.start()) + 1, m[0]))
        for pattern in (NAMED_COUNT, EMBEDDED_COUNT):
            for m in pattern.finditer(text):
                if int(m[1]) != fixture_count:
                    problems.append((rel, text.count("\n", 0, m.start()) + 1, m[0]))
    return [
        f"{rel}:{lineno}: `{' '.join(claim.split())}` does not match the "
        f"{fixture_count} fixtures in fixtures/"
        for rel, lineno, claim in problems
    ]


def check_layout(files: list[str]) -> list[str]:
    rel = LAYOUT_DOC.relative_to(REPO_ROOT)
    text = LAYOUT_DOC.read_text(encoding="utf-8")
    m = LAYOUT_BLOCK.search(text)
    if not m:
        return [f"{rel}: no fenced block under '## Repository layout'"]
    first_line = text.count("\n", 0, m.start(1)) + 1

    problems = []
    entries = []
    for offset, line in enumerate(m[1].splitlines()):
        if not line.strip():
            continue
        entry = line.split()[0]
        entries.append(entry)
        if entry.endswith("/"):
            exists = any(f.startswith(entry) for f in files)
        else:
            exists = entry in files
        if not exists:
            problems.append(
                f"{rel}:{first_line + offset}: layout entry {entry} is not a tracked path"
            )

    for f in files:
        if any(part.startswith(".") for part in f.split("/")):
            continue
        if not any(f == e or (e.endswith("/") and f.startswith(e)) for e in entries):
            problems.append(f"{rel}: layout block has no entry covering {f}")
    return problems


def git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True)


def ref_resolves(root: Path, ref: str) -> bool:
    """True when ref is `latest`, a full commit id this clone has, or a tag this clone has."""
    if ref == "latest":
        return True
    if FULL_COMMIT.fullmatch(ref) and git(root, "cat-file", "-e", f"{ref}^{{commit}}").returncode == 0:
        return True
    return bool(TAG_NAME.fullmatch(ref)) and ref in git(root, "tag", "-l", ref).stdout.splitlines()


def check_go_run_refs(root: Path = REPO_ROOT) -> list[str]:
    problems = []
    for doc in [root / "README.md", *sorted((root / "docs").glob("*.md"))]:
        rel = doc.relative_to(root)
        text = doc.read_text(encoding="utf-8")
        for m in GO_RUN.finditer(text):
            ref = m["ref"].rstrip(REF_TRAILER)
            if not ref_resolves(root, ref):
                lineno = text.count("\n", 0, m.start()) + 1
                problems.append(
                    f"{rel}:{lineno}: `go run {m['target']}@{ref}` names {ref}, which is "
                    "neither `latest` nor a full commit id or tag this clone has"
                )
    if problems and git(root, "rev-parse", "--is-shallow-repository").stdout.strip() == "true":
        problems = [
            f"{problem}; this clone is shallow, so fetch its history and tags "
            "(`git fetch --unshallow --tags`) and run the check again"
            for problem in problems
        ]
    return problems


def main() -> int:
    try:
        files = tracked_files()
    except (OSError, subprocess.CalledProcessError) as err:
        print(f"error: cannot list tracked files with git: {err}")
        return 2

    fixture_count = len(list((REPO_ROOT / "fixtures").glob("*.json")))
    problems = check_counts(fixture_count) + check_layout(files) + check_go_run_refs()
    for problem in problems:
        print(problem)
    if problems:
        print(f"\n{len(problems)} stale statement(s) in the docs")
        return 1
    print("docs fixture counts, repository layout and go run refs are current")
    return 0


if __name__ == "__main__":
    sys.exit(main())
