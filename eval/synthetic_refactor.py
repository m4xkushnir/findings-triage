"""Apply a behavior-preserving "refactor" to a copy of a repository.

Two edits that reformatters and license tooling make all the time, and that change no finding:

  1. Insert a 7-line license header at the top of every source file, which shifts every line.
  2. Double the leading indentation of every line in JS/TS/Python files.

Usage:
    python eval/synthetic_refactor.py SRC DEST
"""

from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path

HEADER = [
    "Copyright (c) 2026 Example Contributors",
    "SPDX-License-Identifier: MIT",
    "",
    "This header was inserted by eval/synthetic_refactor.py to shift every line of",
    "the file without changing its behavior.",
    "",
    "",
]
COMMENT = {
    ".ts": "//",
    ".js": "//",
    ".go": "//",
    ".py": "#",
    ".tf": "#",
    ".yml": "#",
    ".yaml": "#",
    ".rb": "#",
    ".sh": "#",
}
REINDENT = {".ts", ".js", ".py"}
LEADING = re.compile(r"^( +)")


def transform(path: Path) -> bool:
    prefix = COMMENT.get(path.suffix)
    if prefix is None:
        return False
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return False
    lines = text.split("\n")
    if path.suffix in REINDENT:
        lines = [LEADING.sub(lambda m: m.group(1) * 2, line) for line in lines]
    # Keep shebangs and Python encoding lines first, where they must stay.
    keep = 1 if lines and lines[0].startswith("#!") else 0
    header = [f"{prefix} {h}".rstrip() for h in HEADER]
    path.write_text("\n".join(lines[:keep] + header + lines[keep:]), encoding="utf-8")
    return True


def main() -> None:
    src, dest = Path(sys.argv[1]), Path(sys.argv[2])
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src, dest, ignore=shutil.ignore_patterns(".git", "node_modules"))
    changed = sum(transform(p) for p in dest.rglob("*") if p.is_file())
    print(f"transformed {changed} files in {dest}")


if __name__ == "__main__":
    main()
