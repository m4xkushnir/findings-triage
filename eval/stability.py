"""Fingerprint stability between two commits, checked against `git diff`.

For a pair of run files scanned at commits OLD and NEW of the same repository:

  1. Diff the runs by fingerprint (what triage reports) and by a naive line-number key
     (scanner, rule, path, start line), which is what most dashboards key on.
  2. Classify every finding the fingerprint diff calls "new" or "fixed" by whether git says the
     flagged lines changed. A "new" finding whose lines are untouched in OLD..NEW is churn: the
     same issue reported again under a new ID. Same for "fixed" findings on the OLD side.

Usage:
    python eval/stability.py REPO OLD_SHA NEW_SHA old_run.json new_run.json
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", re.MULTILINE)


def changed_lines(
    repo: Path, old: str, new: str
) -> tuple[dict[str, set[int]], dict[str, set[int]]]:
    """Lines touched by OLD..NEW: (removed/changed lines in OLD, added/changed lines in NEW)."""
    out = subprocess.run(
        ["git", "-C", str(repo), "diff", "-U0", "--no-renames", old, new],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    old_side: dict[str, set[int]] = defaultdict(set)
    new_side: dict[str, set[int]] = defaultdict(set)
    path_old = path_new = None
    for line in out.splitlines():
        if line.startswith("--- "):
            path_old = None if line.endswith("/dev/null") else line[6:]
        elif line.startswith("+++ "):
            path_new = None if line.endswith("/dev/null") else line[6:]
        elif line.startswith("@@"):
            m = HUNK.match(line)
            if not m:
                continue
            o_start, o_len = int(m.group(1)), int(m.group(2) or 1)
            n_start, n_len = int(m.group(3)), int(m.group(4) or 1)
            if path_old:
                old_side[path_old].update(range(o_start, o_start + max(o_len, 1)))
            if path_new:
                new_side[path_new].update(range(n_start, n_start + max(n_len, 1)))
    return old_side, new_side


def ids(f: dict[str, Any]) -> set[str]:
    return {f["fingerprint"], *f["aliases"]}


def line_keys(run: dict[str, Any]) -> set[tuple[str, str, str, int | None]]:
    keys = set()
    for f in run["findings"]:
        for s in f["sources"]:
            keys.add(
                (s["scanner"], s["rule_id"], f["location"]["path"], f["location"]["start_line"])
            )
    return keys


def touched(f: dict[str, Any], lines: dict[str, set[int]], all_files: set[str]) -> bool:
    loc = f["location"]
    path = loc["path"]
    if path not in all_files:
        return False
    if loc["start_line"] is None:
        return True  # file-level finding in a changed file
    span = set(range(loc["start_line"], (loc["end_line"] or loc["start_line"]) + 1))
    return bool(span & lines.get(path, set()))


def main() -> None:
    repo, old, new, old_run_path, new_run_path = sys.argv[1:6]
    old_run = json.loads(Path(old_run_path).read_text())
    new_run = json.loads(Path(new_run_path).read_text())
    old_lines, new_lines = changed_lines(Path(repo), old, new)
    files_old, files_new = set(old_lines), set(new_lines)

    old_ids = {i for f in old_run["findings"] for i in ids(f)}
    new_ids = {i for f in new_run["findings"] for i in ids(f)}
    fp_new = [f for f in new_run["findings"] if not ids(f) & old_ids]
    fp_fixed = [f for f in old_run["findings"] if not ids(f) & new_ids]
    fp_same = [f for f in new_run["findings"] if ids(f) & old_ids]

    lk_old, lk_new = line_keys(old_run), line_keys(new_run)
    # Per scanner report, the same unit the line keys use.
    src_old = {s["fingerprint"] for f in old_run["findings"] for s in f["sources"]}
    src_new = {s["fingerprint"] for f in new_run["findings"] for s in f["sources"]}

    new_explained = [f for f in fp_new if touched(f, new_lines, files_new)]
    fixed_explained = [f for f in fp_fixed if touched(f, old_lines, files_old)]
    churn_new = [f for f in fp_new if f not in new_explained]
    churn_fixed = [f for f in fp_fixed if f not in fixed_explained]

    result = {
        "old_commit": old,
        "new_commit": new,
        "files_changed": len(files_old | files_new),
        "findings_old": len(old_run["findings"]),
        "findings_new": len(new_run["findings"]),
        "fingerprint": {
            "unchanged": len(fp_same),
            "new": len(fp_new),
            "fixed": len(fp_fixed),
            "new_explained_by_diff": len(new_explained),
            "fixed_explained_by_diff": len(fixed_explained),
            "unexplained_new": [
                f"{f['location']['path']}:{f['location']['start_line']} {f['rule_id']}"
                for f in churn_new
            ],
            "unexplained_fixed": [
                f"{f['location']['path']}:{f['location']['start_line']} {f['rule_id']}"
                for f in churn_fixed
            ],
        },
        "fingerprint_per_report": {
            "unchanged": len(src_old & src_new),
            "new": len(src_new - src_old),
            "fixed": len(src_old - src_new),
        },
        "line_key_per_report": {
            "unchanged": len(lk_old & lk_new),
            "new": len(lk_new - lk_old),
            "fixed": len(lk_old - lk_new),
        },
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
