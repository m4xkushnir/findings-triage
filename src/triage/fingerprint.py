"""Stable finding fingerprints.

A fingerprint has to survive the edits that don't change the finding (code inserted above it,
reformatting, a rename elsewhere in the file) and change when the finding itself changes.
Line numbers fail the first test, so they are never hashed. What is hashed depends on kind:

  code / config   scanner, rule, path, normalized flagged lines, occurrence index
  secret          scanner, rule, path, the flagged line with the secret value masked out
  dependency      scanner, advisory id, ecosystem, package, installed version, manifest path

The occurrence index separates identical snippets in the same file (the same unsafe call made
twice). It is the rank of the finding among identical (rule, path, snippet) matches, ordered by
line, so it only shifts when an identical match is inserted *above* an existing one.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

from triage.model import Kind, RawFinding
from triage.source import SourceTree

FINGERPRINT_VERSION = "v1"
CONTEXT_RADIUS = 8

_WS = re.compile(r"\s+")
# Long runs of key-like characters. Applied to every line shown or hashed for a secret finding
# on top of the scanner's own column span, so a scanner that reports the wrong columns still
# cannot leak the value into a report, the cache or the LLM prompt.
_TOKENISH = re.compile(r"[A-Za-z0-9+/=_\-.]{20,}")
# PEM armor. The body lines are masked as tokens; the armor itself is rewritten so that masked
# output (reports, caches) does not look like a key to the next secret scanner that reads it.
_PEM_ARMOR = re.compile(r"-----(BEGIN|END) ([A-Z0-9 ]*?)-----")
_QUOTED = re.compile(r"""(["'`])((?:(?!\1).){6,})\1""")


def normalize_code(text: str) -> str:
    """Collapse whitespace inside lines and drop blank lines. This is the displayed snippet;
    the fingerprint hashes it with whitespace removed entirely (see base_key).

    Deliberately conservative: it does not strip comments or rename identifiers, so a change to
    the code itself produces a new fingerprint. Reformatting (indentation, spacing, blank lines,
    re-wrapping) does not.
    """
    lines = (_WS.sub(" ", line).strip() for line in text.splitlines())
    return "\n".join(line for line in lines if line)


def mask_secret_line(line: str, start_col: int | None = None, end_col: int | None = None) -> str:
    """Return `line` with anything that could be the secret replaced by a placeholder."""
    if start_col is not None and end_col is not None and 1 <= start_col <= end_col:
        # SARIF columns are 1-based. Scanners disagree on whether the end column is inclusive,
        # so the span is taken generously and the token masking below catches any remainder.
        line = line[: start_col - 1] + "<SECRET>" + line[end_col:]
    line = _PEM_ARMOR.sub(lambda m: f"[{m.group(1).lower()} {m.group(2).lower()}]", line)
    line = _QUOTED.sub(lambda m: f"{m.group(1)}<SECRET>{m.group(1)}", line)
    return _TOKENISH.sub("<SECRET>", line)


def _sha(*parts: str) -> str:
    h = hashlib.sha256()
    for part in parts:
        h.update(part.encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()


@dataclass(frozen=True)
class Fingerprinted:
    raw: RawFinding
    fingerprint: str
    snippet: str  # normalized and, for secrets, masked
    context: str
    context_start_line: int | None


def snippet_for(raw: RawFinding, tree: SourceTree) -> str:
    """The text the fingerprint is computed from, before the occurrence index is applied."""
    loc = raw.location
    if raw.kind is Kind.DEPENDENCY:
        return ""
    lines = tree.lines(loc.path, loc.start_line, loc.end_line or loc.start_line)
    if raw.kind is Kind.SECRET:
        if lines is None:
            # Without the file, the scanner's own (redacted) snippet is the only context left.
            return normalize_code(mask_secret_line(raw.scanner_snippet or ""))
        masked = [
            mask_secret_line(
                text,
                loc.start_column if i == 0 else None,
                loc.end_column if i == len(lines) - 1 else None,
            )
            for i, text in enumerate(lines)
        ]
        return normalize_code("\n".join(masked))
    if lines is None:
        return normalize_code(raw.scanner_snippet or raw.message)
    if tree.is_sensitive(loc.path):
        # A code rule firing on .npmrc or .env still must not copy a token into the report.
        lines = [mask_secret_line(line) for line in lines]
    return normalize_code("\n".join(lines))


def context_for(raw: RawFinding, tree: SourceTree) -> tuple[str, int | None]:
    loc = raw.location
    if loc.start_line is None:
        return "", None
    start = max(1, loc.start_line - CONTEXT_RADIUS)
    end = (loc.end_line or loc.start_line) + CONTEXT_RADIUS
    lines = tree.lines(loc.path, start, end, clamp=True)
    if lines is None:
        return "", None
    if raw.kind is Kind.SECRET or tree.is_sensitive(loc.path):
        lines = [mask_secret_line(line) for line in lines]
    return "\n".join(lines), start


def base_key(raw: RawFinding, snippet: str) -> tuple[str, ...]:
    loc = raw.location
    if raw.kind is Kind.DEPENDENCY and raw.package is not None:
        pkg = raw.package
        return (
            FINGERPRINT_VERSION,
            "dependency",
            raw.scanner,
            raw.rule_id,
            pkg.ecosystem or "",
            pkg.name,
            pkg.version,
            loc.path,
        )
    # Hash with all whitespace removed: formatters add and remove spaces between tokens
    # ("f(a, b)" vs "f( a,b )") and re-wrap lines, none of which changes the finding.
    compact = _WS.sub("", snippet)
    return (FINGERPRINT_VERSION, raw.kind.value, raw.scanner, raw.rule_id, loc.path, compact)


def fingerprint_all(raws: Iterable[RawFinding], tree: SourceTree) -> list[Fingerprinted]:
    """Fingerprint a batch. Batch-level because the occurrence index needs every sibling."""
    prepared = []
    for raw in raws:
        snippet = snippet_for(raw, tree)
        context, ctx_start = context_for(raw, tree)
        prepared.append((raw, snippet, context, ctx_start, base_key(raw, snippet)))

    groups: dict[tuple[str, ...], list[int]] = defaultdict(list)
    for idx, item in enumerate(prepared):
        groups[item[4]].append(idx)

    occurrence: dict[int, int] = {}
    for members in groups.values():
        ordered = sorted(
            members,
            key=lambda i: (
                prepared[i][0].location.start_line or 0,
                prepared[i][0].location.start_column or 0,
            ),
        )
        for rank, i in enumerate(ordered):
            occurrence[i] = rank

    result = []
    for idx, (raw, snippet, context, ctx_start, key) in enumerate(prepared):
        fp = _sha(*key, str(occurrence[idx]))[:32]
        result.append(Fingerprinted(raw, fp, snippet, context, ctx_start))
    return result
