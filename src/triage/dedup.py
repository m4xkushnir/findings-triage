"""Merge reports of the same issue.

Two different questions, kept apart on purpose:

  identity    "is this the same finding as last run?"   -> the fingerprint (fingerprint.py)
  duplication "are these two reports the same issue?"   -> this module

A fingerprint is per scanner and per rule, so it never changes when a scanner is added or
removed. Dedup groups reports that point at the same thing, keeps the strongest one as the
primary and records the rest as sources and aliases. That way a diff still matches when a
merged finding's primary changes between runs.

Merge rules, in order of confidence:

  1. Exact repeats from one scanner (same rule, path and span) collapse before fingerprinting.
  2. Secrets: any reports on the same path whose line ranges overlap. A line rarely holds two
     different credentials, while Gitleaks, Trivy and Semgrep routinely flag the same one.
  3. Dependencies: same advisory, package, version and manifest.
  4. Code and config: reports from *different* scanners whose lines overlap and that share a
     CWE or are listed as equivalent in data/equivalences.yaml. Two rules from one scanner
     firing on one line are usually two distinct problems, so they stay separate.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from functools import cache
from importlib import resources

import yaml

from triage.fingerprint import Fingerprinted
from triage.model import Finding, Kind, RawFinding, SourceRef

_PRIMARY_ORDER = {
    Kind.SECRET: ("gitleaks", "trivy", "semgrep"),
    Kind.DEPENDENCY: ("trivy", "semgrep"),
    Kind.CONFIG: ("trivy", "semgrep"),
    Kind.CODE: ("semgrep", "trivy"),
}


@dataclass(frozen=True)
class DedupStats:
    same_scanner_duplicates: int
    cross_scanner_duplicates: int


def exact_key(raw: RawFinding) -> tuple[object, ...]:
    loc = raw.location
    pkg = raw.package
    return (
        raw.scanner,
        raw.rule_id,
        loc.path,
        loc.start_line,
        loc.end_line,
        loc.start_column,
        (pkg.name, pkg.version) if pkg else None,
    )


def drop_exact_repeats(raws: Sequence[RawFinding]) -> tuple[list[RawFinding], int]:
    seen: set[tuple[object, ...]] = set()
    kept = []
    for raw in raws:
        key = exact_key(raw)
        if key in seen:
            continue
        seen.add(key)
        kept.append(raw)
    return kept, len(raws) - len(kept)


@cache
def _equivalences() -> tuple[tuple[re.Pattern[str], ...], ...]:
    text = resources.files("triage.data").joinpath("equivalences.yaml").read_text("utf-8")
    groups = yaml.safe_load(text) or []
    return tuple(tuple(re.compile(p) for p in g["rules"]) for g in groups)


def _equivalent(a: RawFinding, b: RawFinding) -> bool:
    ida, idb = f"{a.scanner}:{a.rule_id}", f"{b.scanner}:{b.rule_id}"
    for group in _equivalences():
        hit_a = any(p.fullmatch(ida) for p in group)
        hit_b = any(p.fullmatch(idb) for p in group)
        if hit_a and hit_b:
            return True
    return False


def _overlap(a: RawFinding, b: RawFinding) -> bool:
    la, lb = a.location, b.location
    if la.path != lb.path:
        return False
    if la.start_line is None or lb.start_line is None:
        return la.start_line is None and lb.start_line is None
    a_end = la.end_line or la.start_line
    b_end = lb.end_line or lb.start_line
    return la.start_line <= b_end and lb.start_line <= a_end


def _secretish(r: RawFinding) -> bool:
    return r.kind is Kind.SECRET or "CWE-798" in r.cwe


def _same_issue(a: RawFinding, b: RawFinding) -> bool:
    if _secretish(a) and _secretish(b):
        # Covers Semgrep filing a hardcoded key under a code rule tagged CWE-798.
        return _overlap(a, b)
    if a.kind is not b.kind:
        return False
    if a.kind is Kind.DEPENDENCY:
        pa, pb = a.package, b.package
        return (
            pa is not None
            and pb is not None
            and a.rule_id == b.rule_id
            and (pa.name, pa.version) == (pb.name, pb.version)
            and a.location.path == b.location.path
        )
    if a.scanner == b.scanner or not _overlap(a, b):
        return False
    return bool(set(a.cwe) & set(b.cwe)) or _equivalent(a, b)


class _UnionFind:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def _primary_rank(item: Fingerprinted) -> tuple[int, int, str, str]:
    order = _PRIMARY_ORDER[item.raw.kind]
    scanner_rank = order.index(item.raw.scanner) if item.raw.scanner in order else len(order)
    return (scanner_rank, -item.raw.severity.rank, item.raw.rule_id, item.fingerprint)


def merge(items: Sequence[Fingerprinted]) -> tuple[list[Finding], DedupStats]:
    """Group fingerprinted reports into findings."""
    # Only reports on the same path can merge, so compare within a path bucket.
    by_path: dict[str, list[int]] = {}
    for i, item in enumerate(items):
        by_path.setdefault(item.raw.location.path, []).append(i)

    uf = _UnionFind(len(items))
    for members in by_path.values():
        for x, i in enumerate(members):
            for j in members[x + 1 :]:
                if _same_issue(items[i].raw, items[j].raw):
                    uf.union(i, j)

    groups: dict[int, list[Fingerprinted]] = {}
    for i, item in enumerate(items):
        groups.setdefault(uf.find(i), []).append(item)

    cross = same = 0
    for group in groups.values():
        if len({g.raw.scanner for g in group}) > 1:
            cross += len(group) - 1
        else:
            same += len(group) - 1
    findings = [_build(group) for group in groups.values()]
    findings.sort(key=lambda f: (f.location.path, f.location.start_line or 0, f.fingerprint))
    return findings, DedupStats(same_scanner_duplicates=same, cross_scanner_duplicates=cross)


_SENTENCE_END = re.compile(r"(?<=[.!?])\s")
TITLE_LIMIT = 160


def _title(message: str) -> str:
    """First sentence of the scanner's message, cut at a word boundary if still too long."""
    text = " ".join(message.split())
    text = _SENTENCE_END.split(text, maxsplit=1)[0]
    if len(text) > TITLE_LIMIT:
        text = text[: TITLE_LIMIT - 1].rsplit(" ", 1)[0] + "…"
    return text


def _build(group: list[Fingerprinted]) -> Finding:
    ordered = sorted(group, key=_primary_rank)
    primary = ordered[0]
    raw = primary.raw
    severity = max((g.raw.severity for g in group), key=lambda s: s.rank)
    sources = tuple(
        sorted(
            (
                SourceRef(
                    scanner=g.raw.scanner,
                    rule_id=g.raw.rule_id,
                    fingerprint=g.fingerprint,
                    severity=g.raw.severity,
                )
                for g in group
            ),
            key=lambda s: (s.scanner, s.rule_id, s.fingerprint),
        )
    )
    return Finding(
        fingerprint=primary.fingerprint,
        aliases=tuple(sorted({g.fingerprint for g in ordered[1:]} - {primary.fingerprint})),
        kind=raw.kind,
        rule_id=raw.rule_id,
        title=_title(raw.message) or raw.rule_id,
        severity=severity,
        location=raw.location,
        cwe=tuple(sorted({c for g in group for c in g.raw.cwe})),
        package=raw.package,
        rule_confidence=raw.rule_confidence,
        sources=sources,
        snippet=primary.snippet,
        context=primary.context,
        context_start_line=primary.context_start_line,
        help_uri=raw.help_uri,
    )
