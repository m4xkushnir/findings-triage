"""Suppression rules, read from a versioned YAML file.

Every rule needs a reason and an author so that "why is this hidden?" always has an answer, and
can carry an expiry so that "accepted for now" does not silently become "accepted forever".
An expired rule stops matching and the finding comes back, with a note saying which rule
lapsed. Rules that match nothing are reported as stale so the file does not accumulate dead
entries that could later hide a new finding by accident.

    version: 1
    suppressions:
      - id: SUP-001
        match:
          rule: "semgrep:javascript.lang.security.audit.*"   # scanner:rule_id, glob
          path: "test/**"                                     # glob, ** crosses directories
          # fingerprint: 3f2a...                              # or one exact finding
          # kind: secret
        reason: Test fixtures exercise the vulnerable path on purpose.
        author: jane@example.com
        created: 2026-10-01
        expires: 2027-01-01
"""

from __future__ import annotations

import datetime as dt
import fnmatch
import re
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from triage.model import Finding, Kind, SuppressionRef


class SuppressionError(Exception):
    """The suppression file is malformed. Fails the run: a typo must not hide findings."""


class Match(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    fingerprint: str | None = None
    rule: str | None = None
    path: str | None = None
    kind: Kind | None = None

    @model_validator(mode="after")
    def _not_empty(self) -> Match:
        if not (self.fingerprint or self.rule or self.path):
            raise ValueError("match needs at least one of fingerprint, rule, path")
        return self


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1)
    match: Match
    reason: str = Field(min_length=10)
    author: str = Field(min_length=1)
    created: dt.date
    expires: dt.date | None = None

    @model_validator(mode="after")
    def _expiry_after_creation(self) -> Rule:
        if self.expires is not None and self.expires < self.created:
            raise ValueError(f"{self.id}: expires ({self.expires}) is before created")
        return self

    def ref(self) -> SuppressionRef:
        return SuppressionRef(
            rule_id=self.id,
            reason=self.reason,
            author=self.author,
            created=self.created.isoformat(),
            expires=self.expires.isoformat() if self.expires else None,
        )


class SuppressionFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal[1]
    suppressions: tuple[Rule, ...] = ()

    @model_validator(mode="after")
    def _unique_ids(self) -> SuppressionFile:
        ids = [r.id for r in self.suppressions]
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        if dupes:
            raise ValueError(f"duplicate suppression ids: {', '.join(dupes)}")
        return self


def load_suppressions(path: Path | None) -> SuppressionFile:
    if path is None:
        return SuppressionFile(version=1)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise SuppressionError(f"{path}: {exc}") from exc
    try:
        return SuppressionFile.model_validate(data)
    except ValidationError as exc:
        raise SuppressionError(f"{path}: {exc}") from exc


@cache
def _glob(pattern: str) -> re.Pattern[str]:
    """Path glob where `**` spans directories and `*` stays inside one segment."""
    out = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out))


def _matches(match: Match, finding: Finding) -> bool:
    if match.fingerprint and match.fingerprint not in (finding.fingerprint, *finding.aliases):
        return False
    if match.kind and match.kind is not finding.kind:
        return False
    if match.path and not _glob(match.path).fullmatch(finding.location.path):
        return False
    if match.rule:
        rules = [f"{s.scanner}:{s.rule_id}" for s in finding.sources]
        if not any(fnmatch.fnmatchcase(r, match.rule) for r in rules):
            return False
    return True


@dataclass(frozen=True)
class SuppressionResult:
    applied: SuppressionRef | None
    expired: tuple[SuppressionRef, ...]


@dataclass
class Suppressor:
    rules: SuppressionFile
    as_of: dt.date

    def __post_init__(self) -> None:
        self.hits: dict[str, int] = {r.id: 0 for r in self.rules.suppressions}

    def check(self, finding: Finding) -> SuppressionResult:
        """First active matching rule wins; file order is the precedence order."""
        expired = []
        for rule in self.rules.suppressions:
            if not _matches(rule.match, finding):
                continue
            self.hits[rule.id] += 1
            if rule.expires is not None and rule.expires < self.as_of:
                expired.append(rule.ref())
                continue
            return SuppressionResult(applied=rule.ref(), expired=tuple(expired))
        return SuppressionResult(applied=None, expired=tuple(expired))

    def stale(self) -> list[str]:
        return [rule_id for rule_id, n in self.hits.items() if n == 0]
