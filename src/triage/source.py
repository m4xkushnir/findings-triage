"""Read-only access to the scanned tree.

Scanner output is untrusted input: a crafted SARIF file can point at `../../etc/passwd` or an
absolute path. Every path is resolved against the root and rejected if it escapes it, so the
tool never copies content from outside the scanned repository into a report or an LLM prompt.
"""

from __future__ import annotations

import fnmatch
from pathlib import Path, PurePosixPath

MAX_FILE_BYTES = 2_000_000
MAX_LINE_CHARS = 400

SENSITIVE_GLOBS = (
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "id_rsa*",
    "*.keystore",
    "*.jks",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "credentials*",
)


def normalize_path(raw: str, root: Path) -> str | None:
    """Turn a scanner-reported path or URI into a POSIX path relative to `root`.

    Returns None for paths that resolve outside the root.
    """
    text = raw.removeprefix("file://")
    candidate = Path(text)
    if not candidate.is_absolute():
        # Scanners report paths relative either to the root or to their working directory,
        # which is often the root's parent (`gitleaks dir juice-shop` -> `juice-shop/app.ts`).
        direct = (root / candidate).resolve()
        via_parent = (root.parent / candidate).resolve()
        prefixed = bool(candidate.parts) and candidate.parts[0] == root.resolve().name
        use_parent = not direct.exists() and (via_parent.exists() or prefixed)
        candidate = via_parent if use_parent else direct
    else:
        candidate = candidate.resolve()
    try:
        rel = candidate.relative_to(root.resolve())
    except ValueError:
        return None
    return PurePosixPath(*rel.parts).as_posix()


class SourceTree:
    def __init__(self, root: Path | None) -> None:
        self.root = root.resolve() if root is not None else None
        self._cache: dict[str, list[str] | None] = {}

    def _load(self, rel: str) -> list[str] | None:
        if rel in self._cache:
            return self._cache[rel]
        lines: list[str] | None = None
        if self.root is not None:
            path = (self.root / rel).resolve()
            inside = path.is_relative_to(self.root)
            if inside and path.is_file() and path.stat().st_size <= MAX_FILE_BYTES:
                data = path.read_bytes()
                if b"\x00" not in data[:8192]:
                    text = data.decode("utf-8", errors="replace")
                    lines = [line[:MAX_LINE_CHARS] for line in text.splitlines()]
        self._cache[rel] = lines
        return lines

    def lines(
        self, rel: str, start: int | None, end: int | None, *, clamp: bool = False
    ) -> list[str] | None:
        """Lines `start`..`end` inclusive (1-based), or None if unavailable."""
        content = self._load(rel)
        if content is None or start is None:
            return None
        end = end if end is not None and end >= start else start
        if clamp:
            end = min(end, len(content))
        if start < 1 or end > len(content):
            return None
        return content[start - 1 : end]

    @staticmethod
    def is_sensitive(rel: str) -> bool:
        name = PurePosixPath(rel).name
        return any(fnmatch.fnmatch(name, pattern) for pattern in SENSITIVE_GLOBS)
