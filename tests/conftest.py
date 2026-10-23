from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from triage.model import Kind, Location, Package, RawFinding, Severity


def raw(
    *,
    scanner: str = "semgrep",
    rule: str = "js.sqli",
    kind: Kind = Kind.CODE,
    path: str = "app.js",
    line: int | None = 3,
    end: int | None = None,
    severity: Severity = Severity.HIGH,
    cwe: tuple[str, ...] = (),
    package: Package | None = None,
    col: int | None = None,
    end_col: int | None = None,
) -> RawFinding:
    return RawFinding(
        scanner=scanner,
        rule_id=rule,
        kind=kind,
        severity=severity,
        message=f"{rule} message",
        location=Location(
            path=path, start_line=line, end_line=end or line, start_column=col, end_column=end_col
        ),
        cwe=cwe,
        package=package,
    )


def write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class FakeMessages:
    """Stands in for `client.beta.messages`. Records calls; answers from a queue or a default."""

    def __init__(self, answers: list[Any] | None = None, default: dict[str, str] | None = None):
        self.calls: list[dict[str, Any]] = []
        self.answers = list(answers or [])
        self.default = default or {
            "exploitable": "likely",
            "reachable": "likely",
            "suggested_severity": "high",
            "confidence": "high",
            "reasoning": "User input reaches the query on line 3 without parameterization.",
        }

    def create(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        answer = self.answers.pop(0) if self.answers else self.default
        if isinstance(answer, Exception):
            raise answer
        if isinstance(answer, SimpleNamespace):
            return answer
        return SimpleNamespace(
            stop_reason="end_turn",
            stop_details=None,
            model=kwargs["model"],
            content=[SimpleNamespace(type="text", text=json.dumps(answer))],
            usage=SimpleNamespace(input_tokens=900, output_tokens=120),
        )


class FakeClient:
    def __init__(self, messages: FakeMessages) -> None:
        self.beta = SimpleNamespace(messages=messages)


@pytest.fixture
def fake_llm() -> tuple[FakeClient, FakeMessages]:
    messages = FakeMessages()
    return FakeClient(messages), messages
