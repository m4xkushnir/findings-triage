from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest
from conftest import raw

from triage.engine import build_run
from triage.model import Finding, Kind
from triage.suppress import SuppressionError, Suppressor, load_suppressions

TODAY = dt.date(2026, 10, 23)


def rules(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "triage.suppressions.yaml"
    path.write_text("version: 1\nsuppressions:\n" + body, encoding="utf-8")
    return path


def finding(path: str = "test/fixtures/app.js", rule: str = "js.sqli") -> Finding:
    run = build_run([raw(path=path, rule=rule)], None, root_name="r", commit=None, scanners=[])
    return run.findings[0]


RULE = """\
  - id: SUP-1
    match: {{ rule: "semgrep:js.*", path: "test/**" }}
    reason: Fixture code exercising the vulnerable path on purpose.
    author: jane@example.com
    created: 2026-09-01
{expires}
"""


def test_matches_rule_and_path_globs(tmp_path: Path) -> None:
    sup = Suppressor(load_suppressions(rules(tmp_path, RULE.format(expires=""))), TODAY)
    assert sup.check(finding()).applied is not None
    assert sup.check(finding(path="src/app.js")).applied is None
    assert sup.check(finding(rule="py.sqli")).applied is None


def test_double_star_spans_directories_single_star_does_not(tmp_path: Path) -> None:
    body = RULE.format(expires="").replace("test/**", "test/*.js")
    sup = Suppressor(load_suppressions(rules(tmp_path, body)), TODAY)
    assert sup.check(finding(path="test/app.js")).applied is not None
    assert sup.check(finding(path="test/fixtures/app.js")).applied is None


def test_active_until_and_including_expiry_date(tmp_path: Path) -> None:
    path = rules(tmp_path, RULE.format(expires="    expires: 2026-10-23"))
    on_day = Suppressor(load_suppressions(path), dt.date(2026, 10, 23)).check(finding())
    assert on_day.applied is not None


def test_expired_rule_stops_matching_and_is_reported(tmp_path: Path) -> None:
    path = rules(tmp_path, RULE.format(expires="    expires: 2026-10-22"))
    result = Suppressor(load_suppressions(path), TODAY).check(finding())
    assert result.applied is None
    assert [e.rule_id for e in result.expired] == ["SUP-1"]


def test_later_rule_applies_when_earlier_one_expired(tmp_path: Path) -> None:
    body = RULE.format(expires="    expires: 2026-10-01") + RULE.format(expires="").replace(
        "SUP-1", "SUP-2"
    )
    result = Suppressor(load_suppressions(rules(tmp_path, body)), TODAY).check(finding())
    assert result.applied is not None and result.applied.rule_id == "SUP-2"
    assert [e.rule_id for e in result.expired] == ["SUP-1"]


def test_fingerprint_match_includes_aliases(tmp_path: Path) -> None:
    f = finding()
    aliased = f.model_copy(update={"fingerprint": "f" * 32, "aliases": (f.fingerprint,)})
    body = f"""\
  - id: SUP-FP
    match: {{ fingerprint: {f.fingerprint} }}
    reason: Accepted risk, documented in the threat model.
    author: sec@example.com
    created: 2026-09-01
"""
    sup = Suppressor(load_suppressions(rules(tmp_path, body)), TODAY)
    assert sup.check(aliased).applied is not None


def test_stale_rules_are_listed(tmp_path: Path) -> None:
    sup = Suppressor(load_suppressions(rules(tmp_path, RULE.format(expires=""))), TODAY)
    sup.check(finding(path="src/app.js"))
    assert sup.stale() == ["SUP-1"]


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (
            RULE.format(expires="").replace(
                "    reason: Fixture code exercising the vulnerable path on purpose.\n", ""
            ),
            "reason",
        ),
        (
            RULE.format(expires="")
            .replace("on purpose.", "")
            .replace("Fixture code exercising the vulnerable path ", "ok"),
            "reason",
        ),
        (RULE.format(expires="    expires: 2026-08-01"), "before created"),
        (RULE.format(expires="") + RULE.format(expires=""), "duplicate"),
        (RULE.format(expires="    severity: low"), "severity"),
        (
            RULE.format(expires="").replace(
                'rule: "semgrep:js.*", path: "test/**"', "kind: secret"
            ),
            "at least one",
        ),
    ],
)
def test_invalid_files_fail_loudly(tmp_path: Path, body: str, message: str) -> None:
    with pytest.raises(SuppressionError, match=message):
        load_suppressions(rules(tmp_path, body))


def test_kind_filter(tmp_path: Path) -> None:
    body = RULE.format(expires="").replace(
        'rule: "semgrep:js.*", path: "test/**"', 'path: "**", kind: secret'
    )
    sup = Suppressor(load_suppressions(rules(tmp_path, body)), TODAY)
    assert sup.check(finding()).applied is None
    secret = build_run(
        [raw(kind=Kind.SECRET, scanner="gitleaks", rule="x")],
        None,
        root_name="r",
        commit=None,
        scanners=[],
    ).findings[0]
    assert sup.check(secret).applied is not None
