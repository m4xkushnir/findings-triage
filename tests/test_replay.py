"""Replay determinism: same run + suppressions + cache + as-of date -> byte-identical report."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from conftest import FakeClient, FakeMessages, raw, write
from typer.testing import CliRunner

from triage.cli import app
from triage.engine import build_report, build_run
from triage.enrich import EnrichMode
from triage.model import Kind
from triage.output import FORMATS, render
from triage.suppress import load_suppressions

AS_OF = dt.date(2026, 10, 23)
runner = CliRunner()


def sample_run(tmp_path: Path):  # type: ignore[no-untyped-def]
    write(tmp_path, "src/app.js", "a\nb\ndb.query('x' + req.body.id)\n")
    write(tmp_path, "test/app.test.js", "eval(input)\n")
    write(tmp_path, "src/cfg.js", "const k = 'zzzzzzzzzzzzzzzzzzzzzzzzzz'\n")
    raws = [
        raw(path="src/app.js", line=3),
        raw(path="test/app.test.js", line=1, rule="js.eval"),
        raw(path="src/cfg.js", line=1, kind=Kind.SECRET, scanner="gitleaks", rule="generic"),
    ]
    return build_run(raws, tmp_path, root_name="demo", commit="abc123", scanners=["semgrep"])


def all_formats(report) -> dict[str, str]:  # type: ignore[no-untyped-def]
    return {f: render(report, f) for f in FORMATS}


def test_heuristic_report_is_byte_identical(tmp_path: Path) -> None:
    run = sample_run(tmp_path)
    kwargs = {
        "suppressions": load_suppressions(None),
        "as_of": AS_OF,
        "enrich_mode": EnrichMode.HEURISTIC,
        "cache_dir": None,
    }
    a = all_formats(build_report(run, **kwargs).report)  # type: ignore[arg-type]
    b = all_formats(build_report(run, **kwargs).report)  # type: ignore[arg-type]
    assert a == b


def test_llm_report_replays_from_cache_without_api(tmp_path: Path) -> None:
    run = sample_run(tmp_path)
    cache = tmp_path / "cache"
    messages = FakeMessages()
    first = build_report(
        run,
        suppressions=load_suppressions(None),
        as_of=AS_OF,
        enrich_mode=EnrichMode.LLM,
        cache_dir=cache,
        llm_client=FakeClient(messages),
    ).report
    calls = len(messages.calls)
    assert calls == 3
    replay = build_report(
        run,
        suppressions=load_suppressions(None),
        as_of=AS_OF,
        enrich_mode=EnrichMode.CACHE_ONLY,
        cache_dir=cache,
    ).report
    assert len(messages.calls) == calls
    assert all_formats(first) == all_formats(replay)


def test_run_file_is_independent_of_scanner_output_order(tmp_path: Path) -> None:
    run = sample_run(tmp_path)
    shuffled = build_run(
        list(
            reversed(
                [
                    raw(path="src/app.js", line=3),
                    raw(path="test/app.test.js", line=1, rule="js.eval"),
                    raw(
                        path="src/cfg.js",
                        line=1,
                        kind=Kind.SECRET,
                        scanner="gitleaks",
                        rule="generic",
                    ),
                ]
            )
        ),
        tmp_path,
        root_name="demo",
        commit="abc123",
        scanners=["semgrep"],
    )
    assert run.model_dump_json() == shuffled.model_dump_json()


def sarif_fixture(path: Path) -> Path:
    data = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Semgrep OSS",
                        "rules": [
                            {
                                "id": "js.sqli",
                                "shortDescription": {"text": "SQL injection"},
                                "defaultConfiguration": {"level": "error"},
                                "properties": {"tags": ["CWE-89: SQL Injection"]},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "js.sqli",
                        "message": {"text": "SQL injection"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/app.js"},
                                    "region": {"startLine": 3},
                                }
                            }
                        ],
                    },
                    {
                        "ruleId": "js.sqli",
                        "message": {"text": "outside"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "../x.js"},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                    },
                ],
            }
        ],
    }
    out = path / "semgrep.sarif"
    out.write_text(json.dumps(data))
    return out


def test_cli_end_to_end_with_audit_and_replay(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    write(repo, "src/app.js", "a\nb\ndb.query('x' + req.body.id)\n")
    sarif = sarif_fixture(tmp_path)
    run_file = tmp_path / "run.json"
    res = runner.invoke(app, ["scan", str(repo), "-i", str(sarif), "-o", str(run_file)])
    assert res.exit_code == 0, res.output
    run = json.loads(run_file.read_text())
    assert len(run["findings"]) == 1  # the ../x.js result was dropped

    sup = tmp_path / "sup.yaml"
    sup.write_text("version: 1\nsuppressions: []\n")
    log = tmp_path / "audit.jsonl"
    args = [
        "report",
        str(run_file),
        "-o",
        str(tmp_path / "out"),
        "--enrich",
        "heuristic",
        "--as-of",
        "2026-10-23",
        "--suppressions",
        str(sup),
        "--audit-log",
        str(log),
    ]
    res = runner.invoke(app, args)
    assert res.exit_code == 1  # one high, actionable finding
    sarif_out = json.loads((tmp_path / "out" / "report.sarif").read_text())
    result = sarif_out["runs"][0]["results"][0]
    assert (
        result["partialFingerprints"]["triageFingerprint/v1"] == run["findings"][0]["fingerprint"]
    )

    res = runner.invoke(app, ["replay", "--audit-log", str(log)])
    assert res.exit_code == 0, res.output
    assert "byte-for-byte" in res.output

    fp = run["findings"][0]["fingerprint"]
    res = runner.invoke(app, ["explain", fp[:10], "--audit-log", str(log)])
    assert res.exit_code == 0 and "actionable" in res.output

    # Suppress it, report again: exit 0, and the log explains why it is hidden.
    sup.write_text(
        "version: 1\nsuppressions:\n"
        f"  - id: SUP-7\n    match: {{fingerprint: {fp}}}\n"
        "    reason: Parameterized by the ORM wrapper, verified manually.\n"
        "    author: sec@example.com\n    created: 2026-10-20\n    expires: 2026-12-31\n"
    )
    res = runner.invoke(app, args)
    assert res.exit_code == 0, res.output
    res = runner.invoke(app, ["explain", fp, "--audit-log", str(log)])
    assert "suppressed by SUP-7" in res.output

    # Changing an input after the fact makes replay refuse rather than pass silently.
    sup.write_text(sup.read_text().replace("2026-12-31", "2027-12-31"))
    res = runner.invoke(app, ["replay", "--audit-log", str(log)])
    assert res.exit_code == 2 and "changed" in res.output

    res = runner.invoke(app, ["verify-log", str(log)])
    assert res.exit_code == 0 and res.output.startswith("ok:")
