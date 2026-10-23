from __future__ import annotations

from pathlib import Path

from conftest import raw, write

from triage.dedup import drop_exact_repeats, merge
from triage.engine import build_run, diff_runs
from triage.fingerprint import fingerprint_all
from triage.model import Kind, Severity
from triage.source import SourceTree

TF = """\
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  map_public_ip_on_launch = true
}
"""


def findings(root: Path, *raws):  # type: ignore[no-untyped-def]
    found, stats = merge(fingerprint_all(raws, SourceTree(root)))
    return found, stats


def test_same_secret_from_three_scanners_is_one_finding(tmp_path: Path) -> None:
    write(tmp_path, "cfg.ts", "x\nconst jwt = 'aaa.bbb.ccc'\n")
    common = {"kind": Kind.SECRET, "path": "cfg.ts", "line": 2}
    out, stats = findings(
        tmp_path,
        raw(scanner="trivy", rule="jwt-token", severity=Severity.MEDIUM, **common),
        raw(scanner="semgrep", rule="generic.secrets.detected-jwt-token", **common),
        raw(scanner="gitleaks", rule="jwt", **common),
    )
    assert len(out) == 1
    [f] = out
    assert {s.scanner for s in f.sources} == {"trivy", "semgrep", "gitleaks"}
    assert f.rule_id == "jwt"  # gitleaks is primary for secrets
    assert f.severity is Severity.HIGH  # highest among sources
    assert len(f.aliases) == 2
    assert stats.cross_scanner_duplicates == 2


def test_two_rules_from_one_scanner_on_one_line_stay_separate(tmp_path: Path) -> None:
    write(tmp_path, "app.js", "a\nb\neval(req.body.x + y)\n")
    out, _ = findings(
        tmp_path,
        raw(rule="js.eval-injection", cwe=("CWE-95",)),
        raw(rule="js.string-concat", cwe=("CWE-95",)),
    )
    assert len(out) == 2


def test_cross_scanner_code_merges_on_shared_cwe(tmp_path: Path) -> None:
    write(tmp_path, "app.js", "a\nb\neval(req.body.x)\n")
    out, stats = findings(
        tmp_path,
        raw(scanner="semgrep", rule="js.eval", cwe=("CWE-95",)),
        raw(scanner="other", rule="EVAL-1", cwe=("CWE-95",)),
    )
    assert len(out) == 1
    assert stats.cross_scanner_duplicates == 1


def test_listed_equivalence_merges_config_without_cwe(tmp_path: Path) -> None:
    write(tmp_path, "net.tf", TF)
    common = {"kind": Kind.CONFIG, "path": "net.tf"}
    out, _ = findings(
        tmp_path,
        raw(scanner="trivy", rule="AWS-0164", line=3, **common),
        raw(
            scanner="semgrep",
            rule="terraform.aws.security.aws-subnet-has-public-ip-address.aws-subnet-has-public-ip-address",
            line=1,
            end=4,
            **common,
        ),
    )
    assert len(out) == 1
    assert out[0].rule_id == "AWS-0164"  # trivy is primary for config


def test_colocated_but_different_config_checks_stay_separate(tmp_path: Path) -> None:
    write(tmp_path, "lb.tf", TF)
    common = {"kind": Kind.CONFIG, "path": "lb.tf"}
    out, _ = findings(
        tmp_path,
        raw(scanner="trivy", rule="AWS-0052", line=1, end=4, **common),
        raw(
            scanner="semgrep",
            rule="terraform.aws.security.aws-elb-access-logs-not-enabled.x",
            line=1,
            end=4,
            **common,
        ),
    )
    assert len(out) == 2


def test_exact_repeats_collapse() -> None:
    a = raw()
    kept, dropped = drop_exact_repeats([a, a, raw(line=9)])
    assert len(kept) == 2
    assert dropped == 1


def test_diff_matches_through_aliases(tmp_path: Path) -> None:
    """Adding a scanner must not make an existing finding look new."""
    write(tmp_path, "cfg.ts", "x\nconst jwt = 'aaa.bbb.ccc'\n")
    common = {"kind": Kind.SECRET, "path": "cfg.ts", "line": 2}
    trivy_only = [raw(scanner="trivy", rule="jwt-token", **common)]
    both = [*trivy_only, raw(scanner="gitleaks", rule="jwt", **common)]
    base = build_run(trivy_only, tmp_path, root_name="r", commit=None, scanners=["trivy"])
    head = build_run(both, tmp_path, root_name="r", commit=None, scanners=["trivy", "gitleaks"])
    assert base.findings[0].fingerprint != head.findings[0].fingerprint  # primary changed
    d = diff_runs(base, head)
    assert (len(d.new), len(d.fixed), len(d.unchanged)) == (0, 0, 1)


def test_diff_reports_new_and_fixed(tmp_path: Path) -> None:
    write(tmp_path, "app.js", "a\nb\neval(x)\nexec(y)\n")
    base = build_run([raw(line=3)], tmp_path, root_name="r", commit=None, scanners=[])
    head = build_run(
        [raw(line=4, rule="js.exec")], tmp_path, root_name="r", commit=None, scanners=[]
    )
    d = diff_runs(base, head)
    assert [f.rule_id for f in d.new] == ["js.exec"]
    assert [f.rule_id for f in d.fixed] == ["js.sqli"]


def test_title_is_first_sentence(tmp_path: Path) -> None:
    from triage.dedup import _title

    long = "This Dependabot configuration does not set a cooldown period. Newly published " * 3
    assert _title(long) == "This Dependabot configuration does not set a cooldown period."
    assert _title("word " * 100).endswith("…")
    assert len(_title("word " * 100)) <= 160
