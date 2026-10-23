from __future__ import annotations

from conftest import raw

from triage.engine import build_run
from triage.enrich.heuristic import enrich, path_class
from triage.model import Confidence, Finding, Kind, Package, RawFinding, Severity, Verdict


def one(r: RawFinding) -> Finding:
    return build_run([r], None, root_name="r", commit=None, scanners=[]).findings[0]


def test_path_classes() -> None:
    assert path_class("src/app/login.spec.ts") == "test"
    assert path_class("tests/test_api.py") == "test"
    assert path_class("pkg/handler_test.go") == "test"
    assert path_class("docs/config.rst") == "non-shipped"
    assert path_class("examples/celery/requirements.txt") == "non-shipped"
    assert path_class("src/flask/app.py") == "production"
    assert path_class("contest/app.py") == "production"  # "test" inside a word is not a test dir


def test_code_in_tests_is_demoted() -> None:
    e = enrich(one(raw(path="test/api.test.js")))
    assert e.exploitable is Verdict.UNLIKELY
    assert e.suggested_severity is Severity.LOW  # high shifted two levels


def test_secret_in_docs_is_unlikely_but_not_dismissed() -> None:
    e = enrich(one(raw(kind=Kind.SECRET, scanner="gitleaks", rule="k", path="docs/config.rst")))
    assert e.exploitable is Verdict.UNLIKELY
    assert "confirm it is not valid" in e.reasoning


def test_secret_in_shipped_code_is_treated_as_live() -> None:
    e = enrich(one(raw(kind=Kind.SECRET, scanner="gitleaks", rule="k", path="lib/auth.ts")))
    assert e.exploitable is Verdict.LIKELY
    assert e.suggested_severity is Severity.HIGH


def test_dependency_in_example_manifest_is_demoted() -> None:
    pkg = Package(name="jinja2", version="3.1.2", fixed_version="3.1.6")
    f = one(
        raw(
            kind=Kind.DEPENDENCY,
            scanner="trivy",
            rule="CVE-1",
            package=pkg,
            path="examples/celery/requirements.txt",
        )
    )
    assert enrich(f).exploitable is Verdict.UNLIKELY


def test_low_confidence_rule_is_demoted_one_level() -> None:
    f = one(raw(path="render/json.go", severity=Severity.MEDIUM))
    f = f.model_copy(update={"rule_confidence": Confidence.LOW})
    e = enrich(f)
    assert e.suggested_severity is Severity.LOW
    assert "low-confidence" in e.reasoning


def test_unknown_stays_unknown() -> None:
    e = enrich(one(raw(path="src/app.js")))
    assert (e.exploitable, e.suggested_severity) == (Verdict.UNKNOWN, Severity.HIGH)
