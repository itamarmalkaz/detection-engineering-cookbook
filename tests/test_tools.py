"""Tests for the cookbook tooling itself. The content gate (schema + logic tests over every rule) is
tools/validate.py; here we test the evaluator, the lint, the coverage maths and the promotion rules."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from evaluate import evaluate, run_tests  # noqa: E402
from validate import lint_query  # noqa: E402


# ---------------------------------------------------------------- evaluator
def test_leaf_operators():
    ev = {"a": {"b": "Hello World", "n": 5}, "l": "x"}
    assert evaluate({"field": "a.b", "eq": "hello world"}, ev)
    assert evaluate({"field": "a.b", "contains": "World"}, ev)
    assert not evaluate({"field": "a.b", "contains": "world"}, ev)
    assert evaluate({"field": "a.b", "icontains": "world"}, ev)
    assert evaluate({"field": "a.b", "startswith": "HELLO"}, ev)
    assert evaluate({"field": "a.b", "regex": r"W\w+d$"}, ev)
    assert evaluate({"field": "a.n", "gte": 5}, ev) and not evaluate({"field": "a.n", "gt": 5}, ev)
    assert evaluate({"field": "a.b", "in": ["HELLO WORLD", "x"]}, ev)
    assert evaluate({"field": "missing", "exists": False}, ev)
    assert not evaluate({"field": "missing", "eq": "x"}, ev), "missing field never matches a value operator"


def test_tree_combinators():
    ev = {"p": {"name": "x.exe"}, "q": 1}
    logic = {"all": [{"field": "p.name", "eq": "x.exe"}, {"not": {"field": "q", "eq": 2}}, {"any": [{"field": "q", "eq": 9}, {"field": "q", "eq": 1}]}]}
    assert evaluate(logic, ev)
    with pytest.raises(ValueError):
        evaluate({"field": "p.name", "eq": "x", "ne": "y"}, ev)
    with pytest.raises(ValueError):
        evaluate({"bogus": []}, ev)


def test_run_tests_reports_mismatches():
    rule = {"id": "DET-9999", "logic": {"field": "a", "eq": 1}, "tests": [{"name": "t1", "event": {"a": 1}, "expect": True}, {"name": "t2", "event": {"a": 2}, "expect": True}]}
    out = run_tests(rule)
    assert out == ["DET-9999 test 't2': expected True, got False"]


# ---------------------------------------------------------------- lint
def test_lint_refuses_org_tokens_and_limits():
    assert "no trailing `| limit` in a detection (hides hits)" in lint_query("xsiam-xql", "dataset = x\n| limit 10")
    assert any("organisation-specific" in m for m in lint_query("sentinel-kql", "SigninLogs | where IPAddress == '10.1.2.3'"))
    assert lint_query("sentinel-kql", "let own = dynamic([${ORG_DOMAINS}]);\nSigninLogs | where a == 1") == []
    assert lint_query("xsiam-xql", "config case_sensitive = false | dataset = x") == []


# ---------------------------------------------------------------- end to end: validate + coverage on the repo content
def run(*args):
    return subprocess.run([sys.executable, *args], cwd=ROOT, capture_output=True, text=True)


def test_repo_content_passes_the_gate():
    r = run("tools/validate.py")
    assert r.returncode == 0, r.stdout + r.stderr


def test_coverage_artifacts_are_consistent():
    r = run("tools/coverage.py")
    assert r.returncode == 0, r.stdout + r.stderr
    layer = json.loads((ROOT / "coverage" / "navigator-layer.json").read_text(encoding="utf-8"))
    assert layer["techniques"], "layer must list at least one technique"
    for t in layer["techniques"]:
        assert 1 <= t["score"] <= 3
    gaps = (ROOT / "coverage" / "gaps.md").read_text(encoding="utf-8")
    assert "Profile coverage:" in gaps


def test_promotion_is_one_step_and_gated(tmp_path):
    import shutil
    import promote
    src = next((ROOT / "detections").glob("det-0001-*.yml"))
    work = tmp_path / "detections"; work.mkdir(); shutil.copy(src, work / src.name)
    (tmp_path / "hunts").mkdir()
    import common
    old = common.CONTENT_DIRS
    common.CONTENT_DIRS = (work, tmp_path / "hunts")
    try:
        assert promote.main("DET-0001", "prod") == 1, "qa -> prod must be refused without a simulation block"
        assert promote.main("DET-0001", "retired") == 0
    finally:
        common.CONTENT_DIRS = old


def test_sentinel_render_only_prod_sentinel_rules():
    r = run("tools/sentinel_deploy.py", "render")
    assert r.returncode == 0, r.stdout + r.stderr
    params = json.loads((ROOT / "infra" / "sentinel" / "rules.generated.json").read_text(encoding="utf-8"))
    for rule in params["parameters"]["rules"]["value"]:
        assert rule["queryFrequency"].startswith("P") and rule["severity"] in {"Informational", "Low", "Medium", "High"}
