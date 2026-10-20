"""Validate every detection and hunt: schema, ATT&CK references, platform query lint, duplicate ids,
promotion rules, and the portable-logic unit tests. Exit 1 on any failure. This is the CI gate."""
from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from common import load_attack, load_content, load_schema
from evaluate import run_tests

LINT = {
    "xsiam-xql": [
        (r"^\s*(datamodel|dataset|config|preset)\b", "XQL must start with datamodel/dataset/config/preset"),
        (r"\|\s*limit\s+\d+\s*$", "no trailing `| limit` in a detection (hides hits)", True),
    ],
    "sentinel-kql": [
        (r"^\s*(let\s|\w+\s*\|)", "KQL must start with a table or a let binding"),
        (r"\|\s*take\s+\d+", "no `| take` in a detection", True),
    ],
    "defender-kql": [
        (r"^\s*(let\s|\w+\s*\|)", "KQL must start with a table or a let binding"),
        (r"\|\s*take\s+\d+", "no `| take` in a detection", True),
    ],
}
ORG_TOKENS = re.compile(r"(?i)\b(iai|flytru|contoso\.corp|internal\.local)\b|@[a-z0-9.-]+\.(co\.il|com)\b|\b(?:\d{1,3}\.){3}\d{1,3}\b")


def lint_query(platform: str, query: str) -> list[str]:
    out = []
    for pat, msg, *neg in LINT[platform]:
        hit = re.search(pat, query, re.M | re.I) is not None
        if neg and hit: out.append(msg)
        if not neg and not hit: out.append(msg)
    if ORG_TOKENS.search(query):
        out.append("query carries an organisation-specific token (domain, address, IP); use a profile variable")
    return out


def main() -> int:
    schema = load_schema(); attack = load_attack()
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    items = load_content()
    problems: list[str] = []
    ids = Counter(r.get("id") for _, r in items)
    for p, r in items:
        rel = p.relative_to(p.parents[1])
        for err in sorted(validator.iter_errors(r), key=lambda e: list(e.path)):
            problems.append(f"{rel}: schema: {'/'.join(map(str, err.path)) or '<root>'}: {err.message}")
        if not r.get("id"): continue
        if ids[r["id"]] > 1: problems.append(f"{rel}: duplicate id {r['id']}")
        if p.stem != r["id"].lower() and not p.stem.startswith(r["id"].lower() + "-"):
            problems.append(f"{rel}: file name must start with the id ({r['id'].lower()}-...)")
        if r.get("kind") == "hunt" and not r["id"].startswith("HUNT"): problems.append(f"{rel}: hunts use HUNT- ids")
        if r.get("kind") == "detection" and not r["id"].startswith("DET"): problems.append(f"{rel}: detections use DET- ids")
        for ta in r.get("attack", {}).get("tactics", []):
            if ta not in attack["tactics"]: problems.append(f"{rel}: unknown tactic {ta}")
        for t in r.get("attack", {}).get("techniques", []):
            if t not in attack["techniques"]:
                problems.append(f"{rel}: unknown technique {t} (run tools/attack_refresh.py or fix the id)")
            else:
                tt = set(attack["techniques"][t]["tactics"]); declared = set(r["attack"]["tactics"])
                if not tt & declared:
                    problems.append(f"{rel}: technique {t} belongs to {sorted(tt)}, not to the declared tactics {sorted(declared)}")
        if r.get("platform") in LINT and r.get("query"):
            problems += [f"{rel}: lint: {m}" for m in lint_query(r["platform"], r["query"])]
        v = r.get("validation") or {}
        if v.get("method") == "unit":
            problems += [f"{rel}: {m}" for m in run_tests(r)]
            if r.get("tests") and not any(t["expect"] for t in r["tests"]): problems.append(f"{rel}: needs at least one positive test")
            if r.get("tests") and not any(not t["expect"] for t in r["tests"]): problems.append(f"{rel}: needs at least one negative test")
        if v.get("method") == "manual" and r.get("status") == "prod" and not v.get("lab_run"):
            problems.append(f"{rel}: manual-validated rule cannot be prod without validation.lab_run date")
        if r.get("kind") == "detection" and r.get("status") == "prod" and not r.get("simulation"):
            problems.append(f"{rel}: prod detections must say how to simulate them (simulation.atomic or bas_scenario)")
    for m in problems: print("FAIL", m)
    print(f"{len(items)} items checked, {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
