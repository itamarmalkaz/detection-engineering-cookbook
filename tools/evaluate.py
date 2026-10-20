"""Portable detection logic evaluator.

A rule's `logic` block is a Sigma-style predicate tree that mirrors the native query (XQL / KQL). CI runs it
against the rule's own sample events so the *intent* of a detection is unit-tested on every change, even
though the query engine is not available in CI.

Grammar
-------
    node := {"all": [node, ...]} | {"any": [node, ...]} | {"not": node} | leaf
    leaf := {"field": "<dotted.path>", "<op>": <value>}
    ops  := eq ne in not_in contains not_contains icontains startswith endswith regex gt gte lt lte exists

String comparisons are case-insensitive for eq/in/startswith/endswith (log data is rarely case-stable);
`contains` is case-sensitive, `icontains` is not. A missing field fails every operator except `exists: false`.
"""
from __future__ import annotations

import re
from typing import Any

_MISSING = object()


def get_field(event: dict, path: str) -> Any:
    cur: Any = event
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return _MISSING
    return cur


def _norm(v: Any) -> Any:
    return v.lower() if isinstance(v, str) else v


def _leaf(event: dict, leaf: dict) -> bool:
    field = leaf["field"]
    value = get_field(event, field)
    ops = {k: v for k, v in leaf.items() if k != "field"}
    if len(ops) != 1:
        raise ValueError(f"leaf for {field!r} must have exactly one operator, got {sorted(ops)}")
    (op, arg), = ops.items()
    if op == "exists":
        return (value is not _MISSING) == bool(arg)
    if value is _MISSING:
        return False
    if op == "eq": return _norm(value) == _norm(arg)
    if op == "ne": return _norm(value) != _norm(arg)
    if op == "in": return _norm(value) in [_norm(a) for a in arg]
    if op == "not_in": return _norm(value) not in [_norm(a) for a in arg]
    if op == "contains": return str(arg) in str(value)
    if op == "not_contains": return str(arg) not in str(value)
    if op == "icontains": return str(arg).lower() in str(value).lower()
    if op == "startswith": return str(value).lower().startswith(str(arg).lower())
    if op == "endswith": return str(value).lower().endswith(str(arg).lower())
    if op == "regex": return re.search(arg, str(value)) is not None
    if op == "gt": return value > arg
    if op == "gte": return value >= arg
    if op == "lt": return value < arg
    if op == "lte": return value <= arg
    raise ValueError(f"unknown operator {op!r} on field {field!r}")


def evaluate(logic: dict, event: dict) -> bool:
    if "all" in logic: return all(evaluate(n, event) for n in logic["all"])
    if "any" in logic: return any(evaluate(n, event) for n in logic["any"])
    if "not" in logic: return not evaluate(logic["not"], event)
    if "field" in logic: return _leaf(event, logic)
    raise ValueError(f"malformed logic node: {logic!r}")


def run_tests(rule: dict) -> list[str]:
    """Return a list of failure messages (empty = all sample events behave as expected)."""
    failures = []
    logic = rule.get("logic")
    for t in rule.get("tests") or []:
        try:
            got = evaluate(logic, t["event"])
        except Exception as e:  # noqa: BLE001 - report, don't crash the whole run
            failures.append(f"{rule['id']} test {t['name']!r}: error {e}")
            continue
        if got != t["expect"]:
            failures.append(f"{rule['id']} test {t['name']!r}: expected {t['expect']}, got {got}")
    return failures
