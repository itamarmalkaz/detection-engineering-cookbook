"""Promotion is a code change: draft -> qa -> prod, one step at a time, with the gate re-run.

    python tools/promote.py DET-0007 qa          # draft -> qa
    python tools/promote.py DET-0007 prod        # qa -> prod (requires simulation + lab_run for manual rules)
    python tools/promote.py DET-0007 retired

The GitHub workflow `promote.yml` calls this when a maintainer adds the label promote:qa / promote:prod to a
PR, then commits the change back so the promotion is reviewed like any other diff."""
from __future__ import annotations

import datetime as dt
import sys

from common import STATUS_ORDER, dump_yaml, load_content


def main(rule_id: str, target: str) -> int:
    for path, r in load_content():
        if r.get("id") != rule_id: continue
        cur = r["status"]
        if target == "retired":
            pass
        elif STATUS_ORDER.index(target) != STATUS_ORDER.index(cur) + 1:
            print(f"refusing: {rule_id} is {cur}; promotion goes one step at a time (next: {STATUS_ORDER[STATUS_ORDER.index(cur)+1]})")
            return 1
        if target == "prod":
            if not r.get("simulation"): print("refusing: prod needs a `simulation` block (how to prove it fires)"); return 1
            if r.get("validation", {}).get("method") == "manual" and not r["validation"].get("lab_run"):
                print("refusing: manual-validated rule needs validation.lab_run before prod"); return 1
        r["status"] = target; r["updated"] = dt.date.today().isoformat()
        dump_yaml(r, path); print(f"{rule_id}: {cur} -> {target} ({path.name})")
        return 0
    print(f"{rule_id} not found"); return 1


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[2] not in STATUS_ORDER: print(__doc__); sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2]))
