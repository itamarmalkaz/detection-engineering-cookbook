"""Render prod `sentinel-kql` detections into a Bicep parameters file for Microsoft Sentinel scheduled
analytics rules, and (optionally) deploy with `az deployment group what-if` / `create`.

    python tools/sentinel_deploy.py render                 # -> infra/sentinel/rules.generated.json
    python tools/sentinel_deploy.py what-if  -g RG -w WS   # az what-if (no change)
    python tools/sentinel_deploy.py deploy   -g RG -w WS   # az deployment (CI runs this only on main with approval)

The Bicep template (infra/sentinel/main.bicep) loops over the rules array; one source of truth, the YAML."""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import uuid

from common import ROOT, load_attack, load_content

SEV = {"informational": "Informational", "low": "Low", "medium": "Medium", "high": "High", "critical": "High"}
OUT = ROOT / "infra" / "sentinel" / "rules.generated.json"


def iso_duration(s: str) -> str:
    n, u = int(s[:-1]), s[-1]
    return {"m": f"PT{n}M", "h": f"PT{n}H", "d": f"P{n}D"}[u]


def render() -> dict:
    attack = load_attack(); rules = []
    for _, r in load_content():
        if r["kind"] != "detection" or r["platform"] != "sentinel-kql" or r["status"] != "prod": continue
        sched = r.get("schedule") or {"frequency": "1h", "lookback": "1h"}
        rules.append({
            "name": str(uuid.uuid5(uuid.NAMESPACE_URL, f"cookbook/{r['id']}")),
            "displayName": f"[{r['id']}] {r['name']}",
            "description": r["description"].strip(),
            "severity": SEV[r["severity"]],
            "query": r["query"].strip(),
            "queryFrequency": iso_duration(sched["frequency"]), "queryPeriod": iso_duration(sched["lookback"]),
            "tactics": [attack["tactics"][t].replace(" ", "") for t in r["attack"]["tactics"]],
            "techniques": [t.split(".")[0] for t in r["attack"]["techniques"]],
            "enabled": True,
        })
    params = {"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
              "contentVersion": "1.0.0.0", "parameters": {"rules": {"value": rules}}}
    OUT.write_text(json.dumps(params, indent=1), encoding="utf-8")
    print(f"rendered {len(rules)} prod Sentinel rules -> {OUT.relative_to(ROOT)}")
    return params


def az(mode: str, rg: str, ws: str) -> int:
    render()
    cmd = ["az", "deployment", "group", "what-if" if mode == "what-if" else "create", "-g", rg,
           "-f", str(ROOT / "infra" / "sentinel" / "main.bicep"), "-p", f"@{OUT}", "-p", f"workspaceName={ws}"]
    print(" ".join(cmd)); return subprocess.call(cmd)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("mode", choices=["render", "what-if", "deploy"])
    ap.add_argument("-g", "--resource-group"); ap.add_argument("-w", "--workspace")
    a = ap.parse_args()
    if a.mode == "render": render(); sys.exit(0)
    if not (a.resource_group and a.workspace): ap.error("-g and -w required")
    sys.exit(az(a.mode, a.resource_group, a.workspace))
