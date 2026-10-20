"""Regenerate data/attack-techniques.json from the official MITRE ATT&CK STIX bundle, keeping only the
techniques referenced by content or by the threat profile (plus whatever is already listed), so the file stays
small and reviewable. Needs internet; CI uses the committed file.

    python tools/attack_refresh.py
"""
from __future__ import annotations

import json
import urllib.request

from common import ATTACK, load_attack, load_content, load_profile

STIX = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
SHORT = {"reconnaissance": "TA0043", "resource-development": "TA0042", "initial-access": "TA0001", "execution": "TA0002",
         "persistence": "TA0003", "privilege-escalation": "TA0004", "defense-evasion": "TA0005", "credential-access": "TA0006",
         "discovery": "TA0007", "lateral-movement": "TA0008", "collection": "TA0009", "command-and-control": "TA0011",
         "exfiltration": "TA0010", "impact": "TA0040"}


def main():
    cur = load_attack(); wanted = set(cur["techniques"])
    for _, r in load_content(): wanted |= set(r["attack"]["techniques"])
    prof = load_profile(); wanted |= set(prof["priority_techniques"])
    for a in prof["actors"]: wanted |= set(a["techniques"])
    bundle = json.load(urllib.request.urlopen(STIX, timeout=60))
    techs = {}
    for o in bundle["objects"]:
        if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"): continue
        tid = next((x["external_id"] for x in o.get("external_references", []) if x.get("source_name") == "mitre-attack"), None)
        if tid not in wanted: continue
        tactics = sorted({SHORT[p["phase_name"]] for p in o.get("kill_chain_phases", []) if p["phase_name"] in SHORT})
        techs[tid] = {"name": o["name"], "tactics": tactics}
    version = next((o.get("x_mitre_version") for o in bundle["objects"] if o.get("type") == "x-mitre-collection"), "?")
    out = {"_meta": {"source": "MITRE ATT&CK Enterprise (curated subset; run tools/attack_refresh.py to regenerate from the STIX bundle)",
                     "version": f"v{version}"}, "tactics": cur["tactics"], "techniques": dict(sorted(techs.items()))}
    ATTACK.write_text(json.dumps(out, indent=1), encoding="utf-8")
    missing = wanted - set(techs)
    print(f"{len(techs)} techniques written; missing/retired: {sorted(missing) or 'none'}")


if __name__ == "__main__":
    main()
