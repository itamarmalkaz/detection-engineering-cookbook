# The cookbook

How detections are written, tested, measured, promoted and deployed here. Each chapter is a recipe you can lift
into your own repository; the tools in `tools/` are the working implementation.

## 1. One file per detection, one schema for everything

A detection is a YAML file with the native query **and** everything a reviewer needs: ATT&CK mapping, data
sources, false positives, the response recipe, how it is validated and how it is simulated. The schema
(`schema/detection.schema.json`) is strict — `additionalProperties: false` — so a field that is not in the schema
is a review comment, not a silent extra. Hunts share the schema with fewer required fields.

Why: the query is the smallest part of a detection. The decisions around it are what rot when they live in a
console.

## 2. The gate (`tools/validate.py`)

Runs on every push and pull request:

- **Schema** — required fields, enums, id/filename agreement, no duplicates.
- **ATT&CK** — every technique exists in `data/attack-techniques.json`; every technique's tactic is among the
  declared tactics (a rule cannot claim Persistence for a Discovery technique).
- **Query lint per platform** — XQL starts with `datamodel`/`dataset`/`config`; KQL starts with a table or `let`;
  no `| limit` / `| take` in detections; **no organisation token** (domain, address, IP) in any query — use a
  profile variable such as `${ORG_DOMAINS}`.
- **Logic tests** — see chapter 3.
- **Promotion rules** — prod needs a `simulation`; a manually validated rule needs a `lab_run` date.

Everything prints `FAIL path: reason` and exits 1. There is no "warning" level: either it is a rule or it is not.

## 3. Unit-testing detections without the engine (`tools/evaluate.py`)

CI has no XSIAM and no Sentinel. Instead each rule carries a **portable logic block** — a Sigma-style predicate
tree that mirrors the query — and **sample events**, at least one that must match and one that must not. The
evaluator runs the logic against the events on every change. It cannot prove the query is right; it proves the
*intent* did not drift when someone edited the exclusion list at 02:00.

Aggregate rules (counts over windows, sequences) cannot be expressed this way. They declare
`validation.method: manual` with a reason, and cannot reach `prod` until a `lab_run` date is recorded — the day
the rule was proven to fire in a lab or against a simulation.

## 4. ATT&CK coverage as a build artefact (`tools/coverage.py`)

Coverage is computed, never hand-maintained:

- `coverage/navigator-layer.json` — an ATT&CK Navigator layer; score = maturity (1 draft, 2 qa, 3 prod). Open it
  in the Navigator to see the heat map.
- `coverage/coverage.md` — per-tactic table (covered / reference, prod count) and the rules behind each technique.
- `coverage/gaps.md` — the **backlog**: techniques the threat profile cares about with no prod rule, ranked by
  priority × number of tracked actors that use them.

The reference set is `data/attack-techniques.json`, a curated subset regenerated from the official STIX bundle by
`tools/attack_refresh.py`. Keeping the subset small keeps the diff reviewable when ATT&CK changes.

## 5. The threat profile decides what "covered" means (`profile/threat-profile.yml`)

Coverage against all of ATT&CK is a vanity number. The profile lists the organisation's sectors, crown jewels,
priority techniques (weighted 1–3) and the public actor groups that target the sector, with their techniques
from the ATT&CK group pages. `gaps.md` is computed against that. When threat intel says a new group is active
against the sector, the profile changes in a PR and the backlog reorders itself.

## 6. Promotion is a diff (`tools/promote.py`, `promote.yml`)

`draft → qa → prod`, one step at a time, by a tool that refuses to skip steps and enforces the prod requirements.
In GitHub, a maintainer adds the label `promote:qa` or `promote:prod` to a PR whose title starts with the rule id;
the workflow runs the tool, re-runs the gate and commits the status change **to the PR branch**, so the promotion
is reviewed like any other change. Retiring works the same way. Nothing is promoted by editing a field by hand.

## 7. Proving a rule fires (`simulation`)

A detection reaches `prod` only with a `simulation` block: the breach-and-attack-simulation scenario or lab
exercise that makes it fire. BAS runs in production also generate real alerts; the companion notebook has the
flow that recognises simulation machines and auto-resolves them so metrics stay clean. "We have a rule for that"
is not coverage; "the simulation fired it on Tuesday" is.

## 8. Deploying to Microsoft Sentinel from the same YAML (`tools/sentinel_deploy.py`, `infra/sentinel`)

Prod rules with `platform: sentinel-kql` are rendered into a Bicep parameters file; one Bicep template loops over
them and creates scheduled analytics rules (frequency, period, severity, tactics, techniques, incident grouping).
Pull requests run `az deployment group what-if`; a push to `main` deploys inside a protected environment with
reviewer approval and OIDC federated login (no client secret in GitHub). The YAML stays the single source of truth;
the console is read-only.

## 9. Response recipes travel with the rule

`response.playbook` names the recipe the alert hands off to (`playbooks/`). The recipe says what automation
already did and what the person decides. The full automation catalogue — flows, diagrams, building blocks, design
patterns — is the companion repository [soc-automation-ideas](https://github.com/itamarmalkaz/soc-automation-ideas).

## 10. Azure security services in this cookbook

| Service | Where |
|---|---|
| Microsoft Sentinel | analytics rules deployed from YAML via Bicep (`infra/sentinel`), `sentinel-kql` content, cross-SIEM incident sync recipe in the notebook |
| Microsoft Defender XDR / Defender for Office 365 | `defender-kql` hunts over EmailEvents, EmailPostDeliveryEvents, UrlClickEvents; advanced-hunting KQL in the identity response flows |
| Microsoft Entra ID | sign-in / audit based detections (profile variables for JIT principals), session revoke + password reset remediation recipe |
| Exchange Online | campaign search-and-delete, inbox-rule monitoring |

## 11. Adding a rule in five minutes

```bash
make new ID=DET-0042 NAME=my-rule      # copies docs/TEMPLATE.yml
# edit detections/det-0042-my-rule.yml
make test                               # gate + tooling tests
make coverage                           # see where it lands on the map
git checkout -b det-0042 && git commit -am "DET-0042: my rule" && git push
# open a PR titled "DET-0042: my rule"; label promote:qa when the reviewer is happy
```
