# Detection engineering cookbook

Detections as code, with the pipeline that keeps them honest: a strict schema, a CI gate that unit-tests each
rule's logic without a query engine, ATT&CK coverage computed from the content against a threat profile, promotion
by labelled pull request, and Microsoft Sentinel deployment from the same YAML through Bicep.

```
detections/   one YAML per rule: query + ATT&CK + validation + tests + response + simulation
hunts/        same schema, fewer required fields
tools/        validate · evaluate · coverage · promote · sentinel_deploy · attack_refresh
coverage/     generated: Navigator layer, per-tactic table, gap backlog   (CI commits these)
profile/      who targets us -> what must be covered
infra/        Bicep for Sentinel scheduled analytics rules
playbooks/    response recipes the rules hand off to
docs/         COOKBOOK.md (the method, chapter by chapter), TEMPLATE.yml
```

**Read first:** [docs/COOKBOOK.md](docs/COOKBOOK.md) — the method in eleven short chapters.

## What the pipeline does on every pull request

1. `tools/validate.py` — schema, ATT&CK consistency, platform query lint, no organisation tokens, logic tests
   against each rule's sample events, promotion rules. Any failure fails the build.
2. `pytest` — tests for the tooling itself.
3. `tools/coverage.py` — regenerates the ATT&CK Navigator layer, the per-tactic coverage table and the gap
   backlog against `profile/threat-profile.yml`; posted as a job summary and committed on `main`.
4. `tools/sentinel_deploy.py` — renders prod `sentinel-kql` rules to Bicep parameters; `az what-if` on PRs,
   deployment on `main` behind an approved environment.

Promotion: label a PR `promote:qa` / `promote:prod` → status moves one step, gate re-runs, change committed to
the branch for review. See `.github/workflows/`.

## Platforms

Cortex XSIAM (XQL), Microsoft Sentinel (KQL), Microsoft Defender XDR (advanced hunting KQL). Queries never carry
an organisation domain, address or IP — profile variables (`${ORG_DOMAINS}`, `${JIT_SERVICE_PRINCIPAL}`, …) are
substituted at deployment.

## Status

Framework complete and green; content is being migrated rule by rule from a production tenant (each rule is
rewritten against the schema, generic, with sample events). `coverage/gaps.md` is the live backlog.

## Related

- [soc-automation-ideas](https://github.com/itamarmalkaz/soc-automation-ideas) — the response side: 84 SOAR flows with diagrams, building blocks and design patterns.
- [SOC-Portal](https://github.com/itamarmalkaz/SOC-Portal) — the governance layer next to the SIEM: exclusion approval pipeline, rule lifecycle (draft → QA → prod), ATT&CK coverage on the Today page, IOC feeding log.

## Run locally

```bash
pip install -r requirements.txt
make test        # gate + tooling tests
make coverage    # regenerate coverage/
```

MIT licence.
