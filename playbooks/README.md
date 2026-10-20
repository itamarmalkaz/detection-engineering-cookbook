# Response recipes

Every detection names the recipe its alert hands off to (`response.playbook`). The full catalogue of flows —
84 playbooks with workflow, Mermaid diagram and building blocks — lives in the companion notebook
[soc-automation-ideas](https://github.com/itamarmalkaz/soc-automation-ideas). The pages here are the short
version: what the responder does in the first ten minutes, and what the automation already did.

| Recipe | Used by | Automation does | Person does |
|---|---|---|---|
| [Explain web alert via browser referer](explain-web-alert-via-referer.md) | DNS / web alerts | pulls browser history around the alert, finds the page that embedded the request, drops allow-listed URLs | decides on block when no referer explains it |
| [Fallback investigation](fallback-investigation.md) | anything without a dedicated flow | bookkeeping (automated flag, severity, SLA), hands to analyst | closing reason through a form |

Conventions shared by all recipes: the three bookkeeping sub-playbooks (start, hand to analyst, close with
SLA timers) wrap every flow; exclusion lists are per action type (isolation, blockage, quarantine, remediation);
an observe-only twin of every blocking flow exists for roll-out.
