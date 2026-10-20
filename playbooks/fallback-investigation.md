# Fallback investigation

**For:** any alert whose rule has no dedicated recipe yet. A detection may ship in `draft`/`qa` with this recipe;
it must point to a real one before `prod` if the alert volume is more than a handful a week.

**Automation already did**

1. Start bookkeeping: marked the case automated, set severity from the rule, started the SLA timers.
2. Hand to analyst: cleared the bot as owner, stamped the execution flag so dashboards count it as human work.

**You do**

1. Read the rule's `description` and `false_positives` (they are written for exactly this moment).
2. Decide: benign (close with reason), needs a recipe (open a PR adding `response.playbook`), real (escalate).
3. Closing reason through the form — structured reasons are what the weekly report counts.

Full flow: [soc-automation-ideas › Fallback Investigation](https://github.com/itamarmalkaz/soc-automation-ideas/blob/main/playbooks/fallback-investigation.md)
