# Explain web alert via browser referer

**For:** DNS / web-reputation alerts where the question is "why did this host talk to that domain?"

**Automation already did**

1. Ran an endpoint script that exports browser history, retrieved the JSON to the war room.
2. Checked the connection came from a browser process (if not → analyst, this recipe does not apply).
3. Looked for direct access to the domain (typed / bookmarked) in the window around the alert.
4. Cut history to the alert window, dropped allow-listed URLs, crawled candidate pages and found the page that
   references the alerted domain or IP (the referer).
5. Searched the indicator store first so nothing is fed twice.

**You decide**

| Finding | Action |
|---|---|
| Referer is a known site (ad, embedded resource) | close with the note; nothing to block |
| Referer is unknown | reputation of the referer; feed the *referer* domain for block, not the alerted one |
| Direct access, domain unknown | feed the domain for block, notify the user |
| No history / not a browser | continue as an endpoint investigation |

**Observe-only twin:** same steps, writes the note, never feeds. Use it for the first weeks of a new rule.

Full flow and diagram: [soc-automation-ideas › Explain Web Alert via Browser Referer](https://github.com/itamarmalkaz/soc-automation-ideas/blob/main/playbooks/explain-web-alert-via-browser-referer.md)
