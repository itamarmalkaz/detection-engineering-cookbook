# ATT&CK coverage

6 content items · 0 detections in prod · 6 techniques covered (4 with a prod rule).

Reference = techniques in `data/attack-techniques.json` (the curated set this profile cares about).

| Tactic | Covered / reference | Prod | Techniques |
|---|---|---|---|
| Reconnaissance (TA0043) | 0 / 1 | 0 | T1598.003 |
| Initial Access (TA0001) | 3 / 7 | 3 | T1078, T1078.004, T1133, T1190, T1566★, T1566.001★, T1566.002★ |
| Execution (TA0002) | 1 / 8 | 1 | T1047, T1053.005, T1059, T1059.001, T1059.003, T1059.007, T1204.001★, T1204.002 |
| Persistence (TA0003) | 0 / 12 | 0 | T1053.005, T1078, T1078.004, T1098, T1098.003, T1098.005, T1133, T1136.001, T1136.002, T1543.003, T1547.001, T1556.006 |
| Privilege Escalation (TA0004) | 0 / 9 | 0 | T1053.005, T1078, T1078.004, T1098, T1098.003, T1098.005, T1543.003, T1547.001, T1548.002 |
| Defense Evasion (TA0005) | 0 / 12 | 0 | T1027, T1036, T1036.005, T1070.001, T1078, T1078.004, T1218.005, T1218.011, T1548.002, T1556.006, T1562.001, T1562.004 |
| Credential Access (TA0006) | 0 / 8 | 0 | T1003.001, T1110, T1110.001, T1110.003, T1556.006, T1557, T1558.003, T1621 |
| Discovery (TA0007) | 0 / 3 | 0 | T1018, T1087.002, T1482 |
| Lateral Movement (TA0008) | 0 / 3 | 0 | T1021.001, T1021.002, T1021.006 |
| Collection (TA0009) | 0 / 4 | 0 | T1114.002, T1114.003, T1557, T1560 |
| Command and Control (TA0011) | 2 / 7 | 0 | T1071.001, T1071.004☆, T1090.003, T1105, T1219, T1568.002☆, T1572 |
| Exfiltration (TA0010) | 0 / 3 | 0 | T1041, T1048.003, T1567.002 |
| Impact (TA0040) | 0 / 3 | 0 | T1486, T1490, T1491.002 |

★ prod rule · ☆ draft/qa only · none = gap

## Techniques and the rules behind them

| Technique | Name | Maturity | Rules |
|---|---|---|---|
| T1071.004 | Application Layer Protocol: DNS | qa | `DET-0001` |
| T1204.001 | User Execution: Malicious Link | prod | `HUNT-0003` |
| T1566 | Phishing | prod | `HUNT-0005` |
| T1566.001 | Phishing: Spearphishing Attachment | prod | `HUNT-0001`, `HUNT-0002` |
| T1566.002 | Phishing: Spearphishing Link | prod | `HUNT-0001`, `HUNT-0002`, `HUNT-0003`, `HUNT-0004` |
| T1568.002 | Dynamic Resolution: Domain Generation Algorithms | qa | `DET-0001` |
