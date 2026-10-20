# Coverage gaps against the threat profile

Techniques the profile says matter (priority ≥ 1 or used by a tracked actor) that have **no prod rule**. Ranked by priority × actors. This is the detection backlog.

| Rank | Technique | Name | Priority | Actors | Current |
|---|---|---|---|---|---|
| 1 | T1105 | Ingress Tool Transfer | 3 | MuddyWater, OilRig, APT33, Lazarus Group | none |
| 2 | T1059.001 | Command and Scripting Interpreter: PowerShell | 3 | MuddyWater, OilRig, APT33 | none |
| 3 | T1557 | Adversary-in-the-Middle | 3 | Magic Hound (Charming Kitten) | none |
| 4 | T1486 | Data Encrypted for Impact | 3 | Agrius | none |
| 5 | T1114.003 | Email Collection: Email Forwarding Rule | 3 | Magic Hound (Charming Kitten) | none |
| 6 | T1110.003 | Brute Force: Password Spraying | 3 | APT33 | none |
| 7 | T1078.004 | Valid Accounts: Cloud Accounts | 3 | Magic Hound (Charming Kitten) | none |
| 8 | T1003.001 | OS Credential Dumping: LSASS Memory | 3 | OilRig | none |
| 9 | T1053.005 | Scheduled Task/Job: Scheduled Task | 2 | MuddyWater, APT33 | none |
| 10 | T1621 | Multi-Factor Authentication Request Generation | 2 | Magic Hound (Charming Kitten) | none |
| 11 | T1490 | Inhibit System Recovery | 2 | Agrius | none |
| 12 | T1219 | Remote Access Software | 2 | MuddyWater | none |
| 13 | T1218.011 | System Binary Proxy Execution: Rundll32 | 2 | Lazarus Group | none |
| 14 | T1190 | Exploit Public-Facing Application | 2 | Agrius | none |
| 15 | T1071.004 | Application Layer Protocol: DNS | 2 | OilRig | qa |
| 16 | T1021.001 | Remote Services: Remote Desktop Protocol | 2 | MuddyWater | none |
| 17 | T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | 2 | - | none |
| 18 | T1562.001 | Impair Defenses: Disable or Modify Tools | 2 | - | none |
| 19 | T1133 | External Remote Services | 2 | - | none |
| 20 | T1098.003 | Account Manipulation: Additional Cloud Roles | 2 | - | none |
| 21 | T1078 | Valid Accounts | - | OilRig, Agrius | none |
| 22 | T1027 | Obfuscated Files or Information | - | MuddyWater, Lazarus Group | none |
| 23 | T1598.003 | Phishing for Information: Spearphishing Link | - | Magic Hound (Charming Kitten) | none |
| 24 | T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | - | Lazarus Group | none |
| 25 | T1204.002 | User Execution: Malicious File | - | Lazarus Group | none |
| 26 | T1036.005 | Masquerading: Match Legitimate Name or Location | - | Lazarus Group | none |
| 27 | T1021.002 | Remote Services: SMB/Windows Admin Shares | - | Agrius | none |
| 28 | T1491.002 | Defacement: External Defacement | 1 | - | none |
| 29 | T1136.002 | Create Account: Domain Account | 1 | - | none |
| 30 | T1070.001 | Indicator Removal: Clear Windows Event Logs | 1 | - | none |
| 31 | T1048.003 | Exfiltration Over Alternative Protocol: Unencrypted Non-C2 Protocol | 1 | - | none |

Profile coverage: **2 / 26** priority techniques have a prod rule; 31 gaps open.
