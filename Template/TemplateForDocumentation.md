# Detection Documentation Template

| Item | Description |
|------|-------------|
| **Title** | Title of the detection |
| **Goal** | What should be detected |
| **Scope** | Which entities should be checked by the detection |
| **Data source** | Which tables from which products are queried |
| **Target Engine** | For which engine the rule was developed (Defender or Sentinel) |
| **Strategy Abstract** | High-level description of what is to be detected |
| **Technical Context** | Technical workflow of the detection |
| **MITRE ATT&CK Tactic identifier** | Example: TA0001 (Initial Access)<br>TA0003 (Persistence) |
| **MITRE ATT&CK Technique identifier** | Example: T1078 (Valid Accounts)<br>T1556 (Modify Authentication Process) |
| **Feasibility** | Yes/No (Is it feasible?) |
| **Severity** | Low; Medium; High |
| **Artifacts** | Example: UserPrincipalName, DeviceName, IPAddress |
| **Blind Spots and assumptions** | Example: Assumes Break Glass Accounts are properly documented and monitored.<br>May not detect token-based or password spray attacks if MFA is bypassed.<br>If conditional access policies exclude emergency accounts, security gaps could exist. |
| **False Positives** | Example: Legitimate use of emergency accounts during IT maintenance or disaster recovery.<br>Expected authentication from approved locations/devices. |
| **Validation** | Example: Logging in with break glass account. |
| **Version** | 1.0 |
| **Response** | Example: Escalate this incident after verifying Source IP |
| **Additional Resources** | Example: Microsoft Entra Sign-In Logs<br>MITRE ATT&CK T1078 - Valid Accounts |
| **Comments** | Example: Waiting for SOC |
| **Suppressions** | Example: The following watchlist is used to exclude users: wtrWatchlistUserAusnahme |
| **Detection Logic** | If applicable, existing detection logic |
| **Change Log** | Example: v1.0: Initial version created (12.02.2025)<br>v1.1: Weitere Exclusion hinzugefügt für User "abc" (15.02.2025) |
| **Notables** | What was found in review? |
| **Test protocol done + Link** | Yes/No |
| **KQL Query** | Query goes here |