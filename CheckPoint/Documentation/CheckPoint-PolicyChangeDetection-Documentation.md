# Detection Documentation: CheckPoint - Policy Change Detection

| Item | Description |
|------|-------------|
| **Title** | CheckPoint - Policy and Configuration Change Detection |
| **Goal** | Detect firewall policy installations, rule changes, admin logins, and configuration modifications on Check Point management systems |
| **Scope** | All Check Point management events including policy installs, object/rule modifications, admin authentication, and SmartConsole activity |
| **Data source** | CommonSecurityLog (Check Point Management) |
| **Target Engine** | Microsoft Sentinel |
| **Strategy Abstract** | Monitors Check Point management plane events for configuration changes that could indicate unauthorized modifications, insider threats, or defense evasion. Captures policy installs, rule CRUD operations, admin logins, and object modifications. |
| **Technical Context** | The rule filters CommonSecurityLog for Check Point events where the Activity field contains management-related keywords (Policy Install, Log In, Object Modified, Rule Modified, etc.) or the DeviceEventClassID matches management categories. Events are enriched with AdminUser identification and ChangeType classification. |
| **MITRE ATT&CK Tactic identifier** | TA0005 (Defense Evasion) |
| **MITRE ATT&CK Technique identifier** | T1562.004 (Disable or Modify System Firewall) |
| **Feasibility** | Yes |
| **Severity** | Medium |
| **Artifacts** | TimeGenerated, ChangeType, AdminUser, Activity, SourceIP, DeviceName, DeviceEventClassID, Message |
| **Blind Spots and assumptions** | Assumes Check Point management events are forwarded to the SIEM.<br>Changes made directly on the firewall CLI bypassing SmartConsole may not be logged in the same format.<br>If admin usernames are not populated in SourceUserName/DestinationUserName fields, the AdminUser field will be empty.<br>API-driven changes may use service account names that are harder to attribute. |
| **False Positives** | Routine policy deployments by authorized administrators during change windows.<br>Automated policy pushes from management orchestration tools.<br>Scheduled configuration backup operations triggering management events.<br>Admin logins for routine monitoring and health checks. |
| **Validation** | Install a test policy on a Check Point gateway and verify the event appears as "Policy Installed" in the rule output. |
| **Version** | 1.0 |
| **Response** | Verify the admin user and source IP are authorized for the change type detected.<br>Cross-reference with change management tickets for scheduled modifications.<br>Investigate unscheduled policy installs or rule deletions immediately.<br>Escalate unauthorized configuration changes per incident response procedures. |
| **Additional Resources** | MITRE ATT&CK T1562.004 - Disable or Modify System Firewall<br>Check Point SmartConsole Audit Log documentation |
| **Comments** | High-volume environments may want to suppress routine admin logins and focus on policy/rule changes. |
| **Suppressions** | None configured by default. Consider suppressing known automation service accounts. |
| **Detection Logic** | Keyword-based filtering on Activity and DeviceEventClassID fields with change type classification |
| **Change Log** | v1.0: Initial version created (04.03.2026) |
| **Notables** | Covers policy installs, rule CRUD, admin logins, and object modifications |
| **Test protocol done + Link** | Yes - [CheckPoint-PolicyChangeDetection-TestProtocol.md](../TestProtocol/CheckPoint-PolicyChangeDetection-TestProtocol.md) |
| **KQL Query** | See [CheckPoint-PolicyChangeDetection.kql](../CheckPoint-PolicyChangeDetection.kql) |
