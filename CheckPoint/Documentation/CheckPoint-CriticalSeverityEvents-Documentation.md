# Detection Documentation: CheckPoint - Critical Severity Events

| Item | Description |
|------|-------------|
| **Title** | CheckPoint - Critical Severity Events |
| **Goal** | Surface high, critical, and emergency severity firewall events from Check Point for immediate SOC attention |
| **Scope** | All Check Point firewall events with LogSeverity 8 (High), 9 (Critical), or 10 (Emergency) |
| **Data source** | CommonSecurityLog (Check Point Firewall) |
| **Target Engine** | Microsoft Sentinel |
| **Strategy Abstract** | Filters Check Point firewall logs for high and critical severity events and enriches them with traffic direction classification for efficient SOC triage. These events represent the most urgent firewall alerts requiring immediate investigation. |
| **Technical Context** | The rule filters CommonSecurityLog for Check Point events with LogSeverity values of 8, 9, or 10 (or string equivalents High, Critical, Emergency). It classifies traffic direction as Inbound, Outbound, Internal, or External based on RFC1918 private IP analysis of source and destination. Results are ordered by time for rapid triage. |
| **MITRE ATT&CK Tactic identifier** | TA0040 (Impact)<br>TA0005 (Defense Evasion) |
| **MITRE ATT&CK Technique identifier** | N/A (severity-based alerting covers multiple technique categories) |
| **Feasibility** | Yes |
| **Severity** | High |
| **Artifacts** | TimeGenerated, Severity, DeviceAction, Activity, SourceIP, DestinationIP, DestinationPort, Protocol, Direction, DeviceEventClassID, DeviceName, Message |
| **Blind Spots and assumptions** | Assumes Check Point correctly assigns severity levels to events.<br>Events with miscategorized severity may be missed.<br>Low-severity events that are operationally critical (e.g., policy violations) will not be captured.<br>Relies on Check Point log forwarding being operational and timely. |
| **False Positives** | Informational high-severity events generated during firmware upgrades or maintenance windows.<br>Recurring known-good high-severity events from specific blades (e.g., threat prevention signature updates).<br>Test or lab environments generating critical events during controlled testing. |
| **Validation** | Trigger a high-severity event on the Check Point firewall (e.g., IPS blade detection) and verify it appears in the rule output. |
| **Version** | 1.0 |
| **Response** | Immediately triage Emergency and Critical severity events.<br>Investigate the source and destination IPs, ports, and associated activity.<br>Correlate with other detection rules (Threat Intel Match, Data Exfiltration) for context.<br>Escalate confirmed security incidents per SOC runbook. |
| **Additional Resources** | MITRE ATT&CK TA0040 - Impact<br>Check Point Log Severity classification documentation |
| **Comments** | This is a high-volume alerting rule; consider suppression or grouping adjustments in production. |
| **Suppressions** | None configured by default |
| **Detection Logic** | Severity-based filtering on LogSeverity >= 8 with direction enrichment |
| **Change Log** | v1.0: Initial version created (04.03.2026) |
| **Notables** | Covers Emergency, Critical, and High severity levels from Check Point |
| **Test protocol done + Link** | Yes - [CheckPoint-CriticalSeverityEvents-TestProtocol.md](../TestProtocol/CheckPoint-CriticalSeverityEvents-TestProtocol.md) |
| **KQL Query** | See [CheckPoint-CriticalSeverityEvents.kql](../CheckPoint-CriticalSeverityEvents.kql) |
