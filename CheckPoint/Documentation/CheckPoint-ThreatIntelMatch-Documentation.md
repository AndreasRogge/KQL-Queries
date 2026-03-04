# Detection Documentation: CheckPoint - Threat Intelligence Match

| Item | Description |
|------|-------------|
| **Title** | CheckPoint - Threat Intelligence IP Match |
| **Goal** | Detect network communications with known malicious IP addresses by correlating Check Point firewall logs with Microsoft Sentinel Threat Intelligence indicators |
| **Scope** | All Check Point firewall events where source or destination IP matches an active Threat Intelligence indicator |
| **Data source** | CommonSecurityLog (Check Point Firewall), ThreatIntelligenceIndicator (Microsoft Sentinel TI) |
| **Target Engine** | Microsoft Sentinel |
| **Strategy Abstract** | Joins Check Point firewall logs with active, non-expired TI indicators on IP addresses. Classifies matches as "Outbound to malicious" or "Inbound from malicious" and reports whether the traffic was blocked or allowed by the firewall. |
| **Technical Context** | The rule extracts active TI indicators with valid IP addresses (NetworkIP, NetworkSourceIP, NetworkDestinationIP) that have not expired. It then joins these against CommonSecurityLog on the non-private IP address (preferring DestinationIP for outbound detection). Results include threat metadata (ThreatType, ConfidenceScore) and the firewall action taken. |
| **MITRE ATT&CK Tactic identifier** | TA0011 (Command and Control) |
| **MITRE ATT&CK Technique identifier** | N/A (indicator-based matching across multiple techniques) |
| **Feasibility** | Yes |
| **Severity** | High |
| **Artifacts** | TimeGenerated, DeviceAction, Activity, SourceIP, DestinationIP, DestinationPort, Protocol, TI_IP, ThreatType, ThreatSeverity, Description, DeviceName, Direction, Action_Taken |
| **Blind Spots and assumptions** | Assumes TI indicators are up-to-date and actively maintained in Sentinel.<br>Only IP-based indicators are matched; domain, URL, and hash indicators are not evaluated.<br>If both source and destination IPs are private, no match will occur.<br>Expired or inactive indicators will be excluded, potentially missing lingering threats. |
| **False Positives** | Stale TI indicators matching IPs that have been reassigned to legitimate services.<br>Shared hosting or CDN IPs that appear in TI feeds due to other tenants' malicious activity.<br>Sinkholes or security research IPs that may appear in some TI feeds. |
| **Validation** | Add a test IP address to the ThreatIntelligenceIndicator table and generate firewall traffic to/from that IP to verify the rule produces a match. |
| **Version** | 1.0 |
| **Response** | Immediately investigate any "Allowed" matches as they indicate active communication with a known malicious IP.<br>Block matched IPs at the firewall if not already blocked.<br>Investigate the internal host for compromise indicators.<br>Escalate to incident response if outbound connections to malicious IPs were allowed. |
| **Additional Resources** | MITRE ATT&CK TA0011 - Command and Control<br>Microsoft Sentinel Threat Intelligence documentation<br>Check Point Threat Prevention blade documentation |
| **Comments** | Alternative watchlist-based matching is included as commented-out code in the KQL file. |
| **Suppressions** | None configured by default |
| **Detection Logic** | Inner join between CommonSecurityLog and ThreatIntelligenceIndicator on IP address |
| **Change Log** | v1.0: Initial version created (04.03.2026) |
| **Notables** | Matches both source and destination IPs; classifies direction and firewall action |
| **Test protocol done + Link** | Yes - [CheckPoint-ThreatIntelMatch-TestProtocol.md](../TestProtocol/CheckPoint-ThreatIntelMatch-TestProtocol.md) |
| **KQL Query** | See [CheckPoint-ThreatIntelMatch.kql](../CheckPoint-ThreatIntelMatch.kql) |
