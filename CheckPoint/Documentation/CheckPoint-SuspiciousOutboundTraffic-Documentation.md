# Detection Documentation: CheckPoint - Suspicious Outbound Traffic

| Item | Description |
|------|-------------|
| **Title** | CheckPoint - Suspicious Outbound Traffic to New Destinations |
| **Goal** | Detect outbound connections from internal hosts to external IP addresses that have never been seen in the last 14 days, potentially indicating C2 communication or data exfiltration |
| **Scope** | Internal hosts (RFC1918) making accepted outbound connections to new external (non-RFC1918) destinations on non-standard ports (excluding 80, 443, 53) |
| **Data source** | CommonSecurityLog (Check Point Firewall) |
| **Target Engine** | Microsoft Sentinel |
| **Strategy Abstract** | Builds a 14-day baseline of known external destination IPs and identifies connections to destinations not in this baseline. Focuses on non-standard ports to filter out common web browsing and DNS traffic, highlighting potentially suspicious C2 channels. |
| **Technical Context** | The rule first builds a distinct set of all external destination IPs seen in accepted connections over the past 14 days. It then identifies current-hour connections to destinations not in this known set, filtering out ports 80, 443, and 53. A minimum of 3 connections to a new destination is required to reduce single-connection noise. |
| **MITRE ATT&CK Tactic identifier** | TA0011 (Command and Control)<br>TA0010 (Exfiltration) |
| **MITRE ATT&CK Technique identifier** | N/A (behavioral anomaly detection across multiple potential techniques) |
| **Feasibility** | Yes |
| **Severity** | Medium |
| **Artifacts** | SourceIP, DestinationIP, DeviceName, ConnectionCount, DistinctPorts, Ports, FirstSeen, LastSeen |
| **Blind Spots and assumptions** | Assumes 14 days is sufficient to establish a baseline of normal destinations.<br>C2 traffic over ports 80, 443, or 53 will be excluded by design to reduce noise.<br>Destinations seen once in the past 14 days will be considered "known" even if they were malicious.<br>New legitimate services or partners will trigger alerts until their IPs enter the baseline. |
| **False Positives** | New SaaS or cloud services being adopted by internal hosts.<br>Legitimate software updates contacting new CDN or mirror servers.<br>Business partner or vendor IPs that change or rotate periodically.<br>Developer or IT staff testing new external integrations. |
| **Validation** | Initiate 3+ outbound connections from an internal host to a new external IP on a non-standard port (e.g., port 4444) and verify the rule detects the new destination. |
| **Version** | 1.0 |
| **Response** | Investigate the destination IP using threat intelligence and WHOIS lookup.<br>Check the ports used for known C2 frameworks or tunneling protocols.<br>Determine if the internal host is expected to communicate with new external destinations.<br>Escalate if the destination IP is unrecognized or associated with malicious activity. |
| **Additional Resources** | MITRE ATT&CK TA0011 - Command and Control<br>MITRE ATT&CK TA0010 - Exfiltration |
| **Comments** | MinConnectionsNewDest (default: 3) can be tuned. Consider adding port 443 back if C2 over HTTPS is a concern. |
| **Suppressions** | None configured by default. Consider suppressing known CDN and cloud provider IP ranges. |
| **Detection Logic** | Baseline-exclusion model comparing current connections against 14-day known destination set |
| **Change Log** | v1.0: Initial version created (04.03.2026) |
| **Notables** | Excludes ports 80, 443, 53 by default to reduce noise; tunable threshold |
| **Test protocol done + Link** | Yes - [CheckPoint-SuspiciousOutboundTraffic-TestProtocol.md](../TestProtocol/CheckPoint-SuspiciousOutboundTraffic-TestProtocol.md) |
| **KQL Query** | See [CheckPoint-SuspiciousOutboundTraffic.kql](../CheckPoint-SuspiciousOutboundTraffic.kql) |
