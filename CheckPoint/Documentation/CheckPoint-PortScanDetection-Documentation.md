# Detection Documentation: CheckPoint - Port Scan Detection

| Item | Description |
|------|-------------|
| **Title** | CheckPoint - Port Scan Detection |
| **Goal** | Detect vertical and horizontal port scanning patterns through Check Point firewalls |
| **Scope** | All hosts attempting connections to multiple distinct destination ports (vertical scan) or multiple distinct hosts on a single port (horizontal scan) through Check Point firewalls |
| **Data source** | CommonSecurityLog (Check Point Firewall) |
| **Target Engine** | Microsoft Sentinel |
| **Strategy Abstract** | Identifies two scanning patterns: vertical scans (one source IP probing many ports on one target) and horizontal scans (one source IP probing one port across many targets). Uses distinct count thresholds to distinguish scanning from normal traffic patterns. |
| **Technical Context** | Vertical scan detection aggregates connections by SourceIP and DestinationIP, alerting when the distinct port count exceeds 25. Horizontal scan detection aggregates by SourceIP and DestinationPort, alerting when the distinct destination host count exceeds 50. Both patterns are evaluated over a 15-minute window and combined via union for unified output. |
| **MITRE ATT&CK Tactic identifier** | TA0043 (Reconnaissance) |
| **MITRE ATT&CK Technique identifier** | T1046 (Network Service Discovery) |
| **Feasibility** | Yes |
| **Severity** | Medium |
| **Artifacts** | ScanType, SourceIP, DestinationIP, DestinationPort, DistinctPorts, EventCount, Actions, DeviceName |
| **Blind Spots and assumptions** | Assumes scanning generates firewall log entries (blocked or allowed).<br>Slow scanners staying below 25 distinct ports per 15 minutes will evade vertical scan detection.<br>Scans distributed across multiple source IPs will not aggregate to the threshold.<br>Legitimate services connecting to many ports (e.g., load balancers, monitoring tools) may trigger false positives. |
| **False Positives** | Network monitoring tools (Nagios, PRTG, Zabbix) checking service availability across many ports/hosts.<br>Vulnerability scanners (Nessus, Qualys) during authorized scans.<br>Load balancers or reverse proxies connecting to multiple backend services.<br>DNS or DHCP servers communicating with many endpoints. |
| **Validation** | Run a port scan from a test host targeting 25+ ports on a single destination (vertical) or targeting 50+ hosts on a single port (horizontal) and verify the rule detects it. |
| **Version** | 1.0 |
| **Response** | Identify the source IP and determine if it is an internal or external scanner.<br>Cross-reference with authorized vulnerability scanning schedules.<br>For external sources, check threat intelligence and consider blocking.<br>For internal sources, investigate for potential lateral movement or compromised hosts. |
| **Additional Resources** | MITRE ATT&CK T1046 - Network Service Discovery<br>Check Point IPS blade port scan detection documentation |
| **Comments** | DistinctPortThreshold (default: 25) and DistinctHostPortThreshold (default: 50) are tunable. |
| **Suppressions** | None configured by default. Consider suppressing known vulnerability scanner IPs. |
| **Detection Logic** | Distinct count threshold on destination ports (vertical) and destination hosts (horizontal) per source IP |
| **Change Log** | v1.0: Initial version created (04.03.2026) |
| **Notables** | Detects both vertical (port sweep) and horizontal (host sweep) scanning patterns |
| **Test protocol done + Link** | Yes - [CheckPoint-PortScanDetection-TestProtocol.md](../TestProtocol/CheckPoint-PortScanDetection-TestProtocol.md) |
| **KQL Query** | See [CheckPoint-PortScanDetection.kql](../CheckPoint-PortScanDetection.kql) |
