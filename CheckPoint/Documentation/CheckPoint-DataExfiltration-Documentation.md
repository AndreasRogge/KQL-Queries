# Detection Documentation: CheckPoint - Data Exfiltration Detection

| Item | Description |
|------|-------------|
| **Title** | CheckPoint - Data Exfiltration Detection |
| **Goal** | Detect potential data exfiltration via unusually large outbound data transfers from internal hosts to external destinations |
| **Scope** | Internal hosts (RFC1918) sending data to external (non-RFC1918) destinations via accepted connections through Check Point firewalls |
| **Data source** | CommonSecurityLog (Check Point Firewall) |
| **Target Engine** | Microsoft Sentinel |
| **Strategy Abstract** | Statistical anomaly detection on outbound data volume per source IP. Uses a 14-day per-source baseline to identify hosts transferring abnormally large amounts of data externally. A minimum 100 MB threshold reduces noise from low-volume deviations. |
| **Technical Context** | The rule calculates per-source-IP hourly averages and standard deviations of outbound SentBytes over 14 days. Current hour outbound volume is compared against the baseline. An alert fires when the current volume exceeds both the 100 MB minimum and the baseline mean plus 3x standard deviation. Anomaly scores quantify the deviation magnitude. |
| **MITRE ATT&CK Tactic identifier** | TA0010 (Exfiltration) |
| **MITRE ATT&CK Technique identifier** | T1048 (Exfiltration Over Alternative Protocol) |
| **Feasibility** | Yes |
| **Severity** | High |
| **Artifacts** | SourceIP, CurrentSentMB, AvgHourlyMB, AnomalyScore, DistinctDestinations, TopDestinations, TopPorts, ConnectionCount |
| **Blind Spots and assumptions** | Assumes SentBytes field is accurately populated in Check Point logs.<br>Encrypted exfiltration over HTTPS on port 443 will be detected by volume but protocol content is not inspected.<br>Hosts with highly variable outbound patterns (e.g., backup servers) may have wide standard deviations, reducing sensitivity.<br>New hosts without 14 days of baseline data will not be evaluated. |
| **False Positives** | Legitimate large file uploads to cloud services (OneDrive, SharePoint, AWS S3).<br>Backup operations transferring data to off-site locations.<br>Software deployment or update distribution from internal servers.<br>Video conferencing or streaming generating high outbound volume. |
| **Validation** | Transfer a large file (>100 MB) from an internal host to an external destination, exceeding the host's 14-day average outbound volume by 3x standard deviation. |
| **Version** | 1.0 |
| **Response** | Identify the source host and investigate its purpose and typical outbound patterns.<br>Check the destination IPs against threat intelligence and reputation services.<br>Review the ports used for transfer and correlate with known exfiltration techniques.<br>Escalate if the destination is suspicious or unauthorized. |
| **Additional Resources** | MITRE ATT&CK T1048 - Exfiltration Over Alternative Protocol<br>Check Point Data Loss Prevention blade documentation |
| **Comments** | MinBytesThreshold (default: 100 MB) and ThresholdMultiplier (default: 3) are tunable per environment. |
| **Suppressions** | None configured by default. Consider suppressing known backup server IPs. |
| **Detection Logic** | Per-source baseline with average + (standard deviation x multiplier) threshold and minimum byte floor |
| **Change Log** | v1.0: Initial version created (04.03.2026) |
| **Notables** | Requires SentBytes field to be populated; 14-day baseline per source IP |
| **Test protocol done + Link** | Yes - [CheckPoint-DataExfiltration-TestProtocol.md](../TestProtocol/CheckPoint-DataExfiltration-TestProtocol.md) |
| **KQL Query** | See [CheckPoint-DataExfiltration.kql](../CheckPoint-DataExfiltration.kql) |
