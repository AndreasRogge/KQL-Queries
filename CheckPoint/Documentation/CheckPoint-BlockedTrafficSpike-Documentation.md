# Detection Documentation: CheckPoint - Blocked Traffic Spike

| Item | Description |
|------|-------------|
| **Title** | CheckPoint - Blocked Traffic Spike Detection |
| **Goal** | Detect abnormal spikes in blocked/dropped connections from Check Point firewalls that may indicate an ongoing attack or misconfiguration |
| **Scope** | All Check Point firewall devices reporting to CommonSecurityLog with Drop, Reject, or Block actions |
| **Data source** | CommonSecurityLog (Check Point Firewall) |
| **Target Engine** | Microsoft Sentinel |
| **Strategy Abstract** | Statistical anomaly detection comparing current blocked traffic volume against a 14-day historical baseline. Triggers when the current hourly count exceeds 3x the standard deviation above the historical average. |
| **Technical Context** | The rule calculates a baseline of hourly blocked event counts over 14 days, computing the average and standard deviation. The current hour's blocked event count is then compared against this baseline. An anomaly score is generated representing how many standard deviations the current count deviates from the mean. A minimum threshold of 50 events filters out low-volume noise. |
| **MITRE ATT&CK Tactic identifier** | TA0001 (Initial Access)<br>TA0043 (Reconnaissance) |
| **MITRE ATT&CK Technique identifier** | N/A (behavioral anomaly detection) |
| **Feasibility** | Yes |
| **Severity** | Medium |
| **Artifacts** | CurrentCount, AvgCount, StdDev, AnomalyScore, DistinctSources, DistinctDestinations, TopSources, TopDestPorts |
| **Blind Spots and assumptions** | Assumes a stable 14-day baseline exists for accurate statistical comparison.<br>New firewall deployments with less than 14 days of data may produce inaccurate baselines.<br>Gradual increases in blocked traffic over weeks will shift the baseline and may not trigger alerts.<br>Does not differentiate between legitimate traffic spikes (e.g., vulnerability scanning by authorized tools) and malicious activity. |
| **False Positives** | Scheduled vulnerability scans or penetration tests generating high volumes of blocked traffic.<br>Network misconfigurations causing temporary spikes in denied connections.<br>Legitimate infrastructure changes (new services, IP range changes) causing baseline deviation. |
| **Validation** | Generate a burst of blocked connections from a test source to exceed the 3x standard deviation threshold above the 14-day average. |
| **Version** | 1.0 |
| **Response** | Investigate the top source IPs and destination ports involved in the spike.<br>Determine if the spike correlates with known scanning tools or authorized penetration tests.<br>Check if the source IPs are external and potentially malicious.<br>Escalate if the spike is unexplained and involves sensitive destination ports. |
| **Additional Resources** | MITRE ATT&CK TA0001 - Initial Access<br>MITRE ATT&CK TA0043 - Reconnaissance<br>Check Point Logging and Monitoring documentation |
| **Comments** | ThresholdMultiplier (default: 3) and MinimumEvents (default: 50) can be tuned per environment. |
| **Suppressions** | None configured by default |
| **Detection Logic** | Baseline comparison using average + (standard deviation x multiplier) threshold |
| **Change Log** | v1.0: Initial version created (04.03.2026) |
| **Notables** | Requires 14 days of historical data for accurate baseline calculation |
| **Test protocol done + Link** | Yes - [CheckPoint-BlockedTrafficSpike-TestProtocol.md](../TestProtocol/CheckPoint-BlockedTrafficSpike-TestProtocol.md) |
| **KQL Query** | See [CheckPoint-BlockedTrafficSpike.kql](../CheckPoint-BlockedTrafficSpike.kql) |
