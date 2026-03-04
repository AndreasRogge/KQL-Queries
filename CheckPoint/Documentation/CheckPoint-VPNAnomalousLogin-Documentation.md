# Detection Documentation: CheckPoint - VPN Anomalous Login

| Item | Description |
|------|-------------|
| **Title** | CheckPoint - VPN Anomalous Login Detection |
| **Goal** | Detect VPN logins from new or unusual source IP addresses not seen in the user's 30-day login history, indicating potential credential compromise or unauthorized remote access |
| **Scope** | All Check Point VPN authentication events (VPN, Remote Access, SSL Network Extender, Endpoint Security) with successful actions |
| **Data source** | CommonSecurityLog (Check Point VPN) |
| **Target Engine** | Microsoft Sentinel |
| **Strategy Abstract** | Builds a 30-day per-user baseline of known VPN source IPs and identifies logins from IPs not in this baseline. Focuses on successful authentication events to detect credential compromise scenarios where an attacker logs in from a new location. |
| **Technical Context** | The rule identifies VPN-related events by filtering on Activity keywords and DeviceEventClassID patterns. It builds a historical set of up to 100 known source IPs per user over 30 days. Current-hour VPN logins are left-joined against this baseline, and events where the source IP is not in the known set are flagged as anomalous. |
| **MITRE ATT&CK Tactic identifier** | TA0001 (Initial Access) |
| **MITRE ATT&CK Technique identifier** | T1133 (External Remote Services) |
| **Feasibility** | Yes |
| **Severity** | Medium |
| **Artifacts** | TimeGenerated, VPNUser, SourceIP, DeviceAction, Activity, DeviceName, IsNewSourceIP |
| **Blind Spots and assumptions** | Assumes VPN users have stable source IPs over time; mobile users may have many legitimate new IPs.<br>Users with more than 100 unique source IPs in 30 days may have truncated baseline sets.<br>New VPN users without 30 days of history will trigger alerts on every login.<br>VPN events must contain SourceUserName or DestinationUserName for user identification. |
| **False Positives** | Users connecting from new locations (travel, home moves, new ISPs).<br>Mobile users with frequently changing IPs (cellular networks).<br>Users connecting through VPN chains or different proxy services.<br>New employees making their first VPN connection. |
| **Validation** | Connect to the Check Point VPN from an IP address not used in the past 30 days and verify the rule flags it as a new source IP. |
| **Version** | 1.0 |
| **Response** | Verify with the user whether the VPN login from the new IP was legitimate.<br>Check the source IP geolocation and reputation.<br>Look for impossible travel (login from two geographically distant locations in a short time).<br>If unauthorized, disable the VPN account and investigate credential compromise. |
| **Additional Resources** | MITRE ATT&CK T1133 - External Remote Services<br>Check Point Remote Access VPN documentation |
| **Comments** | Consider implementing a watchlist for executive/privileged VPN accounts that require stricter monitoring. |
| **Suppressions** | None configured by default. Consider suppressing mobile workforce users with known dynamic IP patterns. |
| **Detection Logic** | Left-outer join comparing current VPN source IPs against 30-day per-user known IP baseline |
| **Change Log** | v1.0: Initial version created (04.03.2026) |
| **Notables** | 30-day baseline window; up to 100 known IPs per user; identifies new source IPs only |
| **Test protocol done + Link** | Yes - [CheckPoint-VPNAnomalousLogin-TestProtocol.md](../TestProtocol/CheckPoint-VPNAnomalousLogin-TestProtocol.md) |
| **KQL Query** | See [CheckPoint-VPNAnomalousLogin.kql](../CheckPoint-VPNAnomalousLogin.kql) |
