# Detection Documentation: CheckPoint - Brute Force Detection

| Item | Description |
|------|-------------|
| **Title** | CheckPoint - Brute Force Detection |
| **Goal** | Detect brute force attempts and password spray attacks against services protected by Check Point firewalls |
| **Scope** | External IPs targeting internal hosts on common authentication ports (SSH, RDP, SMB, FTP, database ports) |
| **Data source** | CommonSecurityLog (Check Point Firewall) |
| **Target Engine** | Microsoft Sentinel |
| **Strategy Abstract** | Identifies external IPs generating a high volume of dropped/rejected connections to authentication-related ports within a 15-minute window. Classifies attack type as brute force, password spray, or distributed scan based on target distribution patterns. |
| **Technical Context** | The rule filters for blocked connections from external (non-RFC1918) source IPs targeting internal (RFC1918) destination IPs on predefined authentication ports (22, 23, 3389, 445, 21, 3306, 1433, 5432, 8080, 8443). Events are aggregated per source IP and device, then filtered by a threshold of 30+ failed attempts. The attack pattern is classified based on the distribution of distinct targets and ports. |
| **MITRE ATT&CK Tactic identifier** | TA0006 (Credential Access) |
| **MITRE ATT&CK Technique identifier** | T1110 (Brute Force) |
| **Feasibility** | Yes |
| **Severity** | Medium |
| **Artifacts** | SourceIP, DeviceName, FailedAttempts, DistinctTargets, DistinctPorts, TargetIPs, TargetPorts, AttackType, DurationMinutes |
| **Blind Spots and assumptions** | Assumes brute force attacks generate Drop/Reject/Block actions on the firewall.<br>Attacks using legitimate credentials that pass through the firewall will not be detected.<br>Low-and-slow brute force attacks staying below the 30-attempt threshold within 15 minutes will be missed.<br>Does not detect brute force on non-standard authentication ports not listed in AuthPorts. |
| **False Positives** | Misconfigured applications or services repeatedly connecting to blocked ports.<br>Legitimate external monitoring services probing service availability.<br>CDN or proxy IPs aggregating multiple users' connection attempts. |
| **Validation** | Simulate 30+ blocked connection attempts from an external IP to an internal host on SSH (port 22) within 15 minutes. |
| **Version** | 1.0 |
| **Response** | Verify the source IP reputation using threat intelligence feeds.<br>Check if the targeted ports correspond to exposed services.<br>Block the attacking IP at the firewall perimeter if confirmed malicious.<br>Investigate if any successful connections from the same source IP occurred. |
| **Additional Resources** | MITRE ATT&CK T1110 - Brute Force<br>Check Point SmartEvent IPS blade documentation |
| **Comments** | FailedConnectionThreshold (default: 30) and AuthPorts list can be customized per environment. |
| **Suppressions** | None configured by default |
| **Detection Logic** | Threshold-based detection on blocked connection count per source IP to authentication ports |
| **Change Log** | v1.0: Initial version created (04.03.2026) |
| **Notables** | Classifies attacks as Brute Force, Password Spray, or Distributed Scan |
| **Test protocol done + Link** | Yes - [CheckPoint-BruteForceDetection-TestProtocol.md](../TestProtocol/CheckPoint-BruteForceDetection-TestProtocol.md) |
| **KQL Query** | See [CheckPoint-BruteForceDetection.kql](../CheckPoint-BruteForceDetection.kql) |
