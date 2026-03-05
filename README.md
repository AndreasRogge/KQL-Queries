# KQL-Queries

A curated collection of **KQL (Kusto Query Language)** queries for **Microsoft Sentinel**, **Microsoft Defender**, **Microsoft Intune**, **Google Cloud Platform (GCP)**, and related security services.

Built for SOC analysts, security engineers, and IT administrators to accelerate threat hunting, incident investigation, cost management, and operational monitoring across multi-cloud environments.

---

## Repository Structure

```
KQL-Queries/
  Sentinel/
    Workbooks/  Sentinel Workbook templates (importable JSON)
  Sentinel/     Microsoft Sentinel, Entra ID, Syslog, FortiNet, Ingestion
  CheckPoint/   Check Point Firewall analytic rules, tier splitting, DCR examples
  Hunting/      Cross-product threat hunting queries
  MDE/          Microsoft Defender for Endpoint
  MDI/          Microsoft Defender for Identity
  Intune/       Microsoft Intune device management
  GCP/          Google Cloud Platform audit log detections
```

---

## Categories

| Folder | Description | Queries |
|--------|-------------|:-------:|
| [Sentinel](#sentinel) | Billing, Entra ID, ingestion monitoring, incident management, syslog, FortiNet | 23 |
| [CheckPoint](#check-point-firewall) | Check Point Firewall analytic rules, data tier splitting, DCR transformations | 12 |
| [Hunting](#hunting) | Threat hunting across MDE, Sentinel, and cloud services | 5 |
| [MDE](#microsoft-defender-for-endpoint) | Defender for Endpoint detections | 1 |
| [MDI](#microsoft-defender-for-identity) | Failed logon and account lockout anomaly detection | 3 |
| [Intune](#intune) | Enrollment, compliance, policy changes, audit operations | 10 |
| [GCP](#google-cloud-platform) | GCP audit log threat detections and anomaly analysis | 17 |
| **Total** | | **71** |

---

## Queries

### Sentinel

| File | Description |
|------|-------------|
| [Billing-BillableDataCap.kql](Sentinel/Billing-BillableDataCap.kql) | Visualize daily billable data ingestion by data type over the last 31 days |
| [Billing-EPSPerTable.kql](Sentinel/Billing-EPSPerTable.kql) | Calculate events per second (EPS) for CommonSecurityLog with timechart |
| [Billing-GetBillableSize.kql](Sentinel/Billing-GetBillableSize.kql) | Comprehensive cost analysis comparing Analytic tier and Sentinel Data Lake |
| [Billing-IngestionByTableDetail.kql](Sentinel/Billing-IngestionByTableDetail.kql) | Per-table ingestion detail with event count, EPS, data size, and tier cost comparison |
| [Billing-IngestionTrend.kql](Sentinel/Billing-IngestionTrend.kql) | Daily ingestion volume and cost trends over 90 days per table with charts |
| [Billing-TierCostComparison.kql](Sentinel/Billing-TierCostComparison.kql) | Automated tier cost comparison across all tables with Data Lake savings potential |
| [Entra-BreakGlassUserSignInActivity.kql](Sentinel/Entra-BreakGlassUserSignInActivity.kql) | Monitor break glass account activity across SigninLogs and OfficeActivity using a watchlist |
| [Entra-DistinctUserPerMonth.kql](Sentinel/Entra-DistinctUserPerMonth.kql) | Count distinct users per month per tenant from sign-in logs |
| [Entra-FailedSignInsWithCAP.kql](Sentinel/Entra-FailedSignInsWithCAP.kql) | Analyze failed sign-ins with conditional access policy details and failure reasons |
| [Example-JSONParsing.kql](Sentinel/Example-JSONParsing.kql) | Examples of JSON entity parsing from SecurityAlert data using `mv-apply` and `mv-expand` |
| [FortiNet-EventsPerDevice.kql](Sentinel/FortiNet-EventsPerDevice.kql) | Analyze FortiNet events per device with traffic classification and cost estimation |
| [Ingestion-AnomalyByTimeseries.kql](Sentinel/Ingestion-AnomalyByTimeseries.kql) | Detect ingestion anomalies using time-series decomposition across all data sources |
| [Ingestion-DiffTimeGeneratedVsIngestionTime.kql](Sentinel/Ingestion-DiffTimeGeneratedVsIngestionTime.kql) | Measure ingestion latency with percentile distribution statistics |
| [Ingestion-GetSize.kql](Sentinel/Ingestion-GetSize.kql) | Daily total ingestion volume in GB over the last 30 days |
| [Ingestion-NoDataLastHour.kql](Sentinel/Ingestion-NoDataLastHour.kql) | Alert when data connectors (Syslog, CEF, XDR, Entra) stop sending data |
| [Sentinel-AIRTimeChartProblems.kql](Sentinel/Sentinel-AIRTimeChartProblems.kql) | Track Automated Investigation & Response (AIR) status across incidents |
| [Sentinel-EntityOverview.kql](Sentinel/Sentinel-EntityOverview.kql) | Summarize security alert entities (IP, URL, mail, file) with public IP filtering |
| [Sentinel-IncidentOverview.kql](Sentinel/Sentinel-IncidentOverview.kql) | Aggregate incidents by title with classification, severity, and product breakdowns |
| [Sentinel-IncidentWithoutClosingComment.kql](Sentinel/Sentinel-IncidentWithoutClosingComment.kql) | Find classified incidents that are missing a closing comment |
| [Syslog-EventsByHosts.kql](Sentinel/Syslog-EventsByHosts.kql) | Syslog event volume by collector host with AMA detection |
| [Syslog-ServerBelowThreshold.kql](Sentinel/Syslog-ServerBelowThreshold.kql) | Alert when syslog servers drop below a percentage of their average event volume |
| [Teams-ExternalChatWithPersonalTenant.kql](Sentinel/Teams-ExternalChatWithPersonalTenant.kql) | Detect one-on-one Teams chats with personal (consumer) tenants |
| [WindowsEvents-ParseEventID4738.kql](Sentinel/WindowsEvents-ParseEventID4738.kql) | Parse Event ID 4738 (user account changes) with full UserAccountControl flag decoding |

#### Workbooks

| File | Description |
|------|-------------|
| [DataTierCostAnalysis.json](Sentinel/Workbooks/DataTierCostAnalysis.json) | Importable Sentinel Workbook for three-tier cost optimization (see details below) |
| [SentinelCostOptimization-CustomerReport.md](Sentinel/Workbooks/SentinelCostOptimization-CustomerReport.md) | Example customer-facing report template with cost breakdown and implementation steps |

##### Sentinel Data Tier Cost Analysis Workbook

An interactive Azure Workbook that models Microsoft Sentinel costs across three data tiers — **Analytic**, **Data Lake only**, and **Defender XDR only** — to identify optimal table placement and quantify savings.

**Key features:**
- **Configurable pricing parameters** — Analytic ingestion, Data Lake ingestion, Data Lake storage (per compressed GB/month), currency
- **Analytic Tier Total Retention** — models the cost of extending Analytic tables beyond 90 days into Data Lake long-term retention (storage cost only, no extra ingestion charge)
- **Data Lake Only Retention** — configurable retention period for Data Lake only tables (1 month to 10 years)
- **Multi-select table assignment** — assign tables to Analytic or Data Lake tier; unselected tables default to Defender XDR only (free)
- **Summary tiles** — total daily ingestion, current vs optimized monthly cost, savings percentage
- **Cost breakdown bar chart** — side-by-side comparison: current (all Analytic) vs Analytic ingestion, Analytic long-term storage, Data Lake ingestion, Data Lake storage, XDR
- **Data volume pie chart** — visual split of GB/day across tiers
- **Data Lake detail grid** — per-table ingestion, compressed storage, and total cost for all Data Lake tables
- **Per-table cost grid** — every billable table with assigned tier, current cost, optimized cost, and savings percentage
- **Top 15 savings bar chart** — tables with the largest monthly savings potential
- **Ingestion trends** — total daily billable ingestion (area chart) and daily ingestion by tier (stacked bar)
- **Daily cost trend** — current vs optimized cost lines with daily savings overlay

**How to import:** Navigate to Microsoft Sentinel > Workbooks > Add workbook > Advanced Editor, paste the JSON, and click Apply.

**Billing model implemented:**

| Configuration | Ingestion | Interactive Retention | Long-Term Retention |
|---------------|-----------|----------------------|---------------------|
| Analytic | Full price/GB | 90 days included | Data Lake storage rate only (no extra ingestion) |
| Data Lake only | Low price/GB | N/A | Data Lake storage rate |
| Defender XDR only | Free | 30 days in Defender | N/A |

Storage uses a **6:1 compression ratio** as documented by Microsoft (600 GB raw = 100 GB billed).

### Check Point Firewall

| File | Description |
|------|-------------|
| [CheckPoint-BlockedTrafficSpike.kql](CheckPoint/CheckPoint-BlockedTrafficSpike.kql) | Detect abnormal spike in blocked/dropped connections using 14-day baseline |
| [CheckPoint-BruteForceDetection.kql](CheckPoint/CheckPoint-BruteForceDetection.kql) | Detect brute force attempts against services on authentication ports |
| [CheckPoint-CriticalSeverityEvents.kql](CheckPoint/CheckPoint-CriticalSeverityEvents.kql) | Alert on high and critical severity firewall events with direction enrichment |
| [CheckPoint-DataExfiltration.kql](CheckPoint/CheckPoint-DataExfiltration.kql) | Detect potential data exfiltration via anomalous outbound data volumes |
| [CheckPoint-DCRTransformationExample.kql](CheckPoint/CheckPoint-DCRTransformationExample.kql) | DCR transformation templates to split data between Analytic tier and Sentinel Data Lake |
| [CheckPoint-InternalAllowedTraffic.kql](CheckPoint/CheckPoint-InternalAllowedTraffic.kql) | Internal allowed traffic analysis for data lake tier (high volume, low security value) |
| [CheckPoint-PolicyChangeDetection.kql](CheckPoint/CheckPoint-PolicyChangeDetection.kql) | Detect firewall policy installs, rule changes, and admin login events |
| [CheckPoint-PortScanDetection.kql](CheckPoint/CheckPoint-PortScanDetection.kql) | Detect vertical and horizontal port scanning activity |
| [CheckPoint-SuspiciousOutboundTraffic.kql](CheckPoint/CheckPoint-SuspiciousOutboundTraffic.kql) | Detect outbound connections to never-before-seen external destinations |
| [CheckPoint-ThreatIntelMatch.kql](CheckPoint/CheckPoint-ThreatIntelMatch.kql) | Correlate firewall traffic with Threat Intelligence indicators |
| [CheckPoint-TierSplitAnalysis.kql](CheckPoint/CheckPoint-TierSplitAnalysis.kql) | Analyze data volumes per traffic category with cost comparison across tiers |
| [CheckPoint-TrafficOverview.kql](CheckPoint/CheckPoint-TrafficOverview.kql) | General traffic overview with top talkers, protocol breakdown, and volume trends |
| [CheckPoint-VPNAnomalousLogin.kql](CheckPoint/CheckPoint-VPNAnomalousLogin.kql) | Detect VPN logins from previously unseen source IPs |

### Hunting

| File | Description |
|------|-------------|
| [Hunting-ActiveRDPConnections.kql](Hunting/Hunting-ActiveRDPConnections.kql) | Detect public-facing RDP logons with failed and successful attempt counts per device |
| [Hunting-ClearTextPasswordForUser.kql](Hunting/Hunting-ClearTextPasswordForUser.kql) | Detect processes using cleartext passwords in command-line arguments |
| [Hunting-ICloudPrivateRelay.kql](Hunting/Hunting-ICloudPrivateRelay.kql) | Identify anonymous IP alerts originating from Apple iCloud Private Relay ranges |
| [Hunting-MaliciousMicrosoftRepoFile.kql](Hunting/Hunting-MaliciousMicrosoftRepoFile.kql) | Hunt for downloads of known malicious files hosted on Microsoft GitHub repositories |
| [Hunting-MultiTenantHighPrivilegeApp.kql](Hunting/Hunting-MultiTenantHighPrivilegeApp.kql) | Detect multi-tenant apps registered with sensitive permissions from external tenants |

### Microsoft Defender for Endpoint

| File | Description |
|------|-------------|
| [MDE-SmartScreenResults.kql](MDE/MDE-SmartScreenResults.kql) | Correlate SmartScreen URL warnings with browser network events |

### Microsoft Defender for Identity

| File | Description |
|------|-------------|
| [MDI-FailedLogon.kql](MDI/MDI-FailedLogon.kql) | Detect failed logon spikes by comparing the last hour against a 30-day hourly baseline |
| [MDI-FailedLogonAccountUsage.kql](MDI/MDI-FailedLogonAccountUsage.kql) | Detect unusual number of distinct accounts with failed logons per device |
| [MDI-FailedLogonAndAccountLockout.kql](MDI/MDI-FailedLogonAndAccountLockout.kql) | Combined failed logon and account lockout anomaly detection with adaptive thresholds |

### Intune

| File | Description |
|------|-------------|
| [Intune-AutopilotEnrollmentLast30Days.kql](Intune/Intune-AutopilotEnrollmentLast30Days.kql) | Autopilot enrollment results as a pie chart over the last 30 days |
| [Intune-ComplianceStateLast30Days.kql](Intune/Intune-ComplianceStateLast30Days.kql) | Device compliance state trends over the last 30 days |
| [Intune-ComplianceStateLast30DaysFilterOS.kql](Intune/Intune-ComplianceStateLast30DaysFilterOS.kql) | Device compliance state trends filtered by operating system |
| [Intune-FailEnrollmentsLast30Days.kql](Intune/Intune-FailEnrollmentsLast30Days.kql) | List all failed device enrollments in the last 30 days |
| [Intune-OperationsLast7Days.kql](Intune/Intune-OperationsLast7Days.kql) | Audit log operations breakdown by type over the last 7 days |
| [Intune-OperationsNameLast7Days.kql](Intune/Intune-OperationsNameLast7Days.kql) | Audit log operations breakdown by name over the last 7 days |
| [Intune-SpecificPolicyChange.kql](Intune/Intune-SpecificPolicyChange.kql) | Track changes to a specific Intune policy by name |
| [Intune-SuccessfulEnrollmentsLast30Days.kql](Intune/Intune-SuccessfulEnrollmentsLast30Days.kql) | Successful enrollments with device details (OS, manufacturer, compliance) |
| [Intune-WhatSettingsChangedPolicy.kql](Intune/Intune-WhatSettingsChangedPolicy.kql) | Show what settings were modified in Intune policies over the last 30 days |
| [Intune-WhoChangedPolicy.kql](Intune/Intune-WhoChangedPolicy.kql) | Summarize which users made Intune policy changes |

### Google Cloud Platform

| File | Description |
|------|-------------|
| [GCP-ConnectionFromTor.kql](GCP/GCP-ConnectionFromTor.kql) | Detect GCP access from Tor exit nodes using the Tor bulk exit list |
| [GCP-ConnectionFromUnallowedCountry.kql](GCP/GCP-ConnectionFromUnallowedCountry.kql) | Detect GCP access from blocked countries using a Sentinel watchlist |
| [GCP-DisableDataAccessLogging.kql](GCP/GCP-DisableDataAccessLogging.kql) | Detect IAM policy changes that disable audit data access logging |
| [GCP-EmptyUserAgent.kql](GCP/GCP-EmptyUserAgent.kql) | Detect IAM policy changes made with an empty user agent string |
| [GCP-ImpossibleTravel.kql](GCP/GCP-ImpossibleTravel.kql) | Impossible travel detection for GCP users based on geo-distance between logins |
| [GCP-MapThreatIntelIP.kql](GCP/GCP-MapThreatIntelIP.kql) | Map threat intelligence IP indicators to GCP audit log events |
| [GCP-MapThreatIntelIPWithoutForbidden.kql](GCP/GCP-MapThreatIntelIPWithoutForbidden.kql) | Map threat intelligence IPs to GCP events, excluding forbidden responses |
| [GCP-MassResourceDeletionTimeSeries.kql](GCP/GCP-MassResourceDeletionTimeSeries.kql) | Time-series anomaly detection for mass resource deletion in GCP |
| [GCP-NewServiceAccount.kql](GCP/GCP-NewServiceAccount.kql) | Detect creation of new GCP service accounts |
| [GCP-NewServiceAccountKey.kql](GCP/GCP-NewServiceAccountKey.kql) | Detect creation of new GCP service account keys |
| [GCP-PrivilegedRolesAdded.kql](GCP/GCP-PrivilegedRolesAdded.kql) | Detect assignment of privileged IAM roles (security admin, secret manager, etc.) |
| [GCP-PubliclyExposedStorageBucket.kql](GCP/GCP-PubliclyExposedStorageBucket.kql) | Detect storage buckets made publicly accessible (allUsers/allAuthenticatedUsers) |
| [GCP-ServiceAccountDeleted.kql](GCP/GCP-ServiceAccountDeleted.kql) | Detect deletion of GCP service accounts |
| [GCP-ServiceAccountEnumeration.kql](GCP/GCP-ServiceAccountEnumeration.kql) | Detect suspicious enumeration of GCP service accounts |
| [GCP-ServiceAccountKeyDeleted.kql](GCP/GCP-ServiceAccountKeyDeleted.kql) | Detect deletion of GCP service account keys |
| [GCP-SQLInstanceDelete.kql](GCP/GCP-SQLInstanceDelete.kql) | Detect deletion of Cloud SQL instances by non-service accounts |
| [GCP-SuspiciousResourceDeployments.kql](GCP/GCP-SuspiciousResourceDeployments.kql) | Time-series anomaly detection for suspicious resource deployment spikes |

---

## Naming Convention

All files follow the pattern: **`Category-PascalCaseDescription.kql`**

| Prefix | Source / Area |
|--------|--------------|
| `Billing-` | Cost and usage analytics |
| `Entra-` | Microsoft Entra ID (Azure AD) |
| `Example-` | Learning and reference examples |
| `CheckPoint-` | Check Point Firewall |
| `FortiNet-` | FortiGate / FortiNet firewalls |
| `GCP-` | Google Cloud Platform |
| `Hunting-` | Cross-product threat hunting |
| `Ingestion-` | Data ingestion monitoring |
| `Intune-` | Microsoft Intune |
| `MDE-` | Microsoft Defender for Endpoint |
| `MDI-` | Microsoft Defender for Identity |
| `Sentinel-` | Microsoft Sentinel |
| `Syslog-` | Syslog / CEF data |
| `Teams-` | Microsoft Teams |
| `WindowsEvents-` | Windows Security Events |

---

## Usage

1. Open [Microsoft Sentinel](https://portal.azure.com/#blade/Microsoft_Azure_Security_Insights/MainMenuBlade), [Advanced Hunting](https://security.microsoft.com/v2/advanced-hunting), or the Log Analytics query editor
2. Copy the contents of any `.kql` file
3. Paste into the query editor
4. Adjust placeholders (marked with `[PLACEHOLDER]`) to match your environment
5. Run the query

> **Note:** Some queries contain multiple variations separated by blank lines. Each variation can be run independently.

---

## Prerequisites

- **Microsoft Sentinel / Defender:** Sentinel workspace or Microsoft 365 Defender access with Security Reader (minimum) permissions
- **GCP Queries:** GCP audit logs ingested into Microsoft Sentinel via the [GCP Audit Logs connector](https://learn.microsoft.com/en-us/azure/sentinel/connect-google-cloud-platform)
- **Intune Queries:** Intune diagnostic logs forwarded to a Log Analytics workspace
- **Check Point Queries:** Check Point logs ingested via [CEF via AMA connector](https://learn.microsoft.com/en-us/azure/sentinel/connect-cef-syslog-ama) into CommonSecurityLog
- Relevant data connectors enabled for the queries you want to use

---

## Contributing

Contributions are welcome! When adding new queries:

1. Follow the naming convention `Category-PascalCaseDescription.kql`
2. Place the file in the appropriate folder
3. Ensure no private or environment-specific data is included (use `[PLACEHOLDER]` markers)
4. Add the query to this README with a description

---

## License

This project is licensed under the [MIT License](LICENSE).
