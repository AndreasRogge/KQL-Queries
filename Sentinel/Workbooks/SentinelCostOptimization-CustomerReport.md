# Microsoft Sentinel Cost Optimization Report

**Prepared by:** Water IT Security GmbH
**Date:** March 2026
**Environment:** securitymanagement-sentinel

---

## Executive Summary

Our analysis of your Microsoft Sentinel ingestion data over the last 30 days reveals a significant cost optimization opportunity. By implementing a **three-tier data strategy**, your monthly Sentinel costs can be reduced from **10,234.92 EUR to 1,672.52 EUR** — a saving of **8,562.40 EUR per month (83.7%)**.

| Metric | Value |
|--------|-------|
| Current monthly cost (all Analytic) | 10,234.92 EUR |
| Optimized monthly cost (3-tier) | 1,672.52 EUR |
| **Monthly savings** | **8,562.40 EUR** |
| **Annual savings** | **~102,749 EUR** |
| Savings percentage | 83.7% |

---

## Current Situation

Today, all billable data (63.65 GB/day) is ingested into the Microsoft Sentinel **Analytic tier** at full price (5.36 EUR/GB). This includes many Defender XDR tables (DeviceEvents, DeviceNetworkEvents, DeviceProcessEvents, etc.) that do not require real-time Sentinel analytics rules but are being charged at the full Analytic ingestion rate.

### Current Ingestion Profile

| Category | Daily Volume |
|----------|-------------|
| Total daily ingestion | 63.65 GB |
| Current monthly cost | 10,234.92 EUR |

---

## Proposed Optimization: Three-Tier Data Strategy

Microsoft Sentinel provides three distinct data tier options, each suited for different use cases and cost profiles. The key insight is that **Analytic tier tables can also extend their retention into the Data Lake** beyond 90 days at minimal cost, while **Data Lake only tables** use a much cheaper ingestion price for data that does not need real-time analytics.

### How Microsoft Sentinel Billing Works

| Configuration | Ingestion Cost | Interactive Retention | Long-Term Retention |
|---------------|---------------|----------------------|---------------------|
| **Analytic tier** | Full price per GB | 90 days included free | Optional: Data Lake storage rate (no extra ingestion charge) |
| **Data Lake only** | Low price per GB | N/A | Data Lake storage rate |
| **Defender XDR only** | Free | 30 days in Defender portal | N/A |

**Important:** When a table is on the Analytic plan with total retention exceeding 90 days, the data beyond 90 days moves to the Data Lake automatically. There is **no separate Data Lake ingestion charge** — you only pay the compressed storage rate for the additional months.

### Tier 1: Analytic (8.23 GB/day)

**Use case:** Tables that require real-time detection rules, scheduled analytics, workbooks, and interactive hunting in Sentinel.

**Cost:** 5.36 EUR per GB ingested. 90 days interactive retention included. Optional long-term retention beyond 90 days at Data Lake storage rate only (0.02 EUR per compressed GB/month, 6:1 compression).

**Tables in this tier (19 selected):**
- SigninLogs, AADNonInteractiveSigninLogs, AuditLogs
- AlertEvidence, AlertInfo
- SecurityEvent
- EmailEvents, EmailAttachmentInfo, EmailPostDeliveryEvents, EmailUrlInfo
- IdentityLogonEvents, IdentityQueryEvents
- AzureDiagnostics, AzureMetrics, InsightsMetrics
- ThreatIntelIndicators, UsePeerAnalytics, Watchlist
- LAQueryLogs, OnePasswordEventLogs_CL

**Rationale:** These tables feed active Sentinel analytics rules, correlation queries, or workbooks. They require the full Analytic tier for real-time detection and response. If long-term retention is needed (e.g., 6 months or 1 year), data beyond 90 days is automatically stored in the Data Lake at the compressed storage rate — no additional ingestion charge applies.

### Tier 2: Data Lake Only (55.42 GB/day)

**Use case:** Long-term retention for compliance, forensic investigations, and historical threat hunting. Data is queryable via KQL but at a per-query scan cost.

**Cost:** 0.19 EUR per GB ingested + 0.02 EUR per compressed GB per month stored (6:1 compression ratio).

**Tables in this tier (56 selected):**
- DeviceNetworkEvents (10.323 GB/day)
- DeviceEvents (9.438 GB/day)
- DeviceFileEvents (7.187 GB/day)
- DeviceProcessEvents (6.593 GB/day)
- CloudAppEvents (6.311 GB/day)
- DeviceRegistryEvents (5.661 GB/day)
- AADNoninteractiveUserSignInLogs (4.337 GB/day)
- DeviceImageLoadEvents (3.645 GB/day)
- MicrosoftGraphActivityLogs (3.607 GB/day)
- SecurityEvent (1.961 GB/day)
- BehaviorAnalytics (0.796 GB/day)
- And 45 additional tables

**Rationale:** These tables generate the highest volume but do not drive real-time Sentinel detection rules. Ingesting them as Data Lake only reduces costs by 96.1% per table while maintaining long-term access for investigations. There is **no Analytic tier access** for these tables — they cannot be used in Sentinel analytics rules or real-time workbooks.

### Tier 3: Defender XDR Only (0.0 GB/day — no Sentinel ingestion)

**Use case:** Tables already available for 30 days in the Microsoft Defender XDR Advanced Hunting portal at no cost to Sentinel.

**Cost:** Free (no Sentinel ingestion charge). Data is retained 30 days in the Defender portal.

**Rationale:** When tables are accessible directly through the Defender portal for threat hunting and investigation, there is no need to duplicate them into Sentinel unless long-term retention or Sentinel analytics rules are required.

---

## Cost Breakdown: Optimized Model

### Monthly Ingestion Costs

| Cost Component | Monthly Cost (EUR) |
|----------------|-------------------|
| Analytic Tier ingestion (8.23 GB/day x 30 x 5.36) | 1,322.97 |
| Analytic Tier long-term storage (beyond 90 days) | Depends on retention setting* |
| Data Lake only ingestion (55.42 GB/day x 30 x 0.19) | 315.90 |
| Data Lake only storage (6 months retention, 6:1 compression) | 33.25 |
| Defender XDR Only | 0.00 |
| **Total optimized** | **~1,672 EUR** |

*With Analytic total retention set to 90 days (default), there is no additional storage cost. If extended to 6 months, the additional 3 months of compressed storage for Analytic tables adds approximately 2.47 EUR/month.*

### Data Lake Storage Calculation

Data Lake storage benefits from a **6:1 compression ratio** as documented by Microsoft. This means that 600 GB of raw data is billed as only 100 GB of storage.

**For Data Lake only tables (6 months retention):**
- Monthly raw volume: ~1,662.6 GB
- Total retained over 6 months: ~9,975.6 GB raw
- Compressed storage billed: ~1,662.6 GB (6:1 ratio)
- Monthly storage cost: ~33.25 EUR

**For Analytic tables with extended retention (e.g., 6 months total):**
- 90 days interactive retention: included free
- Additional 3 months in Data Lake: compressed storage rate only
- No additional ingestion charge (already paid at Analytic rate)
- Monthly extra storage cost: ~2.47 EUR

### Top Tables by Savings Potential

The following tables provide the largest savings when moved from Analytic to Data Lake only:

| Table | Current Cost/mo | Optimized Cost/mo | Savings/mo |
|-------|----------------|-------------------|------------|
| DeviceNetworkEvents | 1,659.94 | 65.03 | 1,594.91 |
| DeviceEvents | 1,517.63 | 59.46 | 1,458.17 |
| DeviceFileEvents | 1,155.67 | 45.28 | 1,110.39 |
| DeviceProcessEvents | 1,060.15 | 41.54 | 1,018.61 |
| CloudAppEvents | 1,014.81 | 39.76 | 975.05 |
| DeviceRegistryEvents | 910.29 | 35.66 | 874.63 |
| DeviceImageLoadEvents | 586.12 | 22.96 | 563.16 |
| MicrosoftGraphActivityLogs | 580.01 | 22.72 | 557.29 |

---

## Implementation Steps

### Step 1: Validate Analytic Tier Table Selection

Review all active Sentinel analytics rules and confirm which tables are referenced. Only tables actively used in detection rules, workbooks, or automated playbooks need to remain in the Analytic tier.

### Step 2: Configure Data Lake Only Ingestion

For tables designated as Data Lake only:
1. Navigate to **Microsoft Sentinel > Data Management > Tables**
2. Change the table plan from "Analytics" to "Lake" tier
3. Configure the desired retention period (recommended: 6 months based on compliance requirements)

### Step 3: Configure Analytic Tier Long-Term Retention (Optional)

For Analytic tables that need retention beyond 90 days:
1. Navigate to **Microsoft Sentinel > Data Management > Tables**
2. Keep the table on the "Analytics" plan
3. Set the **Total retention** to the desired period (e.g., 6 months, 1 year)
4. Data beyond 90 days automatically moves to the Data Lake at the compressed storage rate
5. **No additional ingestion charge** applies — only the low storage rate

### Step 4: Review Defender XDR Tables

Confirm which tables are natively available in the Defender XDR Advanced Hunting portal and do not require any Sentinel ingestion. These tables provide 30 days of free retention in Defender.

### Step 5: Monitor and Adjust

Use the provided **Sentinel Data Tier Cost Analysis** workbook to continuously monitor:
- Ingestion volumes per tier
- Cost trends over time
- Impact of Analytic long-term retention settings
- Identify tables that may need to be promoted or demoted between tiers

---

## Risk Assessment

| Concern | Mitigation |
|---------|------------|
| Data Lake only tables cannot be used in Sentinel analytics rules | Only high-volume tables not used in real-time detections are moved; all active detection tables remain on Analytic tier |
| Data Lake only tables have per-query scan cost | Queries against Data Lake are charged per GB scanned; use summary rules to aggregate high-volume data into the Analytics tier if needed |
| Defender XDR 30-day retention may be insufficient | Tables requiring longer retention are placed in Data Lake tier with configurable retention (up to 12 years) |
| New analytics rules may need Data Lake tables | The workbook enables easy re-evaluation; tables can be promoted back to Analytic tier at any time |
| Compliance requires long-term retention of Analytic data | Analytic tables support total retention beyond 90 days via Data Lake storage at minimal cost (no extra ingestion charge) |

---

## Summary

By implementing the three-tier data strategy, you achieve:

- **83.7% monthly cost reduction** (8,562.40 EUR/month saved)
- **~102,749 EUR annual savings**
- Full retention of all data for compliance and forensics
- Analytic tables can retain data beyond 90 days in the Data Lake at minimal storage cost (no extra ingestion charge)
- No impact to active Sentinel detection capabilities
- Continued 30-day hunting capability in Defender XDR for applicable tables
- Ongoing cost monitoring via the included Sentinel workbook

The optimization is fully reversible — tables can be moved between tiers at any time as requirements change.

---

*Report generated based on 30-day ingestion analysis from the securitymanagement-sentinel workspace. Pricing based on West Europe region rates as of March 2026. Actual costs may vary based on commitment tier discounts and regional pricing. Refer to [Microsoft Sentinel pricing](https://azure.microsoft.com/pricing/details/microsoft-sentinel/) and [Manage data tiers and retention](https://learn.microsoft.com/azure/sentinel/manage-data-overview) for the latest billing details.*
