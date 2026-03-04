# Test Protocol for KQL Detection Rules

## 1. General Information

* **Rule Name:** CheckPoint - VPN Anomalous Login Detection
* **Created by:** [Name of the creator]
* **Date:** [Date of test execution]
* **Version:** 1.0

## 2. Test Environment

* **Test Environment:** Microsoft Sentinel workspace with Check Point VPN event data ingestion via CommonSecurityLog
* **Data Source:** CommonSecurityLog (Check Point VPN - Activity containing "VPN", "Remote Access", "SSL Network Extender")
* **Simulated Attack Scenarios:**
    * Connect to Check Point VPN from an IP address not used by the test user in the past 30 days
    * Simulate impossible travel by connecting from two geographically distant IP addresses in rapid succession

## 3. Test Cases & Results

| Test Case | Description | Expected Result | Actual Result | Successful? (Yes/No) | Notes |
|-----------|-------------|-----------------|---------------|----------------------|-------|
| TC-01 | Connect to VPN from a new source IP not in user's 30-day history | Rule detects the login and flags IsNewSourceIP = true | [Detection result] | [Yes/No] | Verify baseline IP set comparison works |
| TC-02 | Connect to VPN from a known/previously used source IP | Rule does not trigger; known IP is correctly in the baseline set | [Detection result] | [Yes/No] | Confirm baseline matching excludes known IPs |
| TC-03 | New VPN user with no 30-day history connects for the first time | Rule triggers (expected); verify user is flagged but investigate as potential new employee | [Detection result] | [Yes/No] | Document expected behavior for new users |
| TC-04 | Run baseline query with users having 100+ distinct source IPs in 30 days | Query handles large IP sets correctly; make_set limit of 100 is applied | [System impact result] | [Yes/No] | Monitor for truncated baseline sets |
| TC-05 | Test with VPN events using DeviceEventClassID-based matching (vpn, ssl_vpn, remote_access) | Rule correctly identifies VPN events via DeviceEventClassID in addition to Activity keywords | [Result] | [Yes/No] | Validate both VPN event identification methods |

> TC = Test Case

## 4. Findings & Adjustments

* **False Positives Identified?** [Yes/No] → If yes, what causes were identified and what adjustments were made?
* **Detected threats categorized correctly?** [Yes/No]
* **Improvements needed for the rule?** [Yes/No]
* **Recommended Adjustments:**
    * [Add suppression for mobile/roaming users with frequently changing IPs]
    * [Consider implementing geo-IP enrichment to add location context]
    * [Add impossible travel detection as an additional check]

## 5. Approval & Next Steps

* **Test phase completed?** [Yes/No]
* **Rule approved for implementation in the production environment?** [Yes/No]
* **Person responsible for approval:** [Name]
* **Date of implementation:** [Date]
* **Planned Maintenance & Monitoring:** Review VPN anomaly alerts daily during initial deployment; adjust mobile user suppressions as needed
