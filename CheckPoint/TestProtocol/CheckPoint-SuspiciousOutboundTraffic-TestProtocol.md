# Test Protocol for KQL Detection Rules

## 1. General Information

* **Rule Name:** CheckPoint - Suspicious Outbound Traffic to New Destinations
* **Created by:** [Name of the creator]
* **Date:** [Date of test execution]
* **Version:** 1.0

## 2. Test Environment

* **Test Environment:** Microsoft Sentinel workspace with Check Point firewall data ingestion via CommonSecurityLog
* **Data Source:** CommonSecurityLog (Check Point Firewall - DeviceVendor == "Check Point", accepted outbound connections)
* **Simulated Attack Scenarios:**
    * Initiate 3+ outbound connections from an internal host to a never-before-seen external IP on a non-standard port (e.g., port 4444)
    * Simulate C2 callback to an external IP not in the 14-day known destination baseline

## 3. Test Cases & Results

| Test Case | Description | Expected Result | Actual Result | Successful? (Yes/No) | Notes |
|-----------|-------------|-----------------|---------------|----------------------|-------|
| TC-01 | Connect 3+ times from internal host to new external IP on port 4444 (not seen in 14 days) | Rule detects the new destination and creates alert with ConnectionCount >= 3 | [Detection result] | [Yes/No] | Verify destination IP is not in KnownDestinations baseline |
| TC-02 | Normal outbound traffic to known external destinations seen in past 14 days | Rule does not trigger; known destinations are correctly excluded | [Detection result] | [Yes/No] | Confirm baseline exclusion works |
| TC-03 | Connect to new external IP on port 443 (excluded port) | Rule does not trigger because port 443 is in the exclusion list | [Detection result] | [Yes/No] | Validate port exclusion filter (80, 443, 53) |
| TC-04 | Run baseline query over 14 days of data with large distinct destination set (>50K IPs) | Rule executes within acceptable time; known destination set builds correctly | [System impact result] | [Yes/No] | Monitor query performance for large baselines |
| TC-05 | Adjust MinConnectionsNewDest from 3 to 1 and remove port exclusions | Rule triggers on single connections to any new destination; increased sensitivity | [Result] | [Yes/No] | Evaluate trade-off between sensitivity and false positive rate |

> TC = Test Case

## 4. Findings & Adjustments

* **False Positives Identified?** [Yes/No] → If yes, what causes were identified and what adjustments were made?
* **Detected threats categorized correctly?** [Yes/No]
* **Improvements needed for the rule?** [Yes/No]
* **Recommended Adjustments:**
    * [Add CDN and cloud provider IP ranges to a suppression list to reduce false positives]
    * [Consider adding port 443 back to detection if C2-over-HTTPS is a concern]
    * [Tune MinConnectionsNewDest based on environment noise level]

## 5. Approval & Next Steps

* **Test phase completed?** [Yes/No]
* **Rule approved for implementation in the production environment?** [Yes/No]
* **Person responsible for approval:** [Name]
* **Date of implementation:** [Date]
* **Planned Maintenance & Monitoring:** Review new destination alerts daily during initial deployment; tune after 2-week observation period
