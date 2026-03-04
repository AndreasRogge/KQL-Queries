# Test Protocol for KQL Detection Rules

## 1. General Information

* **Rule Name:** CheckPoint - Data Exfiltration Detection
* **Created by:** [Name of the creator]
* **Date:** [Date of test execution]
* **Version:** 1.0

## 2. Test Environment

* **Test Environment:** Microsoft Sentinel workspace with Check Point firewall data ingestion via CommonSecurityLog
* **Data Source:** CommonSecurityLog (Check Point Firewall - DeviceVendor == "Check Point", SentBytes field populated)
* **Simulated Attack Scenarios:**
    * Simulate large file upload (>100 MB) from an internal host to an external destination exceeding the host's 14-day baseline by 3x standard deviation
    * Simulate gradual data exfiltration with volume just above the statistical threshold

## 3. Test Cases & Results

| Test Case | Description | Expected Result | Actual Result | Successful? (Yes/No) | Notes |
|-----------|-------------|-----------------|---------------|----------------------|-------|
| TC-01 | Transfer >100 MB to external IP, exceeding 3x StdDev above 14-day avg for source host | Rule detects the anomaly with AnomalyScore reflecting the deviation magnitude | [Detection result] | [Yes/No] | Verify SentBytes aggregation and baseline comparison |
| TC-02 | Normal outbound traffic within baseline range (below 100 MB or within 3x StdDev) | Rule does not trigger; no false positive generated | [Detection result] | [Yes/No] | Confirm minimum byte threshold and StdDev filtering |
| TC-03 | Transfer 80 MB outbound (below MinBytesThreshold) with high anomaly score | Rule does not trigger because MinBytesThreshold (100 MB) is not met | [Detection result] | [Yes/No] | Validate minimum byte floor prevents low-volume alerts |
| TC-04 | Run baseline calculation over 14 days of high-volume environment data | Query executes within acceptable time, baseline computation completes without timeout | [System impact result] | [Yes/No] | Monitor query performance with large datasets |
| TC-05 | Adjust ThresholdMultiplier from 3 to 2 and MinBytesThreshold to 50 MB | Rule triggers at lower thresholds; increased sensitivity validated | [Result] | [Yes/No] | Define optimal thresholds for environment |

> TC = Test Case

## 4. Findings & Adjustments

* **False Positives Identified?** [Yes/No] → If yes, what causes were identified and what adjustments were made?
* **Detected threats categorized correctly?** [Yes/No]
* **Improvements needed for the rule?** [Yes/No]
* **Recommended Adjustments:**
    * [Add exclusions for known backup server IPs to reduce false positives]
    * [Tune MinBytesThreshold based on typical outbound volume in the environment]
    * [Consider adding destination IP reputation check as enrichment]

## 5. Approval & Next Steps

* **Test phase completed?** [Yes/No]
* **Rule approved for implementation in the production environment?** [Yes/No]
* **Person responsible for approval:** [Name]
* **Date of implementation:** [Date]
* **Planned Maintenance & Monitoring:** Review baseline accuracy monthly; monitor for new backup/cloud services that may need exclusion
