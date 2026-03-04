# Test Protocol for KQL Detection Rules

## 1. General Information

* **Rule Name:** CheckPoint - Blocked Traffic Spike Detection
* **Created by:** [Name of the creator]
* **Date:** [Date of test execution]
* **Version:** 1.0

## 2. Test Environment

* **Test Environment:** Microsoft Sentinel workspace with Check Point firewall data ingestion via CommonSecurityLog
* **Data Source:** CommonSecurityLog (Check Point Firewall - DeviceVendor == "Check Point")
* **Simulated Attack Scenarios:**
    * Simulated DDoS / volumetric attack generating a spike in blocked connections exceeding 3x standard deviation above the 14-day baseline
    * Simulated mass port scanning from multiple external IPs resulting in a high volume of Drop/Reject events within one hour

## 3. Test Cases & Results

| Test Case | Description | Expected Result | Actual Result | Successful? (Yes/No) | Notes |
|-----------|-------------|-----------------|---------------|----------------------|-------|
| TC-01 | Generate blocked traffic exceeding 3x StdDev above 14-day average within 1 hour | Rule detects the spike and creates an alert with AnomalyScore > 3 | [Detection result] | [Yes/No] | Verify AnomalyScore calculation accuracy |
| TC-02 | Normal blocked traffic volume within baseline range (no anomaly) | Rule does not trigger; no false positive alert generated | [Detection result] | [Yes/No] | Confirm no alert during normal operations |
| TC-03 | Blocked traffic slightly above average but below 3x StdDev threshold | Rule does not trigger; threshold is not exceeded | [Detection result] | [Yes/No] | Test boundary condition at threshold |
| TC-04 | Run rule on 14+ days of historical data with high event volume (>100K events/hour) | Rule executes within acceptable time (<30 seconds) without timeout | [System impact result] | [Yes/No] | Monitor query performance and resource usage |
| TC-05 | Adjust ThresholdMultiplier from 3 to 2 and test with moderate spike | Rule triggers at lower threshold; sensitivity increases appropriately | [Result] | [Yes/No] | Validate threshold tunability |

> TC = Test Case

## 4. Findings & Adjustments

* **False Positives Identified?** [Yes/No] → If yes, what causes were identified and what adjustments were made?
* **Detected threats categorized correctly?** [Yes/No]
* **Improvements needed for the rule?** [Yes/No]
* **Recommended Adjustments:**
    * [Adjust MinimumEvents threshold based on environment volume]
    * [Consider adding exclusions for known vulnerability scanner IPs]
    * [Tune ThresholdMultiplier based on false positive rate]

## 5. Approval & Next Steps

* **Test phase completed?** [Yes/No]
* **Rule approved for implementation in the production environment?** [Yes/No]
* **Person responsible for approval:** [Name]
* **Date of implementation:** [Date]
* **Planned Maintenance & Monitoring:** Review baseline accuracy monthly; re-evaluate thresholds quarterly
