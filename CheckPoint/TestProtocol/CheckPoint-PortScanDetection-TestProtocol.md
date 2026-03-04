# Test Protocol for KQL Detection Rules

## 1. General Information

* **Rule Name:** CheckPoint - Port Scan Detection
* **Created by:** [Name of the creator]
* **Date:** [Date of test execution]
* **Version:** 1.0

## 2. Test Environment

* **Test Environment:** Microsoft Sentinel workspace with Check Point firewall data ingestion via CommonSecurityLog
* **Data Source:** CommonSecurityLog (Check Point Firewall - DeviceVendor == "Check Point")
* **Simulated Attack Scenarios:**
    * Simulate a vertical port scan (nmap -p 1-1000) from a test host targeting a single destination through the Check Point firewall
    * Simulate a horizontal port scan (nmap -p 22 <target-subnet>) scanning one port across 50+ destination hosts

## 3. Test Cases & Results

| Test Case | Description | Expected Result | Actual Result | Successful? (Yes/No) | Notes |
|-----------|-------------|-----------------|---------------|----------------------|-------|
| TC-01 | Scan 25+ distinct ports on a single destination host within 15 minutes | Rule detects and classifies as "Vertical" scan with correct SourceIP and DestinationIP | [Detection result] | [Yes/No] | Verify DistinctPorts count and ScanType classification |
| TC-02 | Normal traffic from a host connecting to fewer than 25 distinct ports | Rule does not trigger; no false positive generated | [Detection result] | [Yes/No] | Confirm vertical threshold filtering works |
| TC-03 | Scan one port (e.g., 22) across 50+ distinct destination hosts within 15 minutes | Rule detects and classifies as "Horizontal" scan with correct SourceIP and port | [Detection result] | [Yes/No] | Validate horizontal scan detection |
| TC-04 | Run both vertical and horizontal scan detection simultaneously with high event volume | Both scan types detected in union output; query executes within 15-min frequency | [System impact result] | [Yes/No] | Monitor performance of dual-pattern detection |
| TC-05 | Adjust DistinctPortThreshold to 15 and DistinctHostPortThreshold to 30 | Rule triggers at lower thresholds; validates tunability for sensitive environments | [Result] | [Yes/No] | Define optimal thresholds per environment |

> TC = Test Case

## 4. Findings & Adjustments

* **False Positives Identified?** [Yes/No] → If yes, what causes were identified and what adjustments were made?
* **Detected threats categorized correctly?** [Yes/No]
* **Improvements needed for the rule?** [Yes/No]
* **Recommended Adjustments:**
    * [Add exclusions for authorized vulnerability scanner IPs (Nessus, Qualys, etc.)]
    * [Exclude known monitoring tool IPs that check multiple service ports]
    * [Tune thresholds based on environment-specific scanning noise levels]

## 5. Approval & Next Steps

* **Test phase completed?** [Yes/No]
* **Rule approved for implementation in the production environment?** [Yes/No]
* **Person responsible for approval:** [Name]
* **Date of implementation:** [Date]
* **Planned Maintenance & Monitoring:** Review scan detection alerts weekly; maintain authorized scanner IP exclusion list
