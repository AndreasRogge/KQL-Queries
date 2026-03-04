# Test Protocol for KQL Detection Rules

## 1. General Information

* **Rule Name:** CheckPoint - Brute Force Detection
* **Created by:** [Name of the creator]
* **Date:** [Date of test execution]
* **Version:** 1.0

## 2. Test Environment

* **Test Environment:** Microsoft Sentinel workspace with Check Point firewall data ingestion via CommonSecurityLog
* **Data Source:** CommonSecurityLog (Check Point Firewall - DeviceVendor == "Check Point")
* **Simulated Attack Scenarios:**
    * Simulated SSH brute force attack (30+ blocked attempts to port 22) from an external IP targeting a single internal host within 15 minutes
    * Simulated password spray (30+ blocked attempts from one external IP targeting multiple internal hosts on port 3389/RDP)
    * Simulated distributed scan across multiple authentication ports (SSH, RDP, SMB, FTP)

## 3. Test Cases & Results

| Test Case | Description | Expected Result | Actual Result | Successful? (Yes/No) | Notes |
|-----------|-------------|-----------------|---------------|----------------------|-------|
| TC-01 | Generate 30+ blocked SSH connections from external IP to single internal host in 15 min | Rule detects and classifies as "Brute Force (single target)" | [Detection result] | [Yes/No] | Verify AttackType classification |
| TC-02 | Normal blocked traffic from external IPs below 30 attempts in 15 min | Rule does not trigger; no false positive generated | [Detection result] | [Yes/No] | Confirm threshold filtering works |
| TC-03 | Generate 30+ blocked connections from external IP to 4+ internal hosts on port 3389 | Rule detects and classifies as "Password Spray (multi-target, single port)" | [Detection result] | [Yes/No] | Validate password spray classification |
| TC-04 | Run rule during peak traffic with high event volume on authentication ports | Rule executes within 15-minute frequency without timeout or delays | [System impact result] | [Yes/No] | Monitor query performance |
| TC-05 | Adjust FailedConnectionThreshold from 30 to 20 and test with moderate attack | Rule triggers at lower threshold; validates tunability | [Result] | [Yes/No] | Define optimal threshold for environment |

> TC = Test Case

## 4. Findings & Adjustments

* **False Positives Identified?** [Yes/No] → If yes, what causes were identified and what adjustments were made?
* **Detected threats categorized correctly?** [Yes/No]
* **Improvements needed for the rule?** [Yes/No]
* **Recommended Adjustments:**
    * [Tune FailedConnectionThreshold based on environment noise level]
    * [Add additional authentication ports if custom services exist]
    * [Consider adding geo-IP enrichment for source IP attribution]

## 5. Approval & Next Steps

* **Test phase completed?** [Yes/No]
* **Rule approved for implementation in the production environment?** [Yes/No]
* **Person responsible for approval:** [Name]
* **Date of implementation:** [Date]
* **Planned Maintenance & Monitoring:** Review blocked connection patterns weekly; adjust AuthPorts list as needed
