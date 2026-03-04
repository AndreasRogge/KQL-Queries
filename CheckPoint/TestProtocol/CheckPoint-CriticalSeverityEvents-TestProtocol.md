# Test Protocol for KQL Detection Rules

## 1. General Information

* **Rule Name:** CheckPoint - Critical Severity Events
* **Created by:** [Name of the creator]
* **Date:** [Date of test execution]
* **Version:** 1.0

## 2. Test Environment

* **Test Environment:** Microsoft Sentinel workspace with Check Point firewall data ingestion via CommonSecurityLog
* **Data Source:** CommonSecurityLog (Check Point Firewall - DeviceVendor == "Check Point", LogSeverity >= 8)
* **Simulated Attack Scenarios:**
    * Trigger an IPS blade detection with Critical severity on the Check Point gateway
    * Generate a high-severity event through Anti-Bot or Threat Prevention blade detection

## 3. Test Cases & Results

| Test Case | Description | Expected Result | Actual Result | Successful? (Yes/No) | Notes |
|-----------|-------------|-----------------|---------------|----------------------|-------|
| TC-01 | Trigger a Critical severity event (LogSeverity 9) via IPS blade detection | Rule detects the event, classifies severity as "Critical", and creates an alert | [Detection result] | [Yes/No] | Verify severity classification logic |
| TC-02 | Normal traffic with LogSeverity < 8 (informational/low severity) | Rule does not trigger; no false positive alert generated | [Detection result] | [Yes/No] | Confirm severity filtering works |
| TC-03 | Generate events with string-based LogSeverity ("High", "Critical", "Emergency") | Rule correctly handles both numeric and string severity formats | [Detection result] | [Yes/No] | Test both LogSeverity formats |
| TC-04 | Generate high volume of high-severity events (100+ in one hour) | Rule executes efficiently and groups events for triage without timeout | [System impact result] | [Yes/No] | Monitor alert volume and query performance |
| TC-05 | Test direction classification with inbound, outbound, and internal high-severity events | Direction field correctly classifies based on source/destination IP ranges | [Result] | [Yes/No] | Validate RFC1918 direction logic |

> TC = Test Case

## 4. Findings & Adjustments

* **False Positives Identified?** [Yes/No] → If yes, what causes were identified and what adjustments were made?
* **Detected threats categorized correctly?** [Yes/No]
* **Improvements needed for the rule?** [Yes/No]
* **Recommended Adjustments:**
    * [Consider adding suppression for known recurring high-severity events during maintenance]
    * [Add incident grouping by DeviceEventClassID to reduce alert fatigue]
    * [Filter out specific blade events if they are operational rather than security-relevant]

## 5. Approval & Next Steps

* **Test phase completed?** [Yes/No]
* **Rule approved for implementation in the production environment?** [Yes/No]
* **Person responsible for approval:** [Name]
* **Date of implementation:** [Date]
* **Planned Maintenance & Monitoring:** Review high-severity event trends daily; adjust suppression rules monthly
