# Test Protocol for KQL Detection Rules

## 1. General Information

* **Rule Name:** [Name of the KQL rule]
* **Created by:** [Name of the creator]
* **Date:** [Date of test execution]
* **Version:** [Version of the rule]

## 2. Test Environment

* **Test Environment:** [Description of the test environment – e.g., Microsoft Sentinel, specific log sources]
* **Data Source:** [Which log data is used – e.g., Microsoft Defender logs, Windows Event Logs]
* **Simulated Attack Scenarios:**
    * [Attack Scenario 1 – Description]
    * [Attack Scenario 2 – Description]
    * [Add more scenarios here if multiple were tested]

## 3. Test Cases & Results

| Test Case | Description | Expected Result | Actual Result | Successful? (Yes/No) | Notes |
|-----------|-------------|-----------------|---------------|----------------------|-------|
| TC-01 | Simulated execution to trigger the rule | Rule detects activity and creates an alert | [Detection result] | [Yes/No – Adjustments needed?] | |
| TC-02 | False positive test: normal data flow without provoking | Rule does not generate unnecessary alert | [Detection result] | [Yes/No – False positives?] | |
| TC-03 | Test attack patterns with variations | Rule also detects slightly modified patterns | [Detection result] | [Yes/No – Further adjustments needed?] | |
| TC-04 | Performance test under high data load | Rule does not cause significant delays | [System impact result] | [Yes/No – Performance adjustments?] | |
| TC-05 | Test threshold adjustments | Rule remains reliable with different configurations | [Result] | [Yes/No – Define optimal thresholds?] | |

> TC = Test Case

## 4. Findings & Adjustments

* **False Positives Identified?** [Yes/No] → If yes, what causes were identified and what adjustments were made?
* **Detected threats categorized correctly?** [Yes/No]
* **Improvements needed for the rule?** [Yes/No]
* **Recommended Adjustments:**
    * [Description of required changes]
    * [Adjust filter logic or add additional conditions]
    * [Optimize thresholds]

## 5. Approval & Next Steps

* **Test phase completed?** [Yes/No]
* **Rule approved for implementation in the production environment?** [Yes/No]
* **Person responsible for approval:** [Name]
* **Date of implementation:** [Date]
* **Planned Maintenance & Monitoring:** [Regular review of the rule]
