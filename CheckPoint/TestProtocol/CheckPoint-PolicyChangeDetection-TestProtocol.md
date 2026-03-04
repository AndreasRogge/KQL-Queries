# Test Protocol for KQL Detection Rules

## 1. General Information

* **Rule Name:** CheckPoint - Policy and Configuration Change Detection
* **Created by:** [Name of the creator]
* **Date:** [Date of test execution]
* **Version:** 1.0

## 2. Test Environment

* **Test Environment:** Microsoft Sentinel workspace with Check Point management event data ingestion via CommonSecurityLog
* **Data Source:** CommonSecurityLog (Check Point Management - DeviceVendor == "Check Point", Activity containing management keywords)
* **Simulated Attack Scenarios:**
    * Install a test policy on a Check Point gateway and verify the event is captured
    * Simulate an admin login to SmartConsole and modify a firewall rule

## 3. Test Cases & Results

| Test Case | Description | Expected Result | Actual Result | Successful? (Yes/No) | Notes |
|-----------|-------------|-----------------|---------------|----------------------|-------|
| TC-01 | Install a policy on a Check Point gateway via SmartConsole | Rule detects the event and classifies ChangeType as "Policy Installed" | [Detection result] | [Yes/No] | Verify AdminUser field is populated |
| TC-02 | Normal firewall traffic without any management events | Rule does not trigger; no false positive alert generated | [Detection result] | [Yes/No] | Confirm management event filtering excludes regular traffic |
| TC-03 | Modify a firewall rule (add/edit/delete) via SmartConsole | Rule detects and classifies as "Rule Change", "Configuration Modified", or "Object Deleted" | [Detection result] | [Yes/No] | Test multiple change type classifications |
| TC-04 | Generate multiple management events in rapid succession (policy install + rule changes + admin logins) | Rule handles high volume of management events without duplication or timeout | [System impact result] | [Yes/No] | Verify no event deduplication issues |
| TC-05 | Test with management events using DeviceEventClassID-based matching (mgmt, policy, admin, audit) | Rule correctly detects events matched by DeviceEventClassID in addition to Activity keywords | [Result] | [Yes/No] | Validate both matching approaches work |

> TC = Test Case

## 4. Findings & Adjustments

* **False Positives Identified?** [Yes/No] → If yes, what causes were identified and what adjustments were made?
* **Detected threats categorized correctly?** [Yes/No]
* **Improvements needed for the rule?** [Yes/No]
* **Recommended Adjustments:**
    * [Consider suppressing routine admin logins during known maintenance windows]
    * [Add service account exclusions for automated policy deployment tools]
    * [Implement change management ticket correlation for authorized changes]

## 5. Approval & Next Steps

* **Test phase completed?** [Yes/No]
* **Rule approved for implementation in the production environment?** [Yes/No]
* **Person responsible for approval:** [Name]
* **Date of implementation:** [Date]
* **Planned Maintenance & Monitoring:** Review change detection alerts daily; cross-reference with change management system
