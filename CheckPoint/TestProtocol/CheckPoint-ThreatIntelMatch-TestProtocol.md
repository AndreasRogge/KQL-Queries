# Test Protocol for KQL Detection Rules

## 1. General Information

* **Rule Name:** CheckPoint - Threat Intelligence IP Match
* **Created by:** [Name of the creator]
* **Date:** [Date of test execution]
* **Version:** 1.0

## 2. Test Environment

* **Test Environment:** Microsoft Sentinel workspace with Check Point firewall data and ThreatIntelligenceIndicator table populated
* **Data Source:** CommonSecurityLog (Check Point Firewall), ThreatIntelligenceIndicator (Microsoft Sentinel Threat Intelligence)
* **Simulated Attack Scenarios:**
    * Add a test IP to the ThreatIntelligenceIndicator table and generate firewall traffic to that IP to verify correlation
    * Generate outbound and inbound traffic matching known TI indicator IPs

## 3. Test Cases & Results

| Test Case | Description | Expected Result | Actual Result | Successful? (Yes/No) | Notes |
|-----------|-------------|-----------------|---------------|----------------------|-------|
| TC-01 | Generate outbound traffic to an external IP matching an active TI indicator | Rule detects match, classifies as "Outbound to malicious", reports Action_Taken | [Detection result] | [Yes/No] | Verify TI join produces correct match |
| TC-02 | Normal traffic to external IPs not in TI indicator table | Rule does not trigger; no false positive matches generated | [Detection result] | [Yes/No] | Confirm no spurious TI matches |
| TC-03 | Generate inbound traffic from an external IP matching a TI indicator | Rule detects match, classifies as "Inbound from malicious" with correct Direction | [Detection result] | [Yes/No] | Validate bidirectional matching logic |
| TC-04 | Run rule with large TI indicator table (>10K active indicators) against high-volume firewall logs | Query completes within acceptable time; join operation is efficient | [System impact result] | [Yes/No] | Monitor join performance and resource usage |
| TC-05 | Test with expired TI indicator (ExpirationDateTime < now()) | Rule does not match expired indicators; only active indicators produce alerts | [Result] | [Yes/No] | Validate TI indicator expiration filtering |

> TC = Test Case

## 4. Findings & Adjustments

* **False Positives Identified?** [Yes/No] → If yes, what causes were identified and what adjustments were made?
* **Detected threats categorized correctly?** [Yes/No]
* **Improvements needed for the rule?** [Yes/No]
* **Recommended Adjustments:**
    * [Review and clean stale TI indicators that may cause false positives]
    * [Add confidence score filtering to reduce low-confidence matches]
    * [Consider enriching with domain-based and URL-based TI matching in addition to IP]

## 5. Approval & Next Steps

* **Test phase completed?** [Yes/No]
* **Rule approved for implementation in the production environment?** [Yes/No]
* **Person responsible for approval:** [Name]
* **Date of implementation:** [Date]
* **Planned Maintenance & Monitoring:** Review TI indicator freshness weekly; monitor for stale or overly broad indicators
