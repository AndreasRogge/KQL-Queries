// Bicep Template: CheckPoint - Brute Force Detection Analytic Rule
// Deploys a Microsoft Sentinel Scheduled Analytics Rule

param workspaceName string
param location string = resourceGroup().location

@description('Enable or disable the analytic rule')
param ruleEnabled bool = true

resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
}

resource analyticsRule 'Microsoft.SecurityInsights/alertRules@2023-11-01' = {
  name: guid('CheckPoint-BruteForceDetection', subscription().subscriptionId, resourceGroup().id)
  scope: workspace
  kind: 'Scheduled'
  properties: {
    displayName: 'CheckPoint - Brute Force Detection'
    description: 'Identifies external IPs with a high volume of dropped/rejected connections to common authentication ports (SSH, RDP, SMB, FTP) indicating brute force attempts against services behind Check Point firewall.'
    severity: 'Medium'
    enabled: ruleEnabled
    query: '''
let DetectionWindow = 15m;
let FailedConnectionThreshold = 30;
let AuthPorts = dynamic([22, 23, 3389, 445, 21, 3306, 1433, 5432, 8080, 8443]);
CommonSecurityLog
| where TimeGenerated >= ago(DetectionWindow)
| where DeviceVendor == "Check Point" and DeviceProduct has "Firewall"
| where DeviceAction in ("Drop", "Reject", "Block")
| where not(ipv4_is_private(SourceIP)) and ipv4_is_private(DestinationIP)
| where DestinationPort in (AuthPorts)
| summarize
    FailedAttempts = count(),
    DistinctTargets = dcount(DestinationIP),
    DistinctPorts = dcount(DestinationPort),
    TargetIPs = make_set(DestinationIP, 10),
    TargetPorts = make_set(DestinationPort, 10),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by SourceIP, DeviceName
| where FailedAttempts >= FailedConnectionThreshold
| extend
    AttackType = case(
        DistinctTargets > 3 and DistinctPorts == 1, "Password Spray (multi-target, single port)",
        DistinctTargets == 1 and DistinctPorts == 1, "Brute Force (single target)",
        DistinctTargets > 1 and DistinctPorts > 1,  "Distributed Scan",
        "Brute Force"
    ),
    DurationMinutes = datetime_diff('minute', LastAttempt, FirstAttempt)
| order by FailedAttempts desc
'''
    queryFrequency: 'PT15M'
    queryPeriod: 'PT15M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'CredentialAccess'
    ]
    techniques: [
      'T1110'
    ]
    entityMappings: [
      {
        entityType: 'IP'
        fieldMappings: [
          {
            identifier: 'Address'
            columnName: 'SourceIP'
          }
        ]
      }
    ]
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'AllEntities'
      }
    }
  }
}

output ruleId string = analyticsRule.id
