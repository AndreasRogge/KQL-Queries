// Bicep Template: CheckPoint - Threat Intelligence Match Analytic Rule
// Deploys a Microsoft Sentinel Scheduled Analytics Rule

param workspaceName string
param location string = resourceGroup().location

@description('Enable or disable the analytic rule')
param ruleEnabled bool = true

resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
}

resource analyticsRule 'Microsoft.SecurityInsights/alertRules@2023-11-01' = {
  name: guid('CheckPoint-ThreatIntelMatch', subscription().subscriptionId, resourceGroup().id)
  scope: workspace
  kind: 'Scheduled'
  properties: {
    displayName: 'CheckPoint - Threat Intelligence IP Match'
    description: 'Correlates Check Point firewall logs with Microsoft Sentinel Threat Intelligence indicators (IP-based). Matches both source and destination IPs against active TI indicators and classifies direction as outbound-to-malicious or inbound-from-malicious.'
    severity: 'High'
    enabled: ruleEnabled
    query: '''
let DetectionWindow = 1h;
let TI_IPs = ThreatIntelligenceIndicator
    | where isnotempty(NetworkIP) or isnotempty(NetworkSourceIP) or isnotempty(NetworkDestinationIP)
    | where Active == true and ExpirationDateTime > now()
    | extend TI_IP = coalesce(NetworkIP, NetworkSourceIP, NetworkDestinationIP)
    | where isnotempty(TI_IP)
    | summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by TI_IP;
CommonSecurityLog
| where TimeGenerated >= ago(DetectionWindow)
| where DeviceVendor == "Check Point" and DeviceProduct has "Firewall"
| where isnotempty(SourceIP) or isnotempty(DestinationIP)
| extend CheckIP = iff(not(ipv4_is_private(DestinationIP)), DestinationIP, SourceIP)
| join kind=inner (TI_IPs) on $left.CheckIP == $right.TI_IP
| project
    TimeGenerated, DeviceAction, Activity,
    SourceIP, DestinationIP, DestinationPort, Protocol,
    TI_IP, ThreatType, ThreatSeverity = ConfidenceScore,
    Description, DeviceName,
    Direction = iff(CheckIP == DestinationIP, "Outbound to malicious", "Inbound from malicious"),
    Action_Taken = iff(DeviceAction in ("Drop", "Reject", "Block"), "Blocked", "Allowed")
| order by TimeGenerated desc
'''
    queryFrequency: 'PT1H'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'CommandAndControl'
    ]
    techniques: []
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
      {
        entityType: 'IP'
        fieldMappings: [
          {
            identifier: 'Address'
            columnName: 'DestinationIP'
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
