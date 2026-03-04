// Bicep Template: CheckPoint - Suspicious Outbound Traffic Analytic Rule
// Deploys a Microsoft Sentinel Scheduled Analytics Rule

param workspaceName string
param location string = resourceGroup().location

@description('Enable or disable the analytic rule')
param ruleEnabled bool = true

resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
}

resource analyticsRule 'Microsoft.SecurityInsights/alertRules@2023-11-01' = {
  name: guid('CheckPoint-SuspiciousOutboundTraffic', subscription().subscriptionId, resourceGroup().id)
  scope: workspace
  kind: 'Scheduled'
  properties: {
    displayName: 'CheckPoint - Suspicious Outbound Traffic to New Destinations'
    description: 'Detects outbound connections to external IPs that have not been seen in the last 14 days. Identifies internal hosts connecting to rare/never-before-seen external destinations, filtering out common benign ports (80, 443, 53).'
    severity: 'Medium'
    enabled: ruleEnabled
    query: '''
let LookbackPeriod = 14d;
let DetectionWindow = 1h;
let MinConnectionsNewDest = 3;
let KnownDestinations = CommonSecurityLog
    | where TimeGenerated between (ago(LookbackPeriod) .. ago(DetectionWindow))
    | where DeviceVendor == "Check Point" and DeviceProduct has "Firewall"
    | where DeviceAction == "Accept"
    | where ipv4_is_private(SourceIP) and not(ipv4_is_private(DestinationIP))
    | distinct DestinationIP;
CommonSecurityLog
| where TimeGenerated >= ago(DetectionWindow)
| where DeviceVendor == "Check Point" and DeviceProduct has "Firewall"
| where DeviceAction == "Accept"
| where ipv4_is_private(SourceIP) and not(ipv4_is_private(DestinationIP))
| where DestinationIP !in (KnownDestinations)
| where DestinationPort !in (80, 443, 53)
| summarize
    ConnectionCount = count(),
    DistinctPorts = dcount(DestinationPort),
    Ports = make_set(DestinationPort, 20),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SourceIP, DestinationIP, DeviceName
| where ConnectionCount >= MinConnectionsNewDest
| order by ConnectionCount desc
'''
    queryFrequency: 'PT1H'
    queryPeriod: 'P14D'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'CommandAndControl'
      'Exfiltration'
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
