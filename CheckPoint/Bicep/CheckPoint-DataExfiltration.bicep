// Bicep Template: CheckPoint - Data Exfiltration Detection Analytic Rule
// Deploys a Microsoft Sentinel Scheduled Analytics Rule

param workspaceName string
param location string = resourceGroup().location

@description('Enable or disable the analytic rule')
param ruleEnabled bool = true

resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
}

resource analyticsRule 'Microsoft.SecurityInsights/alertRules@2023-11-01' = {
  name: guid('CheckPoint-DataExfiltration', subscription().subscriptionId, resourceGroup().id)
  scope: workspace
  kind: 'Scheduled'
  properties: {
    displayName: 'CheckPoint - Data Exfiltration Detection'
    description: 'Detects potential data exfiltration via unusually large outbound transfers from internal hosts. Uses a 14-day per-source baseline with 3x standard deviation threshold and 100 MB minimum to reduce noise.'
    severity: 'High'
    enabled: ruleEnabled
    query: '''
let LookbackPeriod = 14d;
let DetectionWindow = 1h;
let ThresholdMultiplier = 3;
let MinBytesThreshold = 104857600;
let Baseline = CommonSecurityLog
    | where TimeGenerated between (ago(LookbackPeriod) .. ago(DetectionWindow))
    | where DeviceVendor == "Check Point" and DeviceProduct has "Firewall"
    | where DeviceAction == "Accept"
    | where ipv4_is_private(SourceIP) and not(ipv4_is_private(DestinationIP))
    | where SentBytes > 0
    | summarize HourlySentBytes = sum(SentBytes) by SourceIP, bin(TimeGenerated, 1h)
    | summarize AvgHourlySentBytes = avg(HourlySentBytes), StdDevBytes = stdev(HourlySentBytes) by SourceIP;
CommonSecurityLog
| where TimeGenerated >= ago(DetectionWindow)
| where DeviceVendor == "Check Point" and DeviceProduct has "Firewall"
| where DeviceAction == "Accept"
| where ipv4_is_private(SourceIP) and not(ipv4_is_private(DestinationIP))
| where SentBytes > 0
| summarize
    CurrentSentBytes = sum(SentBytes),
    DistinctDestinations = dcount(DestinationIP),
    TopDestinations = make_set(DestinationIP, 10),
    TopPorts = make_set(DestinationPort, 10),
    ConnectionCount = count()
    by SourceIP
| join kind=inner Baseline on SourceIP
| where CurrentSentBytes > MinBytesThreshold
| where CurrentSentBytes > AvgHourlySentBytes + (StdDevBytes * ThresholdMultiplier)
| extend
    AnomalyScore = round((CurrentSentBytes - AvgHourlySentBytes) / StdDevBytes, 2),
    CurrentSentMB = round(CurrentSentBytes / 1048576.0, 2),
    AvgHourlyMB = round(AvgHourlySentBytes / 1048576.0, 2)
| project SourceIP, CurrentSentMB, AvgHourlyMB, AnomalyScore,
          DistinctDestinations, TopDestinations, TopPorts, ConnectionCount
| order by AnomalyScore desc
'''
    queryFrequency: 'PT1H'
    queryPeriod: 'P14D'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'Exfiltration'
    ]
    techniques: [
      'T1048'
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
