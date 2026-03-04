// Bicep Template: CheckPoint - Blocked Traffic Spike Analytic Rule
// Deploys a Microsoft Sentinel Scheduled Analytics Rule

param workspaceName string
param location string = resourceGroup().location

@description('Enable or disable the analytic rule')
param ruleEnabled bool = true

resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
}

resource analyticsRule 'Microsoft.SecurityInsights/alertRules@2023-11-01' = {
  name: guid('CheckPoint-BlockedTrafficSpike', subscription().subscriptionId, resourceGroup().id)
  scope: workspace
  kind: 'Scheduled'
  properties: {
    displayName: 'CheckPoint - Blocked Traffic Spike Detection'
    description: 'Detects abnormal spikes in blocked/dropped connections from Check Point firewall. Compares the last hour of blocked traffic against a 14-day hourly baseline. Triggers when the current count exceeds 3x the standard deviation above average.'
    severity: 'Medium'
    enabled: ruleEnabled
    query: '''
let LookbackPeriod = 14d;
let DetectionWindow = 1h;
let ThresholdMultiplier = 3;
let MinimumEvents = 50;
let Baseline = CommonSecurityLog
    | where TimeGenerated between (ago(LookbackPeriod) .. ago(DetectionWindow))
    | where DeviceVendor == "Check Point" and DeviceProduct has "Firewall"
    | where DeviceAction in ("Drop", "Reject", "Block")
    | summarize HourlyCount = count() by bin(TimeGenerated, 1h)
    | summarize AvgCount = avg(HourlyCount), StdDev = stdev(HourlyCount);
let Current = CommonSecurityLog
    | where TimeGenerated >= ago(DetectionWindow)
    | where DeviceVendor == "Check Point" and DeviceProduct has "Firewall"
    | where DeviceAction in ("Drop", "Reject", "Block")
    | summarize CurrentCount = count(),
                DistinctSources = dcount(SourceIP),
                DistinctDestinations = dcount(DestinationIP),
                TopSources = make_set(SourceIP, 10),
                TopDestPorts = make_set(DestinationPort, 10);
Baseline
| join kind=inner Current on $left.AvgCount == $left.AvgCount
| where CurrentCount > MinimumEvents
| where CurrentCount > AvgCount + (StdDev * ThresholdMultiplier)
| extend AnomalyScore = round((CurrentCount - AvgCount) / StdDev, 2)
| project CurrentCount, AvgCount = round(AvgCount, 0), StdDev = round(StdDev, 0),
          AnomalyScore, DistinctSources, DistinctDestinations, TopSources, TopDestPorts
'''
    queryFrequency: 'PT1H'
    queryPeriod: 'P14D'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'InitialAccess'
      'Reconnaissance'
    ]
    techniques: []
    alertDetailsOverride: {}
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
