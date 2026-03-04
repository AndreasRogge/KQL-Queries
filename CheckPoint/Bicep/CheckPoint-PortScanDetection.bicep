// Bicep Template: CheckPoint - Port Scan Detection Analytic Rule
// Deploys a Microsoft Sentinel Scheduled Analytics Rule

param workspaceName string
param location string = resourceGroup().location

@description('Enable or disable the analytic rule')
param ruleEnabled bool = true

resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
}

resource analyticsRule 'Microsoft.SecurityInsights/alertRules@2023-11-01' = {
  name: guid('CheckPoint-PortScanDetection', subscription().subscriptionId, resourceGroup().id)
  scope: workspace
  kind: 'Scheduled'
  properties: {
    displayName: 'CheckPoint - Port Scan Detection'
    description: 'Identifies vertical and horizontal port scanning patterns through Check Point firewall. Detects hosts connecting to an unusually high number of distinct destination ports on a single target (vertical) or scanning one port across many destinations (horizontal).'
    severity: 'Medium'
    enabled: ruleEnabled
    query: '''
let DetectionWindow = 15m;
let DistinctPortThreshold = 25;
let DistinctHostPortThreshold = 50;
let VerticalScans = CommonSecurityLog
    | where TimeGenerated >= ago(DetectionWindow)
    | where DeviceVendor == "Check Point" and DeviceProduct has "Firewall"
    | where isnotempty(DestinationPort)
    | summarize
        DistinctPorts = dcount(DestinationPort),
        Ports = make_set(DestinationPort, 50),
        EventCount = count(),
        Actions = make_set(DeviceAction)
        by SourceIP, DestinationIP, DeviceName
    | where DistinctPorts >= DistinctPortThreshold
    | extend ScanType = "Vertical";
let HorizontalScans = CommonSecurityLog
    | where TimeGenerated >= ago(DetectionWindow)
    | where DeviceVendor == "Check Point" and DeviceProduct has "Firewall"
    | where isnotempty(DestinationPort)
    | summarize
        DistinctHosts = dcount(DestinationIP),
        Targets = make_set(DestinationIP, 50),
        EventCount = count(),
        Actions = make_set(DeviceAction)
        by SourceIP, DestinationPort, DeviceName
    | where DistinctHosts >= DistinctHostPortThreshold
    | extend ScanType = "Horizontal",
             DestinationIP = tostring(Targets[0]);
union VerticalScans, HorizontalScans
| project TimeGenerated = now(), ScanType, SourceIP, DestinationIP,
          DestinationPort = coalesce(DestinationPort, 0),
          DistinctPorts, EventCount, Actions, DeviceName
| order by EventCount desc
'''
    queryFrequency: 'PT15M'
    queryPeriod: 'PT15M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'Reconnaissance'
    ]
    techniques: [
      'T1046'
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
