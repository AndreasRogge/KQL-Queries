// Bicep Template: CheckPoint - VPN Anomalous Login Detection Analytic Rule
// Deploys a Microsoft Sentinel Scheduled Analytics Rule

param workspaceName string
param location string = resourceGroup().location

@description('Enable or disable the analytic rule')
param ruleEnabled bool = true

resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
}

resource analyticsRule 'Microsoft.SecurityInsights/alertRules@2023-11-01' = {
  name: guid('CheckPoint-VPNAnomalousLogin', subscription().subscriptionId, resourceGroup().id)
  scope: workspace
  kind: 'Scheduled'
  properties: {
    displayName: 'CheckPoint - VPN Anomalous Login Detection'
    description: 'Detects anomalous VPN login patterns through Check Point VPN. Identifies VPN logins from unusual source IPs not seen in the last 30 days for a given user, indicating potential credential compromise or unauthorized access.'
    severity: 'Medium'
    enabled: ruleEnabled
    query: '''
let DetectionWindow = 1h;
let LookbackPeriod = 30d;
CommonSecurityLog
| where TimeGenerated >= ago(DetectionWindow)
| where DeviceVendor == "Check Point"
| where Activity has_any ("VPN", "Remote Access", "SSL Network Extender", "Endpoint Security")
    or DeviceEventClassID has_any ("vpn", "ssl_vpn", "remote_access")
| where DeviceAction in ("Accept", "Allow", "Key Install")
| extend VPNUser = coalesce(SourceUserName, DestinationUserName)
| where isnotempty(VPNUser)
| project TimeGenerated, VPNUser, SourceIP, DeviceAction, Activity, DeviceName
| join kind=leftouter (
    CommonSecurityLog
    | where TimeGenerated between (ago(LookbackPeriod) .. ago(DetectionWindow))
    | where DeviceVendor == "Check Point"
    | where Activity has_any ("VPN", "Remote Access", "SSL Network Extender")
    | where DeviceAction in ("Accept", "Allow", "Key Install")
    | extend VPNUser = coalesce(SourceUserName, DestinationUserName)
    | where isnotempty(VPNUser)
    | summarize KnownSourceIPs = make_set(SourceIP, 100) by VPNUser
) on VPNUser
| extend IsNewSourceIP = not(KnownSourceIPs has SourceIP)
| where IsNewSourceIP == true
| project TimeGenerated, VPNUser, SourceIP, DeviceAction, Activity, DeviceName, IsNewSourceIP
| order by TimeGenerated desc
'''
    queryFrequency: 'PT1H'
    queryPeriod: 'P30D'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'InitialAccess'
    ]
    techniques: [
      'T1133'
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
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'VPNUser'
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
