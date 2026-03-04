// Bicep Template: CheckPoint - Policy Change Detection Analytic Rule
// Deploys a Microsoft Sentinel Scheduled Analytics Rule

param workspaceName string
param location string = resourceGroup().location

@description('Enable or disable the analytic rule')
param ruleEnabled bool = true

resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
}

resource analyticsRule 'Microsoft.SecurityInsights/alertRules@2023-11-01' = {
  name: guid('CheckPoint-PolicyChangeDetection', subscription().subscriptionId, resourceGroup().id)
  scope: workspace
  kind: 'Scheduled'
  properties: {
    displayName: 'CheckPoint - Policy and Configuration Change Detection'
    description: 'Monitors for Check Point management events indicating policy installs, rule changes, admin logins, and configuration modifications. Provides audit trail and immediate visibility into firewall configuration changes.'
    severity: 'Medium'
    enabled: ruleEnabled
    query: '''
let DetectionWindow = 1h;
CommonSecurityLog
| where TimeGenerated >= ago(DetectionWindow)
| where DeviceVendor == "Check Point"
| where Activity has_any (
    "Policy Install", "Install Policy",
    "Log In", "Log Out",
    "Object Modified", "Object Created", "Object Deleted",
    "Rule Modified", "Rule Added", "Rule Deleted",
    "Admin", "SmartConsole", "Management"
)
    or DeviceEventClassID has_any ("mgmt", "policy", "admin", "audit")
| extend
    AdminUser = coalesce(SourceUserName, DestinationUserName),
    ChangeType = case(
        Activity has "Policy Install", "Policy Installed",
        Activity has "Log In",         "Admin Login",
        Activity has "Modified",       "Configuration Modified",
        Activity has "Created",        "Object Created",
        Activity has "Deleted",        "Object Deleted",
        Activity has "Rule",           "Rule Change",
        "Other Management Event"
    )
| project TimeGenerated, ChangeType, AdminUser, Activity, SourceIP,
          DeviceName, DeviceEventClassID, Message
| order by TimeGenerated desc
'''
    queryFrequency: 'PT1H'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'DefenseEvasion'
    ]
    techniques: [
      'T1562.004'
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
            columnName: 'AdminUser'
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
