// Bicep Template: CheckPoint - Critical Severity Events Analytic Rule
// Deploys a Microsoft Sentinel Scheduled Analytics Rule

param workspaceName string
param location string = resourceGroup().location

@description('Enable or disable the analytic rule')
param ruleEnabled bool = true

resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
}

resource analyticsRule 'Microsoft.SecurityInsights/alertRules@2023-11-01' = {
  name: guid('CheckPoint-CriticalSeverityEvents', subscription().subscriptionId, resourceGroup().id)
  scope: workspace
  kind: 'Scheduled'
  properties: {
    displayName: 'CheckPoint - Critical Severity Events'
    description: 'Surfaces high/critical severity firewall events from Check Point that require immediate SOC attention. Enriches with direction classification and groups by event class for triage.'
    severity: 'High'
    enabled: ruleEnabled
    query: '''
CommonSecurityLog
| where TimeGenerated >= ago(1h)
| where DeviceVendor == "Check Point" and DeviceProduct has "Firewall"
| where LogSeverity in (8, 9, 10) or LogSeverity in ("High", "Critical", "Emergency")
| extend
    Severity = case(
        LogSeverity in (10, "Emergency"), "Emergency",
        LogSeverity in (9, "Critical"),   "Critical",
        LogSeverity in (8, "High"),       "High",
        tostring(LogSeverity)
    ),
    Direction = case(
        ipv4_is_private(SourceIP) and not(ipv4_is_private(DestinationIP)), "Outbound",
        not(ipv4_is_private(SourceIP)) and ipv4_is_private(DestinationIP), "Inbound",
        ipv4_is_private(SourceIP) and ipv4_is_private(DestinationIP),      "Internal",
        "External"
    )
| project
    TimeGenerated, Severity, DeviceAction, Activity,
    SourceIP, DestinationIP, DestinationPort, Protocol,
    Direction, DeviceEventClassID, DeviceName,
    Message = coalesce(Message, Activity)
| order by TimeGenerated desc
'''
    queryFrequency: 'PT1H'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'Impact'
      'DefenseEvasion'
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
