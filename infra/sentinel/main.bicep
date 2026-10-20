// Microsoft Sentinel scheduled analytics rules from the cookbook's YAML (rendered by tools/sentinel_deploy.py).
// One template, N rules: the YAML is the source of truth, this file never carries a query.
targetScope = 'resourceGroup'

@description('Log Analytics workspace that hosts Sentinel')
param workspaceName string

@description('Rules rendered from detections/*.yml (status: prod, platform: sentinel-kql)')
param rules array

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource rule 'Microsoft.SecurityInsights/alertRules@2023-02-01' = [for r in rules: {
  scope: workspace
  name: r.name
  kind: 'Scheduled'
  properties: {
    displayName: r.displayName
    description: r.description
    severity: r.severity
    enabled: r.enabled
    query: r.query
    queryFrequency: r.queryFrequency
    queryPeriod: r.queryPeriod
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: r.tactics
    techniques: r.techniques
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
}]

output deployedRules array = [for (r, i) in rules: rule[i].name]
