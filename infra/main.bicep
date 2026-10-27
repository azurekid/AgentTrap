// SkillVenom: Linux App Service + private Blob archive, managed identity only (no keys).
targetScope = 'resourceGroup'

@description('Azure region for all resources.')
param location string = resourceGroup().location

@description('Short prefix used in resource names.')
@minLength(3)
@maxLength(12)
param namePrefix string = 'skillvenom'

@description('App Service plan SKU. B1 is the smallest tier with Always On.')
@allowed(['B1', 'B2', 'B3', 'P0v3', 'P1v3'])
param appServiceSku string = 'B3'

@description('Python runtime for App Service Linux.')
param pythonVersion string = '3.14'

@description('Private container for investigation records and statistics.')
param archiveContainerName string = 'skillvenom-investigations'

@description('Days after which archived investigation records are deleted.')
@minValue(1)
@maxValue(365)
param archiveRetentionDays int = 30

@description('Log Analytics retention in days.')
@minValue(30)
@maxValue(730)
param logRetentionDays int = 30

@description('Reverse proxies in front of the app that append X-Forwarded-For (App Service front end = 1, plus Front Door = 2).')
@minValue(0)
@maxValue(4)
param trustedProxyHops int = 1

@description('Comma-separated self-managed GitLab host names users may scan (empty = gitlab.com only).')
param gitlabHosts string = ''

@description('Comma-separated Azure DevOps Server host names users may scan (empty = dev.azure.com only).')
param azureDevOpsHosts string = ''

param tags object = {
  application: 'SkillVenom'
}

var suffix = take(uniqueString(resourceGroup().id, namePrefix), 8)
var storageName = take('st${replace(namePrefix, '-', '')}${suffix}', 24)
// Built-in role: Storage Blob Data Contributor
var blobDataContributorRoleId = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'

resource logs 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: 'log-${namePrefix}-${suffix}'
  location: location
  tags: tags
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: logRetentionDays
  }
}

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  tags: tags
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {
    accessTier: 'Hot'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    allowCrossTenantReplication: false
    defaultToOAuthAuthentication: true
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      defaultAction: 'Allow'
      bypass: 'AzureServices'
    }
  }
}

// No soft delete or versioning: retained copies would outlive the stated retention period.
resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storage
  name: 'default'
  properties: {
    deleteRetentionPolicy: { enabled: false }
    containerDeleteRetentionPolicy: { enabled: false }
    isVersioningEnabled: false
    changeFeed: { enabled: false }
  }
}

resource archiveContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: archiveContainerName
  properties: {
    publicAccess: 'None'
  }
}

// statistics/totals.json lives outside the investigations/ prefix and is kept.
resource retention 'Microsoft.Storage/storageAccounts/managementPolicies@2023-05-01' = {
  parent: storage
  name: 'default'
  properties: {
    policy: {
      rules: [
        {
          enabled: true
          name: 'expire-skillvenom-investigations'
          type: 'Lifecycle'
          definition: {
            filters: {
              blobTypes: ['blockBlob']
              prefixMatch: ['${archiveContainerName}/investigations/']
            }
            actions: {
              baseBlob: {
                delete: { daysAfterModificationGreaterThan: archiveRetentionDays }
              }
            }
          }
        }
      ]
    }
  }
}

resource plan 'Microsoft.Web/serverfarms@2024-04-01' = {
  name: 'asp-${namePrefix}-${suffix}'
  location: location
  tags: tags
  kind: 'linux'
  sku: { name: appServiceSku }
  properties: {
    reserved: true
  }
}

resource site 'Microsoft.Web/sites@2024-04-01' = {
  name: 'app-${namePrefix}-${suffix}'
  location: location
  tags: tags
  kind: 'app,linux'
  identity: { type: 'SystemAssigned' }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    clientAffinityEnabled: false
    publicNetworkAccess: 'Enabled'
    siteConfig: {
      linuxFxVersion: 'PYTHON|${pythonVersion}'
      // One worker: rate limits and scan concurrency are per process.
      appCommandLine: 'python -m uvicorn web.app:app --host 0.0.0.0 --port 8000 --workers 1 --no-proxy-headers'
      alwaysOn: true
      healthCheckPath: '/healthz'
      http20Enabled: true
      minTlsVersion: '1.2'
      scmMinTlsVersion: '1.2'
      ftpsState: 'Disabled'
      remoteDebuggingEnabled: false
      numberOfWorkers: 1
      appSettings: [
        { name: 'ARCHIVE_BACKEND', value: 'azure' }
        { name: 'AZURE_STORAGE_ACCOUNT', value: storage.name }
        { name: 'AZURE_STORAGE_CONTAINER', value: archiveContainer.name }
        // The lifecycle rule in this template enforces the retention period.
        { name: 'AZURE_ARCHIVE_RETENTION_CONFIRMED', value: 'true' }
        { name: 'TRUSTED_PROXY_HOPS', value: string(trustedProxyHops) }
        { name: 'SCAN_TIMEOUT_SECONDS', value: '60' }
        { name: 'SCM_GITLAB_HOSTS', value: gitlabHosts }
        { name: 'SCM_AZDO_HOSTS', value: azureDevOpsHosts }
        { name: 'SCM_DO_BUILD_DURING_DEPLOYMENT', value: 'true' }
        { name: 'WEBSITES_PORT', value: '8000' }
        { name: 'PYTHONUNBUFFERED', value: '1' }
      ]
    }
  }
  dependsOn: [retention]
}

// Deployments use Microsoft Entra ID (OIDC / az login), never publishing passwords.
resource ftpCredentials 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2024-04-01' = {
  parent: site
  name: 'ftp'
  properties: { allow: false }
}

resource scmCredentials 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2024-04-01' = {
  parent: site
  name: 'scm'
  properties: { allow: false }
}

// Least privilege: data access to the archive container only.
resource archiveAccess 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(archiveContainer.id, site.id, blobDataContributorRoleId)
  scope: archiveContainer
  properties: {
    principalId: site.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', blobDataContributorRoleId)
  }
}

resource siteDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'to-log-analytics'
  scope: site
  properties: {
    workspaceId: logs.id
    logs: [
      { categoryGroup: 'allLogs', enabled: true }
    ]
    metrics: [
      { category: 'AllMetrics', enabled: true }
    ]
  }
}

// Audit trail of every read/write/delete on the investigation archive.
resource blobDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'archive-audit'
  scope: blobService
  properties: {
    workspaceId: logs.id
    logs: [
      { categoryGroup: 'allLogs', enabled: true }
    ]
  }
}

output webAppName string = site.name
output webAppUrl string = 'https://${site.properties.defaultHostName}'
output storageAccountName string = storage.name
output archiveContainerName string = archiveContainer.name
output logAnalyticsWorkspaceName string = logs.name
