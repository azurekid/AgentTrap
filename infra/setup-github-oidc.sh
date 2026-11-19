#!/usr/bin/env bash
# One-time setup for the GitHub Actions deployment: a Microsoft Entra app with a
# federated credentials (OIDC, no client secret) for code deployment and news publishing.
#
#   RESOURCE_GROUP=rg-agentlens infra/setup-github-oidc.sh [owner/repo]
set -euo pipefail

RESOURCE_GROUP="${RESOURCE_GROUP:-rg-agentlens}"
REPO="${1:-$(gh repo view --json nameWithOwner -q .nameWithOwner)}"
ENVIRONMENT=production
NEWS_ENVIRONMENT=latest-news

APP_NAME="${APP_NAME:-$(az webapp list --resource-group "$RESOURCE_GROUP" --query "[?tags.application=='agentlens'].name | [0]" -o tsv)}"
[ -n "$APP_NAME" ] || { echo "Deploy the infrastructure first (infra/deploy.sh)." >&2; exit 1; }
APP_ID_SCOPE="$(az webapp show -g "$RESOURCE_GROUP" -n "$APP_NAME" --query id -o tsv)"
TENANT_ID="$(az account show --query tenantId -o tsv)"
SUBSCRIPTION_ID="$(az account show --query id -o tsv)"
STORAGE_ACCOUNT="$(az storage account list -g "$RESOURCE_GROUP" --query "[?tags.application=='agentlens'].name | [0]" -o tsv)"
[ -n "$STORAGE_ACCOUNT" ] || { echo "No AgentLens storage account in $RESOURCE_GROUP." >&2; exit 1; }
NEWS_CONTAINER=agentlens-news
NEWS_CONTAINER_SCOPE="/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Storage/storageAccounts/${STORAGE_ACCOUNT}/blobServices/default/containers/${NEWS_CONTAINER}"
DISPLAY_NAME="github-${REPO%%/*}-agentlens-deploy"

CLIENT_ID="$(az ad app list --display-name "$DISPLAY_NAME" --query "[0].appId" -o tsv)"
if [ -z "$CLIENT_ID" ]; then
  CLIENT_ID="$(az ad app create --display-name "$DISPLAY_NAME" --query appId -o tsv)"
fi
az ad sp show --id "$CLIENT_ID" --output none 2>/dev/null || az ad sp create --id "$CLIENT_ID" --output none
SP_ID="$(az ad sp show --id "$CLIENT_ID" --query id -o tsv)"

SUBJECT="${OIDC_SUBJECT:-$(gh api "repos/$REPO" --jq '"repo:\(.owner.login)@\(.owner.id)/\(.name)@\(.id):environment:production"')}"
NEWS_SUBJECT="$(gh api "repos/$REPO" --jq '"repo:\(.owner.login)@\(.owner.id)/\(.name)@\(.id):environment:latest-news"')"
if ! az ad app federated-credential list --id "$CLIENT_ID" --query "[?subject=='$SUBJECT']" -o tsv | grep -q .; then
  az ad app federated-credential create --id "$CLIENT_ID" --parameters "{
    \"name\": \"github-${ENVIRONMENT}\",
    \"issuer\": \"https://token.actions.githubusercontent.com\",
    \"subject\": \"${SUBJECT}\",
    \"audiences\": [\"api://AzureADTokenExchange\"]
  }" --output none
fi
if ! az ad app federated-credential list --id "$CLIENT_ID" --query "[?subject=='$NEWS_SUBJECT']" -o tsv | grep -q .; then
  az ad app federated-credential create --id "$CLIENT_ID" --parameters "{
    \"name\": \"github-${NEWS_ENVIRONMENT}\",
    \"issuer\": \"https://token.actions.githubusercontent.com\",
    \"subject\": \"${NEWS_SUBJECT}\",
    \"audiences\": [\"api://AzureADTokenExchange\"]
  }" --output none
fi

# Website Contributor on this web app only: enough for code deployment, nothing else.
az role assignment create --assignee-object-id "$SP_ID" --assignee-principal-type ServicePrincipal \
  --role "Website Contributor" --scope "$APP_ID_SCOPE" --output none
az role assignment create --assignee-object-id "$SP_ID" --assignee-principal-type ServicePrincipal \
  --role "Storage Blob Data Contributor" --scope "$NEWS_CONTAINER_SCOPE" --output none

if ! gh api "repos/${REPO}/environments/${ENVIRONMENT}" --silent; then
  gh api --method PUT "repos/${REPO}/environments/${ENVIRONMENT}" --silent
fi
if ! gh api "repos/${REPO}/environments/${NEWS_ENVIRONMENT}" --silent; then
  gh api --method PUT "repos/${REPO}/environments/${NEWS_ENVIRONMENT}" --silent
fi
gh variable set AZURE_TENANT_ID --repo "$REPO" --body "$TENANT_ID"
gh variable set AZURE_SUBSCRIPTION_ID --repo "$REPO" --body "$SUBSCRIPTION_ID"
gh variable set AZURE_RESOURCE_GROUP --repo "$REPO" --body "$RESOURCE_GROUP"
gh variable set AZURE_WEBAPP_NAME --repo "$REPO" --body "$APP_NAME"
gh variable set AZURE_STORAGE_ACCOUNT_NAME --repo "$REPO" --body "$STORAGE_ACCOUNT"
gh variable set AZURE_NEWS_CONTAINER --repo "$REPO" --body "$NEWS_CONTAINER"
gh variable set AZURE_CLIENT_ID --repo "$REPO" --body "$CLIENT_ID"

echo "GitHub Actions can deploy $APP_NAME and publish news for $REPO."
echo "Add required reviewers to the '$ENVIRONMENT' environment in GitHub settings to gate releases."
