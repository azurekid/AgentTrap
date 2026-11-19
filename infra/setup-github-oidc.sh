#!/usr/bin/env bash
# One-time setup for separate GitHub Actions deployment and news publisher Entra identities.
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
NEWS_DISPLAY_NAME="github-${REPO%%/*}-agentlens-news"

CLIENT_ID="$(az ad app list --display-name "$DISPLAY_NAME" --query "[0].appId" -o tsv)"
if [ -z "$CLIENT_ID" ]; then
  CLIENT_ID="$(az ad app create --display-name "$DISPLAY_NAME" --query appId -o tsv)"
fi
az ad sp show --id "$CLIENT_ID" --output none 2>/dev/null || az ad sp create --id "$CLIENT_ID" --output none
SP_ID="$(az ad sp show --id "$CLIENT_ID" --query id -o tsv)"

NEWS_CLIENT_ID="$(az ad app list --display-name "$NEWS_DISPLAY_NAME" --query "[0].appId" -o tsv)"
if [ -z "$NEWS_CLIENT_ID" ]; then
  NEWS_CLIENT_ID="$(az ad app create --display-name "$NEWS_DISPLAY_NAME" --query appId -o tsv)"
fi
az ad sp show --id "$NEWS_CLIENT_ID" --output none 2>/dev/null || az ad sp create --id "$NEWS_CLIENT_ID" --output none
NEWS_SP_ID="$(az ad sp show --id "$NEWS_CLIENT_ID" --query id -o tsv)"

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
if az ad app federated-credential list --id "$CLIENT_ID" --query "[?subject=='$NEWS_SUBJECT'].name" -o tsv | grep -q .; then
  echo "Remove the latest-news federated credential from the deployment identity before continuing." >&2
  exit 1
fi
if ! az ad app federated-credential list --id "$NEWS_CLIENT_ID" --query "[?subject=='$NEWS_SUBJECT']" -o tsv | grep -q .; then
  az ad app federated-credential create --id "$NEWS_CLIENT_ID" --parameters "{
    \"name\": \"github-${NEWS_ENVIRONMENT}\",
    \"issuer\": \"https://token.actions.githubusercontent.com\",
    \"subject\": \"${NEWS_SUBJECT}\",
    \"audiences\": [\"api://AzureADTokenExchange\"]
  }" --output none
fi

# Only the production identity can deploy to the web app.
az role assignment create --assignee-object-id "$SP_ID" --assignee-principal-type ServicePrincipal \
  --role "Website Contributor" --scope "$APP_ID_SCOPE" --output none
az role assignment create --assignee-object-id "$SP_ID" --assignee-principal-type ServicePrincipal \
  --role "Storage Blob Data Contributor" --scope "$NEWS_CONTAINER_SCOPE" --output none
az role assignment create --assignee-object-id "$NEWS_SP_ID" --assignee-principal-type ServicePrincipal \
  --role "Storage Blob Data Contributor" --scope "$NEWS_CONTAINER_SCOPE" --output none

if ! gh api "repos/${REPO}/environments/${ENVIRONMENT}" --silent; then
  gh api --method PUT "repos/${REPO}/environments/${ENVIRONMENT}" --silent
fi
gh api --method PUT "repos/${REPO}/environments/${NEWS_ENVIRONMENT}" --input - --silent \
  <<< '{"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}'
DEFAULT_BRANCH="$(gh api "repos/$REPO" --jq .default_branch)"
if ! gh api "repos/${REPO}/environments/${NEWS_ENVIRONMENT}/deployment-branch-policies" \
  --jq '.branch_policies[] | select(.type == "branch").name' | grep -Fxq "$DEFAULT_BRANCH"; then
  gh api --method POST "repos/${REPO}/environments/${NEWS_ENVIRONMENT}/deployment-branch-policies" \
    -f name="$DEFAULT_BRANCH" -f type=branch --silent
fi
gh variable set AZURE_CLIENT_ID --repo "$REPO" --env "$NEWS_ENVIRONMENT" --body "$NEWS_CLIENT_ID"
gh variable set AZURE_TENANT_ID --repo "$REPO" --body "$TENANT_ID"
gh variable set AZURE_SUBSCRIPTION_ID --repo "$REPO" --body "$SUBSCRIPTION_ID"
gh variable set AZURE_RESOURCE_GROUP --repo "$REPO" --body "$RESOURCE_GROUP"
gh variable set AZURE_WEBAPP_NAME --repo "$REPO" --body "$APP_NAME"
gh variable set AZURE_STORAGE_ACCOUNT_NAME --repo "$REPO" --body "$STORAGE_ACCOUNT"
gh variable set AZURE_NEWS_CONTAINER --repo "$REPO" --body "$NEWS_CONTAINER"
gh variable set AZURE_CLIENT_ID --repo "$REPO" --body "$CLIENT_ID"

echo "GitHub Actions can deploy $APP_NAME and publish news for $REPO."
echo "Add required reviewers to the '$ENVIRONMENT' environment in GitHub settings to gate releases."
