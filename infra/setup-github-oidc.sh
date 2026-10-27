#!/usr/bin/env bash
# One-time setup for the GitHub Actions deployment: a Microsoft Entra app with a
# federated credential (OIDC, no client secret) that may only deploy code to the web app.
#
#   RESOURCE_GROUP=rg-skillvenom infra/setup-github-oidc.sh [owner/repo]
set -euo pipefail

RESOURCE_GROUP="${RESOURCE_GROUP:-rg-skillvenom}"
REPO="${1:-$(gh repo view --json nameWithOwner -q .nameWithOwner)}"
ENVIRONMENT=production

APP_NAME="$(az webapp list --resource-group "$RESOURCE_GROUP" --query "[?tags.application=='SkillVenom'].name | [0]" -o tsv)"
[ -n "$APP_NAME" ] || { echo "Deploy the infrastructure first (infra/deploy.sh)." >&2; exit 1; }
APP_ID_SCOPE="$(az webapp show -g "$RESOURCE_GROUP" -n "$APP_NAME" --query id -o tsv)"
TENANT_ID="$(az account show --query tenantId -o tsv)"
SUBSCRIPTION_ID="$(az account show --query id -o tsv)"
DISPLAY_NAME="github-${REPO//\//-}-deploy"

CLIENT_ID="$(az ad app list --display-name "$DISPLAY_NAME" --query "[0].appId" -o tsv)"
if [ -z "$CLIENT_ID" ]; then
  CLIENT_ID="$(az ad app create --display-name "$DISPLAY_NAME" --query appId -o tsv)"
fi
az ad sp show --id "$CLIENT_ID" --output none 2>/dev/null || az ad sp create --id "$CLIENT_ID" --output none
SP_ID="$(az ad sp show --id "$CLIENT_ID" --query id -o tsv)"

SUBJECT="repo:${REPO}:environment:${ENVIRONMENT}"
if ! az ad app federated-credential list --id "$CLIENT_ID" --query "[?subject=='$SUBJECT']" -o tsv | grep -q .; then
  az ad app federated-credential create --id "$CLIENT_ID" --parameters "{
    \"name\": \"github-${ENVIRONMENT}\",
    \"issuer\": \"https://token.actions.githubusercontent.com\",
    \"subject\": \"${SUBJECT}\",
    \"audiences\": [\"api://AzureADTokenExchange\"]
  }" --output none
fi

# Website Contributor on this web app only: enough for code deployment, nothing else.
az role assignment create --assignee-object-id "$SP_ID" --assignee-principal-type ServicePrincipal \
  --role "Website Contributor" --scope "$APP_ID_SCOPE" --output none

gh api --method PUT "repos/${REPO}/environments/${ENVIRONMENT}" --silent
gh variable set AZURE_CLIENT_ID --repo "$REPO" --body "$CLIENT_ID"
gh variable set AZURE_TENANT_ID --repo "$REPO" --body "$TENANT_ID"
gh variable set AZURE_SUBSCRIPTION_ID --repo "$REPO" --body "$SUBSCRIPTION_ID"
gh variable set AZURE_RESOURCE_GROUP --repo "$REPO" --body "$RESOURCE_GROUP"
gh variable set AZURE_WEBAPP_NAME --repo "$REPO" --body "$APP_NAME"

echo "GitHub Actions can now deploy $APP_NAME from $REPO (environment: $ENVIRONMENT)."
echo "Add required reviewers to the '$ENVIRONMENT' environment in GitHub settings to gate releases."
