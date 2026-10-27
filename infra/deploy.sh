#!/usr/bin/env bash
# Provision SkillVenom on Azure (Bicep) and deploy the application code.
#
#   infra/deploy.sh                 # provision + deploy
#   infra/deploy.sh --what-if       # preview infrastructure changes only
#   infra/deploy.sh --code-only     # redeploy code to existing resources
#
# Environment: RESOURCE_GROUP (default rg-skillvenom), LOCATION (default westeurope),
#              AZURE_SUBSCRIPTION_ID (default: current az account).
set -euo pipefail

cd "$(dirname "$0")/.."
RESOURCE_GROUP="${RESOURCE_GROUP:-rg-skillvenom}"
LOCATION="${LOCATION:-westeurope}"
MODE="${1:-deploy}"
TEMPLATE=infra/main.bicep
PARAMETERS=infra/main.parameters.json

az account show --output none 2>/dev/null || { echo "Run 'az login' first." >&2; exit 1; }
if [ -n "${AZURE_SUBSCRIPTION_ID:-}" ]; then
  az account set --subscription "$AZURE_SUBSCRIPTION_ID"
fi
echo "Subscription: $(az account show --query name -o tsv)"
echo "Resource group: $RESOURCE_GROUP ($LOCATION)"

case "$MODE" in
  --what-if)
    az group create --name "$RESOURCE_GROUP" --location "$LOCATION" --tags application=SkillVenom --output none
    az deployment group what-if --resource-group "$RESOURCE_GROUP" \
      --template-file "$TEMPLATE" --parameters "@$PARAMETERS" --parameters location="$LOCATION"
    exit 0
    ;;
  --code-only)
    APP_NAME="$(az webapp list --resource-group "$RESOURCE_GROUP" --query "[?tags.application=='SkillVenom'].name | [0]" -o tsv)"
    [ -n "$APP_NAME" ] || { echo "No SkillVenom web app in $RESOURCE_GROUP. Run without --code-only first." >&2; exit 1; }
    ;;
  deploy)
    az group create --name "$RESOURCE_GROUP" --location "$LOCATION" --tags application=SkillVenom --output none
    DEPLOYMENT="skillvenom-$(date -u +%Y%m%d%H%M%S)"
    az deployment group create --resource-group "$RESOURCE_GROUP" --name "$DEPLOYMENT" \
      --template-file "$TEMPLATE" --parameters "@$PARAMETERS" --parameters location="$LOCATION" --output none
    APP_NAME="$(az deployment group show -g "$RESOURCE_GROUP" -n "$DEPLOYMENT" --query properties.outputs.webAppName.value -o tsv)"
    ;;
  *)
    echo "Unknown option: $MODE" >&2; exit 2
    ;;
esac

infra/package.sh dist/skillvenom.zip
echo "Deploying code to $APP_NAME (remote build installs requirements.txt)..."
az webapp deploy --resource-group "$RESOURCE_GROUP" --name "$APP_NAME" \
  --src-path dist/skillvenom.zip --type zip --track-status false --output none

URL="https://$(az webapp show -g "$RESOURCE_GROUP" -n "$APP_NAME" --query defaultHostName -o tsv)"
# The first start can fail until the new role assignment propagates; App Service restarts it.
for attempt in $(seq 1 40); do
  if curl --silent --fail --max-time 10 "$URL/healthz" | grep -q '"ok"'; then
    echo "Healthy: $URL"
    exit 0
  fi
  sleep 15
done
echo "Health check did not pass within 10 minutes. Inspect logs: az webapp log tail -g $RESOURCE_GROUP -n $APP_NAME" >&2
exit 1
