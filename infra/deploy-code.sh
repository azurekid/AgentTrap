#!/usr/bin/env bash
# Upload a ZIP package to App Service and wait for the remote build and restart.
#
#   infra/deploy-code.sh <resource-group> <web-app-name> [zip]
#
# The upload returns immediately (--async): a synchronous deploy waits for the
# Oryx build in one HTTP request, which the gateway can end with a 504 although
# the build continues. Kudu deployment status is polled instead.
set -euo pipefail

RESOURCE_GROUP="$1"
APP_NAME="$2"
ZIP="${3:-dist/skillvenom.zip}"
TIMEOUT_SECONDS="${DEPLOY_TIMEOUT_SECONDS:-1200}"

latest() {
  az webapp log deployment list -g "$RESOURCE_GROUP" -n "$APP_NAME" \
    --query "[?!starts_with(id, 'temp-')] | [0].join(' ', [id, to_string(status), to_string(complete)])" -o tsv 2>/dev/null || true
}

previous_id="$(latest | cut -f1)"
echo "Uploading $ZIP to $APP_NAME..."
az webapp deploy --resource-group "$RESOURCE_GROUP" --name "$APP_NAME" \
  --src-path "$ZIP" --type zip --async true --track-status false --output none

deadline=$(( $(date +%s) + TIMEOUT_SECONDS ))
deployment_id=""
# Kudu status: 0 pending, 1 building, 2 deploying, 3 failed, 4 succeeded.
while :; do
  [ "$(date +%s)" -lt "$deadline" ] || { echo "Timed out waiting for the deployment." >&2; exit 1; }
  id=""; status=""; complete=""
  read -r id status complete <<<"$(latest)" || true
  if [ -n "${id:-}" ] && [ "$id" != "$previous_id" ]; then
    deployment_id="$id"
    if [ "$status" = "3" ]; then
      echo "Deployment $id failed. Log:" >&2
      az webapp log deployment show -g "$RESOURCE_GROUP" -n "$APP_NAME" --deployment-id "$id" \
        --query "[].message" -o tsv >&2 || true
      exit 1
    fi
    if [ "$status" = "4" ] && [ "$complete" = "true" ]; then
      echo "Build and deployment $id succeeded."
      break
    fi
    echo "  deployment $id: status $status"
  else
    echo "  waiting for the deployment to register..."
  fi
  sleep 15
done

URL="https://$(az webapp show -g "$RESOURCE_GROUP" -n "$APP_NAME" --query defaultHostName -o tsv)"
# After the build, App Service restarts the container; the first start takes about a minute.
# Give the restart time to begin so the previous version is not reported as healthy.
sleep 30
while [ "$(date +%s)" -lt "$deadline" ]; do
  if curl --silent --fail --max-time 10 "$URL/healthz" | grep -q '"ok"' \
    && curl --silent --fail --max-time 15 "$URL/" | grep -q 'id="scan-form"'; then
    echo "Healthy: $URL (deployment $deployment_id)"
    [ -z "${GITHUB_OUTPUT:-}" ] || echo "url=$URL" >> "$GITHUB_OUTPUT"
    exit 0
  fi
  sleep 15
done
echo "Deployment $deployment_id succeeded but $URL is not healthy. Inspect: az webapp log tail -g $RESOURCE_GROUP -n $APP_NAME" >&2
exit 1
