#!/usr/bin/env bash
# Deploy the public live drill service (Cloud Run, us-central1).
# Usage: demo/live/deploy.sh <project-id> <project-number>
#
# Needs, once: the service account vg-live with only the custom role vgLiveDrill
# (apikeys.keys create/delete/get/getKeyString/list, serviceusage.operations.get),
# objectAdmin on the drill bucket, and run.invoker on the four vantage services
# (the deploy-vantage CI job grants it). The page is public; one drill runs at a time.
set -euo pipefail
PROJECT="$1"
NUMBER="$2"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
cp -r "$REPO/vibeguardian" "$REPO/pyproject.toml" "$REPO/README.md" "$STAGE/"
cp -r "$REPO/demo/live/main.py" "$REPO/demo/live/gunicorn.conf.py" "$REPO/demo/live/requirements.txt" \
      "$REPO/demo/live/Dockerfile" "$REPO/demo/live/static" "$STAGE/"
VANTAGES=""
for region in europe-west1 asia-northeast1 australia-southeast1 southamerica-east1; do
  VANTAGES="$VANTAGES $region=https://vg-vantage-$NUMBER.$region.run.app"
done

gcloud run deploy vg-live \
  --project "$PROJECT" \
  --region us-central1 \
  --source "$STAGE" \
  --service-account "vg-live@$PROJECT.iam.gserviceaccount.com" \
  --set-env-vars "^|^GCP_PROJECT_ID=$PROJECT|BUCKET=vg-live-drills-$NUMBER|HERE_REGION=us-central1|VANTAGES=${VANTAGES# }" \
  --allow-unauthenticated \
  --no-cpu-throttling \
  --memory 512Mi \
  --max-instances 1 \
  --timeout 300 \
  --quiet
