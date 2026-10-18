#!/usr/bin/env bash
# Deploy the demo app to Cloud Run with its key mounted from Secret Manager.
# Usage: demo/deploy.sh <project-id> [region]
set -euo pipefail
PROJECT="$1"
REGION="${2:-us-central1}"
RUNTIME_SA="vg-demo-app@${PROJECT}.iam.gserviceaccount.com"
HERE="$(cd "$(dirname "$0")" && pwd)"

gcloud run deploy vg-demo \
  --project "$PROJECT" \
  --region "$REGION" \
  --source "$HERE/app" \
  --service-account "$RUNTIME_SA" \
  --set-secrets GEMINI_API_KEY=gemini-api-key:latest \
  --allow-unauthenticated \
  --max-instances 1 \
  --memory 256Mi \
  --quiet
