#!/usr/bin/env bash
# Deploy the hosted judge demo to Cloud Run.
#
#   scripts/deploy-cloud-run.sh <gcp-project-id>
#
# Needs: gcloud authenticated, billing enabled on the project, and the relayer
# key at .thine/relayer-testnet.json. The key travels only as a deploy-time
# environment variable; it is never in the repository or the image. It is a
# testnet demo key; for anything that mattered it would go through Secret
# Manager instead.
#
# One always-on minimal instance, because sessions live in memory: a visitor
# mid-migration must keep talking to the same process. min=max=1 also caps the
# cost at roughly ten to fifteen dollars a month.
set -euo pipefail

PROJECT=${1:?usage: deploy-cloud-run.sh <gcp-project-id>}
REGION=${REGION:-us-central1}

ACCOUNT=$(jq -r .account_id .thine/relayer-testnet.json)
KEY=$(jq -r .secret_key .thine/relayer-testnet.json)

gcloud services enable run.googleapis.com cloudbuild.googleapis.com \
    artifactregistry.googleapis.com --project "$PROJECT"

gcloud artifacts repositories create thine --repository-format=docker \
    --location="$REGION" --project "$PROJECT" 2>/dev/null || true

IMAGE="$REGION-docker.pkg.dev/$PROJECT/thine/thine-web:$(git rev-parse --short HEAD)"

# A Rust workspace outgrows the default build machine and timeout.
gcloud builds submit --project "$PROJECT" --tag "$IMAGE" \
    --timeout=3600 --machine-type=e2-highcpu-8

gcloud run deploy thine --project "$PROJECT" --region "$REGION" \
    --image "$IMAGE" --allow-unauthenticated \
    --min-instances 1 --max-instances 1 --memory 512Mi --cpu 1 \
    --set-env-vars "THINE_RELAYER_ACCOUNT=$ACCOUNT,THINE_RELAYER_KEY=$KEY"

echo
echo "Live at:"
gcloud run services describe thine --project "$PROJECT" --region "$REGION" \
    --format='value(status.url)'
