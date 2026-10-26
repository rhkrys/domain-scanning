#!/usr/bin/env bash
# Publish the site to staging.techinpeace.com. Uploads the same files, under
# the same names, as the live site, then clears the staging cache. Never
# touches the live bucket or distribution.
#
# Usage: AWS_PROFILE=svc-ai-cowork-mcp ./deploy/staging.sh
set -euo pipefail

PROFILE="${AWS_PROFILE:-svc-ai-cowork-mcp}"
STACK="${STACK:-techinpeace-staging}"
REGION="us-east-1"
AWS="aws --profile ${PROFILE} --region ${REGION}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

BUCKET="$(${AWS} cloudformation describe-stacks --stack-name "${STACK}" \
  --query "Stacks[0].Outputs[?OutputKey=='SiteBucketName'].OutputValue" --output text)"
DIST="$(${AWS} cloudformation describe-stacks --stack-name "${STACK}" \
  --query "Stacks[0].Outputs[?OutputKey=='DistributionId'].OutputValue" --output text)"
URL="$(${AWS} cloudformation describe-stacks --stack-name "${STACK}" \
  --query "Stacks[0].Outputs[?OutputKey=='StagingUrl'].OutputValue" --output text)"
case "${BUCKET}" in techinpeace.com|"") echo "Refusing: bucket '${BUCKET}' is not the staging bucket" >&2; exit 1;; esac

NOCACHE="no-cache, must-revalidate"
put() { # put <local file> <key> <content type> [cache-control]
  ${AWS} s3 cp "$1" "s3://${BUCKET}/$2" --content-type "$3" --cache-control "${4:-${NOCACHE}}" --only-show-errors
  echo "  $2"
}

echo "==> Uploading to s3://${BUCKET}"
# Scan page lives at /scan; the rest keep their names.
put public/index.html scan.html "text/html; charset=utf-8"
put public/app.js app.js "application/javascript"
put public/styles.css styles.css "text/css; charset=utf-8"
put public/config.js config.js "application/javascript"
put public/accordion.js accordion.js "application/javascript"
put public/accordion.css accordion.css "text/css; charset=utf-8"
put public/popup.js popup.js "application/javascript"
for f in public/*.svg public/*.png public/*.jpg public/*.webp public/*.ico; do
  [ -e "$f" ] || continue
  case "$f" in *.svg) ct="image/svg+xml";; *.png) ct="image/png";; *.jpg) ct="image/jpeg";; *.webp) ct="image/webp";; *.ico) ct="image/x-icon";; esac
  put "$f" "$(basename "$f")" "$ct" "public, max-age=86400"
done
for f in landing/*.html; do put "$f" "$(basename "$f")" "text/html; charset=utf-8"; done
for f in landing/*.png landing/*.svg landing/*.jpg landing/*.webp; do
  [ -e "$f" ] || continue
  case "$f" in *.svg) ct="image/svg+xml";; *.png) ct="image/png";; *.jpg) ct="image/jpeg";; *.webp) ct="image/webp";; esac
  put "$f" "$(basename "$f")" "$ct" "public, max-age=86400"
done
if [ -d public/.well-known ]; then
  for f in public/.well-known/*; do put "$f" ".well-known/$(basename "$f")" "text/plain; charset=utf-8"; done
fi

echo "==> Clearing the staging cache (${DIST})"
${AWS} cloudfront create-invalidation --distribution-id "${DIST}" --paths "/*" --query 'Invalidation.Id' --output text

echo "==> Staging: ${URL}"
