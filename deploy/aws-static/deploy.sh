#!/usr/bin/env bash
# Deploy the scanner as an S3 + CloudFront site (Lambda backend for /api/*) on
# a custom domain, with an auto-validated ACM certificate and Route 53 records.
#
# Prereqs: aws cli v2, a working AWS profile, and the domain's hosted zone in
# Route 53 in the same account. Run from anywhere in the repo.
#
# Usage:
#   AWS_PROFILE=svc-ai-cowork-mcp DOMAIN=awesomeblackbusiness.com \
#     ./deploy/aws-static/deploy.sh
#
# Optional email (Amazon SES) — exported before running:
#   SMTP_HOST SMTP_PORT SMTP_SECURE SMTP_USER SMTP_PASS MAIL_FROM

set -euo pipefail

PROFILE="${AWS_PROFILE:-svc-ai-cowork-mcp}"
DOMAIN="${DOMAIN:-awesomeblackbusiness.com}"
STACK="${STACK:-cyber-protection-scanner}"
# CloudFront certificates MUST live in us-east-1, so the whole stack goes there.
REGION="us-east-1"
AWS="aws --profile ${PROFILE} --region ${REGION}"

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || cd "$(dirname "$0")/../.." && pwd)"
cd "${ROOT}"

echo "==> Profile ${PROFILE} / region ${REGION} / domain ${DOMAIN}"
ACCOUNT_ID="$(${AWS} sts get-caller-identity --query Account --output text)"
echo "==> Account ${ACCOUNT_ID}"

# 1. Resolve the Route 53 hosted zone for the domain
HOSTED_ZONE_ID="${HOSTED_ZONE_ID:-$(${AWS} route53 list-hosted-zones-by-name \
  --dns-name "${DOMAIN}." \
  --query "HostedZones[?Name=='${DOMAIN}.'].Id | [0]" --output text | sed 's#/hostedzone/##')}"
if [ -z "${HOSTED_ZONE_ID}" ] || [ "${HOSTED_ZONE_ID}" = "None" ]; then
  echo "!! No Route 53 hosted zone found for ${DOMAIN}. Create/transfer the zone first." >&2
  exit 1
fi
echo "==> Hosted zone ${HOSTED_ZONE_ID}"

# 2. Artifacts bucket for the packaged Lambda
ARTIFACTS_BUCKET="cyber-protection-artifacts-${ACCOUNT_ID}-${REGION}"
if ! ${AWS} s3api head-bucket --bucket "${ARTIFACTS_BUCKET}" 2>/dev/null; then
  echo "==> Creating artifacts bucket ${ARTIFACTS_BUCKET}"
  ${AWS} s3api create-bucket --bucket "${ARTIFACTS_BUCKET}" >/dev/null
  ${AWS} s3api put-public-access-block --bucket "${ARTIFACTS_BUCKET}" \
    --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
fi

# 3. Package the Lambda (prod deps only) and upload
echo "==> Packaging Lambda"
BUILD="$(mktemp -d)"
trap 'rm -rf "${BUILD}"' EXIT
cp -r server.js lambda.js src public package.json package-lock.json "${BUILD}/"
( cd "${BUILD}" && npm ci --omit=dev --silent )
ZIP="${BUILD}/function.zip"
( cd "${BUILD}" && zip -qr "${ZIP}" server.js lambda.js src public package.json node_modules )
CODE_KEY="lambda/function-$(date +%s).zip"
${AWS} s3 cp "${ZIP}" "s3://${ARTIFACTS_BUCKET}/${CODE_KEY}" >/dev/null
echo "==> Uploaded s3://${ARTIFACTS_BUCKET}/${CODE_KEY}"

# 4. Deploy the stack (this blocks while ACM validates + CloudFront rolls out)
echo "==> Deploying CloudFormation stack ${STACK} (CloudFront can take 15-25 min)"
${AWS} cloudformation deploy \
  --stack-name "${STACK}" \
  --template-file deploy/aws-static/template.yaml \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides \
    DomainName="${DOMAIN}" \
    HostedZoneId="${HOSTED_ZONE_ID}" \
    LambdaCodeBucket="${ARTIFACTS_BUCKET}" \
    LambdaCodeKey="${CODE_KEY}" \
    SmtpHost="${SMTP_HOST:-}" \
    SmtpPort="${SMTP_PORT:-587}" \
    SmtpSecure="${SMTP_SECURE:-false}" \
    SmtpUser="${SMTP_USER:-}" \
    SmtpPass="${SMTP_PASS:-}" \
    MailFrom="${MAIL_FROM:-}"

# 5. Push the current Lambda code onto the (possibly pre-existing) function
FN="$(${AWS} cloudformation describe-stack-resource --stack-name "${STACK}" \
  --logical-resource-id ApiFunction --query StackResourceDetail.PhysicalResourceId --output text)"
${AWS} lambda update-function-code --function-name "${FN}" \
  --s3-bucket "${ARTIFACTS_BUCKET}" --s3-key "${CODE_KEY}" >/dev/null
echo "==> Lambda ${FN} updated"

# 6. Sync the static site to S3 and invalidate CloudFront
SITE_BUCKET="$(${AWS} cloudformation describe-stacks --stack-name "${STACK}" \
  --query "Stacks[0].Outputs[?OutputKey=='SiteBucketName'].OutputValue" --output text)"
DIST_ID="$(${AWS} cloudformation describe-stacks --stack-name "${STACK}" \
  --query "Stacks[0].Outputs[?OutputKey=='DistributionId'].OutputValue" --output text)"

echo "==> Syncing public/ to s3://${SITE_BUCKET}"
${AWS} s3 sync public/ "s3://${SITE_BUCKET}/" --delete \
  --cache-control "public,max-age=300"
# index.html should not be cached hard, so redeploys show immediately
${AWS} s3 cp public/index.html "s3://${SITE_BUCKET}/index.html" \
  --cache-control "no-cache" --content-type "text/html" >/dev/null

echo "==> Invalidating CloudFront ${DIST_ID}"
${AWS} cloudfront create-invalidation --distribution-id "${DIST_ID}" --paths "/*" >/dev/null

echo
echo "==> Done. Live at: https://${DOMAIN}  (and https://www.${DOMAIN})"
echo "    Smoke test:   curl -sI https://${DOMAIN} | head -1"
echo "    API check:    curl -s https://${DOMAIN}/api/scan -X POST -H 'content-type: application/json' -d '{\"domain\":\"example.com\"}'"
