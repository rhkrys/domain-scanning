#!/usr/bin/env bash
# Package and deploy the quiz Lambda stack (techinpeace-quiz).
#
#   bash deploy/aws-quiz/deploy.sh            preview the change set, then ask
#   bash deploy/aws-quiz/deploy.sh --yes      preview, then apply without asking
#
# First run creates the stack and generates the rate-limit salt (never printed
# or saved). Later runs keep every parameter except the code.
set -euo pipefail

STACK="${QUIZ_STACK:-techinpeace-quiz}"
BUCKET="${ARTIFACTS_BUCKET:-cyber-protection-artifacts-306499034564-us-east-1}"
REGION="${AWS_DEFAULT_REGION:-us-east-1}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TEMPLATE="$ROOT/deploy/aws-quiz/template.yaml"

cd "$ROOT"
npm test >/dev/null || { echo "Tests failed; not deploying." >&2; exit 1; }

BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"' EXIT
echo "==> Packaging"
mkdir -p "$BUILD/public"
cp quiz-lambda.js package.json package-lock.json "$BUILD/"
cp -r src "$BUILD/"
cp public/logo-gold.png "$BUILD/public/"
(cd "$BUILD" && npm ci --omit=dev --silent >/dev/null)
# Fail now, not in Lambda, if a file the quiz imports was left out.
(cd "$BUILD" && node -e "import('./quiz-lambda.js').then(() => console.log('    package loads'))")
KEY="lambda/quiz-$(git rev-parse --short HEAD)-$(date +%s).zip"
(cd "$BUILD" && zip -qr function.zip . -x function.zip)
aws s3 cp "$BUILD/function.zip" "s3://$BUCKET/$KEY" --region "$REGION" --only-show-errors
echo "    s3://$BUCKET/$KEY"

if aws cloudformation describe-stacks --stack-name "$STACK" --region "$REGION" >/dev/null 2>&1; then
  TYPE=UPDATE
  PARAMS=(ParameterKey=LambdaCodeKey,ParameterValue="$KEY")
  for p in ExecutionRoleArn LambdaCodeBucket MailFrom NotifyTo AllowedOrigins RateSalt ReportsPerHour; do
    PARAMS+=("ParameterKey=$p,UsePreviousValue=true")
  done
else
  TYPE=CREATE
  PARAMS=(ParameterKey=LambdaCodeKey,ParameterValue="$KEY" ParameterKey=RateSalt,ParameterValue="$(openssl rand -hex 32)")
fi

CS="deploy-$(date +%s)"
echo "==> Change set ($TYPE)"
aws cloudformation create-change-set --stack-name "$STACK" --change-set-name "$CS" --change-set-type "$TYPE" \
  --template-body "file://$TEMPLATE" --parameters "${PARAMS[@]}" --region "$REGION" >/dev/null
aws cloudformation wait change-set-create-complete --stack-name "$STACK" --change-set-name "$CS" --region "$REGION"
aws cloudformation describe-change-set --stack-name "$STACK" --change-set-name "$CS" --region "$REGION" \
  --query 'Changes[].ResourceChange.[Action,LogicalResourceId,Replacement]' --output table

if [ "${1:-}" != "--yes" ]; then
  read -r -p "Apply this change set? [y/N] " ok
  [ "$ok" = "y" ] || { echo "Not applied. Change set $CS left for review."; exit 0; }
fi
aws cloudformation execute-change-set --stack-name "$STACK" --change-set-name "$CS" --region "$REGION"
if [ "$TYPE" = CREATE ]; then W=stack-create-complete; else W=stack-update-complete; fi
aws cloudformation wait "$W" --stack-name "$STACK" --region "$REGION"
aws cloudformation describe-stacks --stack-name "$STACK" --region "$REGION" --query 'Stacks[0].Outputs' --output table
