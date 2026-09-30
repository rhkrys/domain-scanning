#!/usr/bin/env bash
# One-command AWS launch: builds the container, pushes it to ECR, and creates
# (or updates) an App Runner service with HTTPS, autoscaling and health checks.
#
# Prerequisites: aws cli v2 (authenticated), docker.
# Usage:
#   ./deploy/aws/deploy.sh                 # deploy with defaults
#   AWS_REGION=ap-southeast-2 ./deploy/aws/deploy.sh
#
# Email (optional but recommended): set these in your shell before running and
# they are passed to the service as runtime environment variables.
#   SMTP_HOST SMTP_PORT SMTP_USER SMTP_PASS MAIL_FROM

set -euo pipefail

APP_NAME="${APP_NAME:-domain-scanner}"
AWS_REGION="${AWS_REGION:-$(aws configure get region || echo ap-southeast-2)}"
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
ECR_REPO="${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${APP_NAME}"
IMAGE_TAG="${IMAGE_TAG:-$(git rev-parse --short HEAD 2>/dev/null || date +%s)}"
IMAGE="${ECR_REPO}:${IMAGE_TAG}"

echo "==> Deploying ${APP_NAME} to ${AWS_REGION} (account ${ACCOUNT_ID})"

# 1. ECR repository (idempotent)
aws ecr describe-repositories --repository-names "${APP_NAME}" --region "${AWS_REGION}" >/dev/null 2>&1 ||
  aws ecr create-repository --repository-name "${APP_NAME}" --region "${AWS_REGION}" \
    --image-scanning-configuration scanOnPush=true >/dev/null
echo "==> ECR repository ready: ${ECR_REPO}"

# 2. Build and push the image
aws ecr get-login-password --region "${AWS_REGION}" |
  docker login --username AWS --password-stdin "${ECR_REPO%%/*}"
docker build -t "${IMAGE}" "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"
docker push "${IMAGE}"
echo "==> Pushed ${IMAGE}"

# 3. IAM role App Runner uses to pull from ECR (idempotent)
ROLE_NAME="${APP_NAME}-ecr-access"
if ! aws iam get-role --role-name "${ROLE_NAME}" >/dev/null 2>&1; then
  aws iam create-role --role-name "${ROLE_NAME}" --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": { "Service": "build.apprunner.amazonaws.com" },
      "Action": "sts:AssumeRole"
    }]
  }' >/dev/null
  aws iam attach-role-policy --role-name "${ROLE_NAME}" \
    --policy-arn arn:aws:iam::aws:policy/service-role/AWSAppRunnerServicePolicyForECRAccess
  echo "==> Created IAM role ${ROLE_NAME}; waiting for it to propagate..."
  sleep 12
fi
ROLE_ARN="$(aws iam get-role --role-name "${ROLE_NAME}" --query Role.Arn --output text)"

# 4. Runtime environment variables (email config is optional)
ENV_VARS="{\"PORT\": \"3000\""
for var in SMTP_HOST SMTP_PORT SMTP_SECURE SMTP_USER SMTP_PASS MAIL_FROM; do
  if [ -n "${!var:-}" ]; then ENV_VARS="${ENV_VARS}, \"${var}\": \"${!var}\""; fi
done
ENV_VARS="${ENV_VARS}}"

SOURCE_CONFIG="{
  \"ImageRepository\": {
    \"ImageIdentifier\": \"${IMAGE}\",
    \"ImageRepositoryType\": \"ECR\",
    \"ImageConfiguration\": { \"Port\": \"3000\", \"RuntimeEnvironmentVariables\": ${ENV_VARS} }
  },
  \"AuthenticationConfiguration\": { \"AccessRoleArn\": \"${ROLE_ARN}\" },
  \"AutoDeploymentsEnabled\": false
}"

HEALTH_CONFIG='{ "Protocol": "HTTP", "Path": "/healthz", "Interval": 10, "Timeout": 5, "HealthyThreshold": 1, "UnhealthyThreshold": 3 }'

# 5. Create the service, or roll the existing one to the new image
SERVICE_ARN="$(aws apprunner list-services --region "${AWS_REGION}" \
  --query "ServiceSummaryList[?ServiceName=='${APP_NAME}'].ServiceArn | [0]" --output text)"

if [ "${SERVICE_ARN}" = "None" ] || [ -z "${SERVICE_ARN}" ]; then
  echo "==> Creating App Runner service ${APP_NAME}"
  SERVICE_ARN="$(aws apprunner create-service --region "${AWS_REGION}" \
    --service-name "${APP_NAME}" \
    --source-configuration "${SOURCE_CONFIG}" \
    --health-check-configuration "${HEALTH_CONFIG}" \
    --instance-configuration '{ "Cpu": "0.25 vCPU", "Memory": "0.5 GB" }' \
    --query Service.ServiceArn --output text)"
else
  echo "==> Updating App Runner service ${APP_NAME}"
  aws apprunner update-service --region "${AWS_REGION}" \
    --service-arn "${SERVICE_ARN}" \
    --source-configuration "${SOURCE_CONFIG}" >/dev/null
fi

echo "==> Waiting for the service to go live (this can take a few minutes)..."
while true; do
  STATUS="$(aws apprunner describe-service --region "${AWS_REGION}" \
    --service-arn "${SERVICE_ARN}" --query Service.Status --output text)"
  [ "${STATUS}" = "RUNNING" ] && break
  if [ "${STATUS}" = "CREATE_FAILED" ] || [ "${STATUS}" = "UPDATE_FAILED" ]; then
    echo "!! Deployment failed (status ${STATUS}). Check the App Runner logs in the console." >&2
    exit 1
  fi
  printf '.'
  sleep 10
done
echo

URL="$(aws apprunner describe-service --region "${AWS_REGION}" \
  --service-arn "${SERVICE_ARN}" --query Service.ServiceUrl --output text)"
echo "==> Live: https://${URL}"
echo "==> Smoke test: curl https://${URL}/healthz"
