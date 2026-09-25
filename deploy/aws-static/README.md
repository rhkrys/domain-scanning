# Deploy as an S3 + CloudFront site (custom domain)

Serves the scanner on your own domain as a static site on **S3 + CloudFront**,
with the audit backend running as a **Lambda** behind the same distribution
(`/api/*`). The TLS certificate is issued and validated automatically through
**Route 53**, and the apex + `www` records are created for you.

```
                       ┌────────────────────────────┐
   awesomeblackbusiness.com ──▶│        CloudFront          │
                       │  default  ─▶ S3 (static page)     │
   /api/* ────────────────────▶│  /api/*  ─▶ Lambda Function URL │
                       └────────────────────────────┘
   TLS: ACM cert (us-east-1, DNS-validated in Route 53)
```

## Why a Lambda is here

S3 + CloudFront only serve static files. The scanner's `POST /api/scan`
actually runs DNS/TLS/HTTP checks and sends email, so it needs compute. The
same Express app is wrapped as a Lambda (`lambda.js`) and CloudFront routes
`/api/*` to it — one domain, one distribution, no always-on server.

## Prerequisites

- AWS CLI v2, authenticated with a profile that can manage S3, CloudFront,
  Lambda, IAM, ACM and Route 53.
- **The domain's hosted zone already exists in Route 53 in this account.** The
  script looks it up; it does not register domains.
- `node`, `npm` and `zip` on the machine running the script (to package the
  Lambda).

## Run it

```bash
AWS_PROFILE=svc-ai-cowork-mcp DOMAIN=awesomeblackbusiness.com \
  ./deploy/aws-static/deploy.sh
```

Optional email (Amazon SES) — export before running:

```bash
export SMTP_HOST=email-smtp.us-east-1.amazonaws.com SMTP_PORT=587 \
       SMTP_USER=... SMTP_PASS=... \
       MAIL_FROM="Cyber Protection <scanner@awesomeblackbusiness.com>"
```

The script:

1. resolves the Route 53 hosted zone for the domain,
2. packages the Lambda (prod deps only) and uploads it to an artifacts bucket,
3. deploys the CloudFormation stack (`deploy/aws-static/template.yaml`),
4. syncs `public/` to the site bucket and invalidates CloudFront.

**First run takes ~20–30 minutes** — most of it is ACM validation and the
CloudFront distribution rolling out. Re-runs (new code or content) are quick.

## What gets created

| Resource | Purpose |
|---|---|
| S3 bucket (private) | Static page; reachable only via CloudFront (OAC) |
| CloudFront distribution | HTTPS, apex + www, `/api/*` → Lambda, everything else → S3 |
| Lambda + Function URL | The audit/email backend (`nodejs22.x`, 256 MB) |
| ACM certificate | `DomainName` + `www`, DNS-validated in Route 53 (us-east-1) |
| Route 53 A-alias records | apex + www → CloudFront |

## Verify

```bash
curl -sI https://awesomeblackbusiness.com | head -1          # 200
curl -s https://awesomeblackbusiness.com/api/scan \
  -X POST -H 'content-type: application/json' \
  -d '{"domain":"example.com"}' | head -c 200                # JSON report
```

## Notes & hardening

- **Region is fixed to `us-east-1`** because CloudFront requires its ACM
  certificate there. The Lambda runs there too.
- The Lambda must keep **public internet egress** (no VPC without a NAT), or the
  DNS-over-HTTPS / TLS / header checks can't reach the domains being scanned.
- The Lambda **Function URL uses `AuthType: NONE`**. It's rate-limited in-app and
  only does domain scans, but for defence-in-depth you can switch it to
  `AWS_IAM` with a CloudFront origin-access control and sign requests.
- **Email:** Amazon SES starts in sandbox mode (verified recipients only).
  Verify your domain and request production access before going public.
- **Teardown:** empty the site + artifacts buckets, then
  `aws cloudformation delete-stack --stack-name cyber-protection-scanner --region us-east-1 --profile <profile>`.

## Cost (indicative, low traffic)

CloudFront + S3 + Lambda for a low-traffic site is typically **a few dollars a
month** (Lambda and S3 are pay-per-use; CloudFront PriceClass_100 limits edge
locations to keep cost down). SES is $0.10 per 1,000 emails. Route 53 is $0.50
per hosted zone per month.
