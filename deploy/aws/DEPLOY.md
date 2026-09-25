# Launching the scanner on AWS

Two ways to launch, both on **AWS App Runner** (managed HTTPS, autoscaling,
health checks — no servers to run). Pick one.

> **Region tip:** the examples use `ap-southeast-2` (Sydney), the closest
> region for NZ users. Any App Runner region works.

## Option A — from GitHub, no Docker (easiest)

App Runner builds straight from this repo using `apprunner.yaml`.

1. AWS Console → **App Runner** → *Create service*.
2. Source: **Source code repository** → connect GitHub → pick
   `rhkrys/domain-scanning`, branch `main`, deployment trigger **Automatic**.
3. Build settings: **Use a configuration file** (it finds `apprunner.yaml`).
4. Service settings: name `domain-scanner`; 0.25 vCPU / 0.5 GB is plenty.
5. Health check: protocol **HTTP**, path **/healthz**.
6. (Optional, for email) Add the environment variables from the
   [Email via Amazon SES](#email-via-amazon-ses) section below.
7. Create. In a few minutes you get a public `https://….awsapprunner.com` URL.

Every push to `main` redeploys automatically.

## Option B — container via script

Builds the `Dockerfile`, pushes to ECR, and creates/updates the App Runner
service. Needs the AWS CLI (authenticated) and Docker locally.

```bash
# optional email config — see SES section
export SMTP_HOST=email-smtp.ap-southeast-2.amazonaws.com
export SMTP_PORT=587 SMTP_USER=... SMTP_PASS=...
export MAIL_FROM="Domain Scanner <scanner@yourdomain.com>"

AWS_REGION=ap-southeast-2 ./deploy/aws/deploy.sh
```

The script is idempotent: run it again to ship a new version.

## Email via Amazon SES

The app sends the report email over SMTP, which maps directly onto SES:

1. SES Console → **Verified identities** → verify your sending domain (or a
   single address while testing).
2. SES Console → **SMTP settings** → *Create SMTP credentials*. Note the SMTP
   endpoint, username and password.
3. Set these environment variables on the App Runner service:

   | Variable | Value |
   |---|---|
   | `SMTP_HOST` | `email-smtp.<region>.amazonaws.com` |
   | `SMTP_PORT` | `587` |
   | `SMTP_USER` / `SMTP_PASS` | the SMTP credentials from step 2 |
   | `MAIL_FROM` | a verified address, e.g. `Domain Scanner <scanner@yourdomain.com>` |

4. New SES accounts start in **sandbox mode** (can only email verified
   addresses). Request production access in the SES console before opening
   the scanner to the public.

Store `SMTP_PASS` as an App Runner **secret** (Parameter Store/Secrets
Manager reference) rather than a plain variable for production.

Without SMTP configuration the app still runs; it writes email previews to
the container's `./previews` directory instead of sending (fine for a demo,
lost on redeploy).

## Custom domain

App Runner → your service → **Custom domains** → add
`scanner.yourdomain.com` and create the DNS records it gives you.
Certificates are issued and renewed automatically.

## Network requirements (important)

The scanner's audit engine needs outbound HTTPS (port 443) for
DNS-over-HTTPS, TLS and header checks, and outbound DNS as a fallback.
App Runner's default **public** outgoing network mode allows all of this —
don't lock outbound traffic to a VPC without an egress path.

## Costs (indicative)

- App Runner 0.25 vCPU / 0.5 GB: roughly USD $5–15/month at low traffic
  (you pay for provisioned memory while idle, vCPU only while serving).
- SES: $0.10 per 1,000 emails.
- ECR (Option B only): pennies for one small image.
