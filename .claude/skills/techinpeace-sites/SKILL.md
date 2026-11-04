---
name: techinpeace-sites
description: Set up a Claude Code session to work on the Tech in Peace sites (techinpeace.com live, staging.techinpeace.com) and their DNS at GoDaddy. Use at the start of any session that will deploy to AWS, push to GitHub, or change GoDaddy DNS, or when a command fails with a network, login or permission error.
---

# Tech in Peace sites: session setup and runbook

Everything a fresh Claude Code chat needs before it can push to GitHub, deploy to AWS, or change DNS at
GoDaddy. The two login skills do the sign-ins; this skill is the checklist and the inventory.

## 1. One-time environment setup (cloud sessions)

In the cloud environment's settings (environment menu in the session title bar, then Edit):

**Network access: Limited, with "Allow package managers" ticked**, plus these allowed domains:

| Needed for | Domains |
|---|---|
| AWS (CLI calls, SSO device login, CLI installer) | `*.amazonaws.com`, `*.awsapps.com`, `awscli.amazonaws.com` |
| GitHub (fetch, push, release downloads such as the gddy installer) | `github.com`, `*.githubusercontent.com` |
| GoDaddy (docs, CLI API, sign-in) | `developer.godaddy.com`, `api.godaddy.com`, `sso.godaddy.com` |
| Optional: check the live pages from the session | `techinpeace.com`, `www.techinpeace.com`, `staging.techinpeace.com`, `*.cloudfront.net` |
| Optional: run the scanner locally | `cloudflare-dns.com`, `dns.google`, `fonts.googleapis.com`, `fonts.gstatic.com` |

Package managers (npm, pip) are covered by the tick box. No environment secrets are required: AWS uses a
device login each session, and GoDaddy uses a browser login on the user's Mac. The only secret that ever
belongs in environment settings is `GDDY_PAT` (a GoDaddy Personal Access Token), and only if the user
chooses the token path for cloud sessions. Never paste tokens into chat.

**Skills.** These live in this repo under `.claude/skills/` and load when the repo is the working
directory: `aws-sso-login`, `godaddy-dns`, and this one. To have them in any chat regardless of repo,
add them as account skills in claude.ai settings (the AWS one is already synced that way).

## 2. Start of every session

1. `git fetch origin` and check out the branch named in the task. `staging-redesign` is the redesign
   branch; `claude/sweet-goldberg-xqoyfg` is what is live today. Never push to a different branch
   without being told to.
2. AWS: run the `aws-sso-login` skill. The user approves a device code in their browser. Then every aws
   command needs `export AWS_PROFILE=svc-ai-cowork-mcp` and `unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
   AWS_SESSION_TOKEN AWS_SECURITY_TOKEN`. The login expires within hours; re-run the skill when a command
   says the token expired.
3. GoDaddy, only if DNS work is planned: run the `godaddy-dns` skill. The browser login works on the
   user's Mac (Remote Control), not in a cloud session.
4. `npm ci` then `npm test`. All tests must pass before any deploy.

## 3. Inventory (us-east-1, account 306499034564)

| Thing | Value |
|---|---|
| Live site bucket | `techinpeace.com` (the scan page is uploaded as `scan.html`, landing pages keep their names) |
| Live CloudFront | `E3RMERE2MGB15`, aliases `techinpeace.com`, `www.techinpeace.com`, `mta-sts.techinpeace.com` |
| Live headers policy | `12c8e717-b20c-4470-a52b-aff9d4c29941` (`techinpeace-security-headers`) |
| Scanner stack | `cyber-protection-site-my`; Lambda `cyber-protection-site-my-ApiFunction-xyHDoIt3wYhM`; API `xerftm3br1` |
| Scan tables | `cyber-protection-site-my-ScansTable-P9F2Z89T7ZA8`, `cyber-protection-site-my-RateTable-RJDB0O2BJ4E` |
| Staging stack | `techinpeace-staging`; CloudFront `E3K692GH37MD8C`; `https://staging.techinpeace.com` |
| Email | SES, sender `Domain Scanner <scanner@techinpeace.com>`, MAIL FROM `mail.techinpeace.com` |
| DNS | GoDaddy (`ns77`, `ns78.domaincontrol.com`). Route 53 holds other domains, not techinpeace.com |
| Artifacts bucket | `cyber-protection-artifacts-306499034564-us-east-1` (Lambda zips) |

## 4. Deploys

**Staging** (no approval needed beyond the task itself): `bash deploy/staging.sh`. It uploads the pages
to the staging bucket and clears its cache. It refuses to touch the live bucket.

**Live pages** (ask first, back up first): copy each changed file from `public/` or `landing/` to
`s3://techinpeace.com/` with the same content type and `no-cache, must-revalidate`, then invalidate the
paths on `E3RMERE2MGB15`. Save the previous copies to the scratchpad before uploading.

**Scanner code** (ask first): package `server.js lambda.js src public package.json node_modules`
(production deps only), upload the zip to the artifacts bucket, then update the stack
`cyber-protection-site-my` through a change set with `--use-previous-template`, every parameter
`UsePreviousValue=true` except `LambdaCodeKey`. Preview the change set, confirm only `ApiFunction` and
`HttpApiIntegration` change, then execute. Never update the Lambda code directly, or the stack will roll
it back on the next update. Afterwards run one real scan through the Lambda to confirm.

**Never**: deploy to live without the user's explicit go-ahead for that deploy; stage secrets or
`scans.json`; change DNS without the `godaddy-dns` approval steps; use `pkill -f` with a pattern that
matches the calling shell.

## 5. Git rules

One-line imperative commit messages. Run `git commit` and `git push` as separate commands. Check
`git status` before every commit. Push to the branch the task names, with `git push -u origin <branch>`.
