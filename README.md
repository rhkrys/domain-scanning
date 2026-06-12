# Domain Security Scanner

A small web-app that audits a domain's security posture, shows an instant graded
summary, and emails the user a plain-English list of next steps. Inspired by the
[BlackVeil scanner](https://blackveil.co.nz/scanner): enter a domain, get one
score and clear fixes.

It runs **12 checks** across three areas:

- **DNS foundation** — A/AAAA, MX (incl. RFC 7505 null MX), nameserver diversity, DNSSEC, CAA
- **Email authentication** — SPF, DMARC, DKIM, MTA-STS, BIMI
- **Transport security** — TLS certificate validity/expiry, HTTP security headers

Each result is scored, rolled up into a letter grade (A–F), and turned into a
prioritised to-do list shown on the page and emailed to the user.

## Quick start

```bash
npm install
npm start
# open http://localhost:3000
```

Enter a domain (e.g. `example.com`) and, optionally, your email to receive the
report.

## Email delivery

Set SMTP credentials to send real email; otherwise the app writes an HTML
preview of each email to `./previews/` so it works with zero configuration.

```bash
cp .env.example .env   # then fill in SMTP_* and MAIL_FROM
```

Works with SendGrid, Mailgun, Amazon SES, Postmark, or a Gmail app password.

## Tests

```bash
npm test
```

The audit logic, scoring, checks, and email rendering are fully unit-tested
offline with a scripted resolver — no network required.

## How it works

`POST /api/scan` with `{ "domain": "...", "email": "..." }` validates the input,
runs the audit (`src/audit.js`), scores it (`src/scoring.js`), emails the report
if an address was given (`src/email/mailer.js`), and returns the full report as
JSON. The frontend (`public/`) renders the summary instantly.

DNS lookups use DNS-over-HTTPS (Cloudflare/Google) with a native-resolver
fallback. See [`PLAN.md`](./PLAN.md) for the full architecture, the check list,
the scoring model, and deployment/network requirements.

## Disclaimer

This automated scan is a starting point, not a full security audit.
