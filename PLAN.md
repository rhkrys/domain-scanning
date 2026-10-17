# Domain Security Scanner — Plan & Architecture

A web-app that collects a domain (and an optional email), runs an automated
security audit, shows an instant graded summary, and emails the user a
plain-English list of next steps. Modelled on the BlackVeil scanner
(`blackveil.co.nz/scanner`): enter a domain → ~12 checks → one score → clear
fixes, in plain language.

## 1. What we reviewed (the reference)

BlackVeil's free scanner takes a domain and runs a set of DNS, email-auth, TLS
and infrastructure checks (SPF, DKIM, DMARC, MTA-STS, BIMI, DNSSEC, SSL,
security headers, MX/A/NS records), returns a single grade in ~60 seconds, and
explains issues in plain English with next steps. Our build reproduces that
core flow as a self-contained, deployable app.

## 2. User flow (the website that collects domain info and emails the user)

1. User lands on a single page and enters a **domain** (required) and their
   **email** (optional, to receive next steps).
2. The browser POSTs to `/api/scan`.
3. The server validates input, runs the audit, computes a score + letter grade,
   and — if an email was given — sends the report.
4. The page renders the grade, the prioritised next steps, and the full check
   list immediately. The email arrives with the same summary and to-do list.

```
Browser (public/)                Server (Express)              Audit engine (src/)
─────────────────                ───────────────               ──────────────────
form: domain + email   ── POST ▶ /api/scan
                                 ├─ validate + rate-limit
                                 ├─ runAudit(domain) ────────▶  resolver + 12 checks
                                 │                              └─ scoreFindings()
                                 ├─ sendReport(email, report) ─▶ render + SMTP/preview
        summary  ◀── JSON ───────┘
```

## 3. Checks performed

| Category              | Checks |
|-----------------------|--------|
| DNS Foundation        | A/AAAA addressing, MX (incl. RFC 7505 null MX), nameserver diversity, DNSSEC, CAA |
| Email Authentication  | SPF (syntax, policy, 10-lookup limit), DMARC (policy strength + reporting), DKIM (common-selector probe), MTA-STS, BIMI |
| Transport Security    | TLS certificate (validity, expiry window, protocol), HTTP security headers (HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy) |

Each check returns a normalised **finding**: `{ id, category, title, status
(pass/warn/fail/info), severity (critical→info), summary, detail,
recommendation }`. Severity tunes the score; the recommendation is the plain
English "next step" surfaced to the user.

## 4. Scoring

Start at 100, subtract a severity-weighted penalty for each non-passing finding
(failures cost full weight, warnings half, info nothing), clamp to 0–100, then
map to a letter grade A–F. Findings that need action are sorted worst-first into
the "next steps" list. See `src/scoring.js`.

## 5. Architecture

```
server.js              Express app: static page + POST /api/scan + /healthz
src/
  resolver.js          DNS-over-HTTPS client (Cloudflare/Google) w/ native fallback
  audit.js             Orchestrates all checks, builds the scored report
  scoring.js           Pure score + grade + prioritised next steps
  checks/
    records.js         A/AAAA, MX, nameservers, CAA
    email.js           SPF, DMARC, DKIM, MTA-STS, BIMI
    dnssec.js          DNSSEC presence
    tls.js             Certificate validity / expiry / protocol
    headers.js         HTTP security headers
  email/
    render.js          Pure HTML + text email rendering
    mailer.js          Nodemailer SMTP, with on-disk preview fallback
public/                index.html + styles.css + app.js (no build step)
test/                  node:test unit + integration tests (no network needed)
```

**Design principle:** the network layer (DNS, TLS, HTTP fetch) is separated from
pure interpretation/scoring/rendering, so all logic is unit-tested offline with
a scripted `FakeResolver` and fixture certs/headers.

## 6. Email delivery

`src/email/mailer.js` sends via SMTP when `SMTP_HOST/USER/PASS` are set
(SendGrid, Mailgun, SES, Postmark, Gmail app password, …). Without credentials
it writes an HTML preview to `./previews/` so the app is fully usable in
development. The email contains the grade, pass/review/action counts, the
prioritised next steps, and the full check list.

## 7. Deployment notes & network requirements

- The audit needs outbound DNS. Preferred path is **DNS-over-HTTPS** to
  `cloudflare-dns.com` / `dns.google` (port 443); a native resolver (UDP/TCP 53)
  is used as a fallback. The host environment's egress policy must allow at
  least one of these, plus port 443 for the TLS/headers checks.
- Any check that cannot reach the network degrades to a low-severity "could not
  be completed" warning rather than failing the whole scan.
- Configure SMTP via environment variables (see `.env.example`).
- `/healthz` is provided for load-balancer health checks.

## 8. Possible next iterations

- Persist scan history per domain and show trend/improvement over time.
- Scheduled re-scans with change alerts (the monitoring tier the reference sells).
- PDF export of the report; shareable result links.
- Deeper checks: full SPF include expansion, DMARC alignment simulation,
  certificate chain/OCSP, open-port and subdomain enumeration.
- CAPTCHA / stronger abuse controls before exposing publicly.
