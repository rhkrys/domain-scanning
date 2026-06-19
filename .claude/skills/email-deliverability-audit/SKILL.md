---
name: email-deliverability-audit
description: Audit a domain's email authentication (SPF, DKIM, DMARC) and produce a plain-English report for non-technical users, flagging misconfigurations by severity (Critical/High/Medium/Low) plus prioritized recommendations. Use when the user wants to check why their emails go to spam, wants a domain's "email deliverability", "email security", or "DMARC/SPF/DKIM" audited, or asks to verify their email setup is trustworthy to mail providers like Gmail/Outlook.
---

# Email Deliverability Audit

Audit a domain's email authentication setup and explain the results to someone
with no DNS/email background. The audience cares about one thing: "will my
emails land in the inbox, or in spam?" Translate every technical finding into
that frame.

## Step 1 — Identify the domain

Take the domain from the user's message (a bare domain, an email address, or
a URL — extract the registrable domain, e.g. `mail@corp.example.com` ->
`example.com`). If no domain is present anywhere in context, ask the user for
one before doing anything else.

## Step 2 — Pull the DNS records

Run the bundled resolver (no `dig`/`nslookup`/extra packages required):

```
python3 .claude/skills/email-deliverability-audit/scripts/dns_lookup.py <domain>
```

This returns JSON with `spf_records`, `dmarc_records`, `mx_records`, and
`dkim_records_found` (a best-effort probe across ~25 common selectors used by
Google Workspace, Microsoft 365, Mailgun, SendGrid, Mailchimp/Mandrill, Zoho,
ProtonMail, Amazon SES, etc.).

DKIM selectors are sender-chosen and not discoverable from the apex domain
alone, so if `dkim_records_found` is empty, **do not report "DKIM missing"
as a hard fact**. Instead:
- If the user can tell you their email provider (Google Workspace, M365,
  SendGrid, etc.) or share a selector, re-run with
  `--selectors <name1,name2>` and look it up directly.
- Otherwise, report DKIM as "Not detected via common selectors — verify with
  your mail provider" rather than "Missing," and treat it as Medium severity
  rather than Critical, since the absence is unconfirmed.

If a record type query errors out (e.g. `spf_error` present), retry once; if
it still fails, report that check as "Unable to verify" rather than guessing.

## Step 3 — Analyze each record

### SPF (from `spf_records`, the one starting with `v=spf1`)
- **Missing entirely** → Critical. Anyone can spoof the domain; mailbox
  providers have no way to verify the sender.
- **Multiple `v=spf1` TXT records on the apex** → Critical (RFC 7208 says
  this makes SPF permanently fail evaluation).
- **`+all` or no terminal mechanism** → Critical (explicitly allows anyone
  to send as this domain).
- **`?all` (neutral)** → High (no enforcement at all).
- **More than 10 DNS-lookup mechanisms** (`include`, `a`, `mx`, `ptr`,
  `exists` each cost one lookup, recursively through nested includes) →
  High. This breaks SPF outright per spec (PermError) and receiving servers
  will treat it as a fail.
- **`ptr` mechanism used** → Low (deprecated, slow, unreliable — recommend
  removal).
- **`~all` (softfail)** → fine as a baseline; note `-all` (hardfail) is
  stricter and preferable once the user is confident all legitimate senders
  are listed.
- Syntax errors (unknown mechanisms, malformed IP4/IP6 CIDRs) → High.

### DMARC (from `dmarc_records`, the `_dmarc.<domain>` TXT)
- **Missing entirely** → Critical. SPF/DKIM may pass individually but
  nothing tells receivers to act on misalignment, and the domain gets zero
  visibility into spoofing attempts.
- **`p=none`** → Medium. Monitoring-only; spoofed mail isn't blocked. Fine
  as a temporary rollout stage, not as an end state.
- **`p=quarantine` or `p=reject` with no `rua=`** → Medium. The domain
  owner gets no reports, so they're flying blind on who's sending mail as
  them and can't tune the policy safely.
- **No `sp=` while subdomains are in use / `pct=` < 100 long-term** →
  Low–Medium depending on context.
- **Weak alignment (`aspf=r`/`adkim=r` relaxed) combined with `p=none`** →
  Medium; relaxed alignment alone is not a problem, but stacking it with no
  enforcement and no reports is.
- Malformed tags / syntax errors → High.

### DKIM (from `dkim_records_found`)
- **No selector found anywhere and provider unknown** → Medium, flagged as
  unconfirmed (see Step 2 caveat) rather than Critical.
- **Selector found but key looks short** (decode the `p=` base64 value;
  roughly <128 bytes decoded ≈ 1024-bit RSA) → Medium — recommend rotating
  to 2048-bit.
- **`p=` empty** → High — this is a revoked/broken key still published,
  which can cause hard DKIM failures.
- **Test mode flag `t=y` left on in production** → Low — informational,
  should be removed once verified working.

## Step 4 — Write the report

Use this structure. Keep language plain — no jargon without a one-line
explanation in parentheses the first time a term appears.

```markdown
# Email Authentication Report for <domain>

**Bottom line:** <one sentence — e.g. "Your emails are likely landing in
spam because there's no DMARC record, so mailbox providers can't confirm
mail claiming to be from you is legitimate.">

## Findings

| # | Issue | Severity | What it means |
|---|-------|----------|----------------|
| 1 | ... | Critical | ... |
| 2 | ... | High | ... |

(omit the table / say "No significant issues found" if everything's clean —
see Step 5)

## Recommendations (in priority order)

1. ...
2. ...
(5-8 items, each tied to impact: "this stops spoofed emails," "this gets
your reports flowing so you can see who's sending mail as you," etc.)
```

Order findings by severity (Critical first). Order recommendations by
impact, not by how easy they are — the highest-impact fix goes first even if
it requires asking IT/a vendor for help.

## Step 5 — Clean bill of health

If SPF has a valid terminal mechanism (`~all`/`-all`) with a sane lookup
count, DMARC is present with `p=quarantine` or `p=reject` and an `rua=`
reporting address, and at least one DKIM selector resolves with a
reasonably sized key — say so plainly: state the domain's email
authentication is well-configured, and list only minor polish items (e.g.
"move from `~all` to `-all` once you're confident," "consider adding
`ruf=` for forensic reports," "rotate DKIM keys yearly") rather than
manufacturing severity to pad the report.
