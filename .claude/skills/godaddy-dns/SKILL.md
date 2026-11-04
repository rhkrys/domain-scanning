---
name: godaddy-dns
description: Manage GoDaddy domains and DNS records through GoDaddy's official gddy CLI, with a sign-in step the user approves and an explicit approval before every change. Use when the user asks to view, add, change or remove DNS records at GoDaddy, list GoDaddy domains, or when a gddy command fails with an authentication error.
---

# GoDaddy DNS through the gddy CLI

GoDaddy's official CLI is `gddy` (https://developer.godaddy.com/en/docs/api-users/cli/set-up). This skill
wraps it with two rules: the user signs in themselves, and nothing in the account changes without the
user approving the exact change on screen first.

`login.sh` sits in this skill's folder. Below, `SKILL_DIR` means that folder.

## Setup and sign-in

1. **Check the CLI and the sign-in.** This installs `gddy` with GoDaddy's official installer if it is
   missing (to `~/.local/bin`, no shell files changed) and reports the sign-in state:
   ```bash
   bash SKILL_DIR/login.sh status
   ```
   It prints `LOGGED_IN env=prod identity=<masked>` or `NOT_LOGGED_IN`.

2. **Sign in, if needed.** Pick the path that fits the machine:
   - **On the user's own computer (Mac or Linux):** run `bash SKILL_DIR/login.sh start`. It runs
     `gddy auth login`, which opens the user's browser for GoDaddy's login and consent screen. The user
     signs in there. Never ask for their password.
   - **In a cloud session with no browser:** the browser flow cannot finish, because GoDaddy sends the
     browser back to `127.0.0.1` on the session machine. Use a Personal Access Token instead, kept out of
     the conversation: the user creates it at https://developer.godaddy.com/personal-access-token with
     the scopes `domains.domain:read` and `domains.dns:update`, stores it as the environment secret
     `GDDY_PAT` in the session's environment settings, then starts a new session. `login.sh status` then
     reports the token's state. Never ask the user to paste the token into chat.

3. **Confirm the account and environment** before any command that reads or changes records:
   ```bash
   bash SKILL_DIR/login.sh status
   ```
   The environment must be `prod` for real domains. `ote` is GoDaddy's test environment.

## Reading (no approval needed)

```bash
gddy domain list --json
gddy dns list <DOMAIN> --json
gddy dns list <DOMAIN> --type TXT --name _dmarc --json
```

## Changing records (approval required every time)

Treat domain names and record values as exact identifiers. If a target is ambiguous, ask.

1. **Inspect first.** Run `gddy dns list <DOMAIN> --type <TYPE> --name <NAME> --json` and show the user
   the records that exist now.
2. **Explain replacement.** `gddy dns set` replaces every record with that type and name. `gddy dns delete`
   removes every record with that type and name. `gddy dns add` appends one record and leaves the rest.
   Say which one applies and why.
3. **Dry run.** Run the exact command with `--dry-run` and show its output.
4. **Show the plan,** in one block: domain, operation, the records affected, the values before, the values
   after, and any cost or renewal commitment (none for DNS changes).
5. **Ask for approval** of that exact plan. Approval covers only the values shown. If anything changes,
   show the plan again and ask again.
6. **Apply,** then run `gddy dns list` for the same type and name and show the before-and-after.

`NS` and `SOA` records are GoDaddy-managed and read-only. Nameserver changes, purchases, registrations,
renewals and transfers each need their own explicit approval, and GoDaddy may open a consent screen in the
browser for them.

## Never

- Print, log or commit tokens, passwords or recovery codes. `gddy auth status` masks the identity in this
  skill's output; keep it that way.
- Improvise around a failed or unsupported command. Explain the error and stop.
- Use an unofficial MCP server or a guessed command. The CLI documents itself: `gddy --help`,
  `gddy search <keywords>`, `gddy tree`, `gddy guide`.

## Related

- GoDaddy's own agent skill is installed as the Claude Code plugin `gddy@godaddy`
  (https://developer.godaddy.com/en/docs/api-users/cli/agent-skill). It covers purchases, hosting and
  email too. This skill is the stricter wrapper for DNS work.
- Scanner results for a domain (SPF, DKIM, DMARC) come from `POST /api/v1/scan` in this repo; use them
  to decide which records to propose.
