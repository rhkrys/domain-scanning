#!/usr/bin/env bash
# AWS SSO device-code login helper for Claude sessions.
#
#   login.sh start    Install the CLI if needed, write the profile, begin a login,
#                     and print the URL + one-time code for the user to approve.
#   login.sh wait     Block (up to ~3 min) until the user has approved; exit 0 when logged in.
#   login.sh status   Print the account ID if the session is valid, else exit 1.
#
# Nothing secret is stored here: only the SSO start URL / account / role names.
# Override any of them with the environment variables below.
set -u

PROFILE="${AWS_SSO_PROFILE:-svc-ai-cowork-mcp}"
SESSION="${AWS_SSO_SESSION:-cowork}"
START_URL="${AWS_SSO_START_URL:-https://d-9067c5e47a.awsapps.com/start}"
ACCOUNT_ID="${AWS_SSO_ACCOUNT_ID:-306499034564}"
ROLE_NAME="${AWS_SSO_ROLE_NAME:-PowerUserAccess}"
REGION="${AWS_SSO_REGION:-us-east-1}"
OUT="${TMPDIR:-/tmp}/aws-sso-login.out"
AWS="$HOME/.local/bin/aws"

# The sandbox injects placeholder AWS_* credentials that override the SSO profile
# and cause "InvalidClientTokenId". Always run the CLI without them.
awsx() { env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN -u AWS_SECURITY_TOKEN \
           AWS_PROFILE="$PROFILE" "$AWS" "$@"; }

ensure_cli() {
  if [ -x "$AWS" ]; then return 0; fi
  if command -v aws >/dev/null 2>&1; then AWS="$(command -v aws)"; return 0; fi
  echo "Installing AWS CLI v2 into ~/.local ..." >&2
  local tmp; tmp="$(mktemp -d)"
  ( cd "$tmp" \
    && curl -sSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o awscliv2.zip \
    && unzip -q awscliv2.zip \
    && ./aws/install --bin-dir "$HOME/.local/bin" --install-dir "$HOME/.local/aws-cli" --update ) >&2 \
    || { echo "AWS CLI install failed" >&2; exit 2; }
  rm -rf "$tmp"
  AWS="$HOME/.local/bin/aws"
}

ensure_config() {
  mkdir -p "$HOME/.aws"; touch "$HOME/.aws/config"
  if ! grep -q "^\[sso-session $SESSION\]" "$HOME/.aws/config"; then
    cat >> "$HOME/.aws/config" <<EOF

[sso-session $SESSION]
sso_start_url = $START_URL
sso_region = $REGION
sso_registration_scopes = sso:account:access
EOF
  fi
  if ! grep -q "^\[profile $PROFILE\]" "$HOME/.aws/config"; then
    cat >> "$HOME/.aws/config" <<EOF

[profile $PROFILE]
sso_session = $SESSION
sso_account_id = $ACCOUNT_ID
sso_role_name = $ROLE_NAME
region = $REGION
output = json
EOF
  fi
}

identity() { awsx sts get-caller-identity --query Account --output text 2>/dev/null; }

# Prints the code line that follows "enter the code:" in the CLI output.
parse_code() { awk '/enter the code/ {f=1; next} f && NF {print; exit}' "$1" 2>/dev/null; }

cmd_start() {
  ensure_cli; ensure_config
  if id="$(identity)" && [[ "$id" =~ ^[0-9]+$ ]]; then
    echo "ALREADY_LOGGED_IN account=$id profile=$PROFILE"; return 0
  fi
  rm -f "$OUT"
  # Detached, so it keeps polling while the user approves. Never pkill -f "sso login":
  # that pattern matches the calling shell and kills it.
  setsid env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN -u AWS_SECURITY_TOKEN \
    "$AWS" sso login --sso-session "$SESSION" --use-device-code > "$OUT" 2>&1 < /dev/null &
  disown 2>/dev/null || true
  local code="" i
  for i in $(seq 1 30); do
    code="$(parse_code "$OUT")"; [ -n "$code" ] && break; sleep 1
  done
  [ -n "$code" ] || { echo "No code produced. Output:" >&2; cat "$OUT" >&2; exit 3; }
  echo "URL:  https://d-9067c5e47a.awsapps.com/start/#/device"
  echo "CODE: $code"
  echo "Give the user the URL and code NOW (codes expire in a few minutes), then run: login.sh wait"
}

cmd_wait() {
  local i id
  for i in $(seq 1 36); do   # 36 x 5s = 3 min
    if id="$(identity)" && [[ "$id" =~ ^[0-9]+$ ]]; then
      echo "LOGGED_IN account=$id profile=$PROFILE"; return 0
    fi
    sleep 5
  done
  echo "NOT_LOGGED_IN (code likely expired or not approved). Run: login.sh start" >&2
  return 1
}

cmd_status() {
  ensure_cli
  local id
  if id="$(identity)" && [[ "$id" =~ ^[0-9]+$ ]]; then
    echo "$id"; return 0
  fi
  echo "NOT_LOGGED_IN" >&2; return 1
}

case "${1:-}" in
  start)  cmd_start ;;
  wait)   cmd_wait ;;
  status) cmd_status ;;
  parse-code) parse_code "${2:?file}" ;;   # used for testing
  *) echo "usage: login.sh {start|wait|status}" >&2; exit 64 ;;
esac
