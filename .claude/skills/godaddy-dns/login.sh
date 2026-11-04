#!/usr/bin/env bash
# GoDaddy gddy CLI helper: install if missing, sign in, report status.
#
#   login.sh status   install gddy if missing, then print LOGGED_IN or NOT_LOGGED_IN
#   login.sh start    run gddy's browser-based login (works on a machine with a browser)
#   login.sh install  install or update gddy with GoDaddy's official installer
#
# Nothing here reads, prints or stores a password or token. The official
# installer puts the binary in ~/.local/bin and does not touch shell files.
set -euo pipefail

export PATH="$HOME/.local/bin:$PATH"
ENV_NAME="${GDDY_ENV:-prod}"
INSTALLER="https://github.com/godaddy/cli/releases/latest/download/install.sh"

install_cli() {
  echo "Installing gddy with GoDaddy's official installer ..."
  curl -fsSL "$INSTALLER" | bash >/dev/null
  echo "Installed: $(gddy --version)"
}

ensure_cli() {
  command -v gddy >/dev/null 2>&1 || install_cli
}

status() {
  ensure_cli
  # Identity is masked: first character, then ***, then the domain part if it is an email.
  gddy auth status --json 2>/dev/null | python3 -c '
import json, sys
env = sys.argv[1]
try:
    rows = json.load(sys.stdin)["data"]
except Exception:
    print("NOT_LOGGED_IN"); sys.exit(1)
row = next((r for r in rows if r.get("env") == env), None)
if not row or row.get("expired", True):
    print("NOT_LOGGED_IN"); sys.exit(1)
ident = row.get("identity") or ""
if "@" in ident:
    user, dom = ident.split("@", 1)
    masked = user[:1] + "***@" + dom
else:
    masked = ident[:1] + "***" if ident else "(unknown)"
nscopes = len(row.get("scopes", []))
print("LOGGED_IN env=" + env + " identity=" + masked + " scopes=" + str(nscopes))
' "$ENV_NAME"
}

start() {
  ensure_cli
  echo "Starting GoDaddy sign-in for environment ${ENV_NAME}. A browser window opens; sign in there."
  echo "If no browser opens on this machine, the printed link only works from this same machine."
  gddy auth login --env "$ENV_NAME" --human
  status
}

case "${1:-status}" in
  status) status ;;
  start) start ;;
  install) install_cli ;;
  *) echo "usage: login.sh [status|start|install]" >&2; exit 2 ;;
esac
