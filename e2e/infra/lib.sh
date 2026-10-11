# shellcheck shell=bash disable=SC2034
# SC2034: sourced, so the variables it sets are used by the scripts that source it.
# Shared by prepare.sh, verify.sh and teardown.sh: the environment's settings and a few helpers.
# Sourced, never run.

E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_DIR="$E2E_DIR/.state"

# e2e/.env holds what differs per machine; anything already in the environment wins over it, so a
# CI job can set the same names as secrets.
if [[ -f "$E2E_DIR/.env" ]]; then
  while IFS='=' read -r key value; do
    [[ -z "$key" || "$key" == \#* ]] && continue
    [[ -z "${!key:-}" ]] && export "$key=$value"
  done < "$E2E_DIR/.env"
fi

E2E_VPS_HOST="${E2E_VPS_HOST:-}"
E2E_VPS_USER="${E2E_VPS_USER:-root}"
E2E_AUTH_HOST="${E2E_AUTH_HOST:-e2e-auth.goiabada.dev}"
E2E_ADMIN_HOST="${E2E_ADMIN_HOST:-e2e-admin.goiabada.dev}"
E2E_WEBTEST1_HOST="${E2E_WEBTEST1_HOST:-e2e-webtest1.goiabada.dev}"
E2E_WEBTEST2_HOST="${E2E_WEBTEST2_HOST:-e2e-webtest2.goiabada.dev}"
E2E_ADMIN_EMAIL="${E2E_ADMIN_EMAIL:-admin@goiabada.dev}"
E2E_DB="${E2E_DB:-postgres}"
E2E_RATE_LIMITER="${E2E_RATE_LIMITER:-true}"
# On the VPS: the Compose project's directory (and so its name), and the certificate's name.
E2E_REMOTE_DIR="${E2E_REMOTE_DIR:-/root/goiabada-e2e}"
E2E_CERT_NAME="${E2E_CERT_NAME:-e2e.goiabada.dev}"
# Mailpit catches the mail the auth server sends. Its web UI and API listen on the VPS's loopback only;
# e2e/test.sh reaches them through an SSH tunnel.
E2E_MAILPIT_IMAGE="${E2E_MAILPIT_IMAGE:-axllent/mailpit:v1.31.5}"
E2E_MAILPIT_PORT="${E2E_MAILPIT_PORT:-18025}"
# The test app (e2e/testapp), built on the VPS into this image and run twice, one container per test
# app host, on 127.0.0.1:9092 and 9093.
E2E_TESTAPP_IMAGE="${E2E_TESTAPP_IMAGE:-goiabada-e2e-testapp:local}"

E2E_ALL_HOSTS=("$E2E_AUTH_HOST" "$E2E_ADMIN_HOST" "$E2E_WEBTEST1_HOST" "$E2E_WEBTEST2_HOST")

SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=15)
# shellcheck disable=SC2029 # the remote command is built on this side on purpose
ssh_vps() { ssh "${SSH_OPTS[@]}" "$E2E_VPS_USER@$E2E_VPS_HOST" "$@"; }
scp_vps() { scp -q "${SSH_OPTS[@]}" "$@"; }

# The records a public resolver answers for a name, one per line, through Cloudflare's DNS over
# HTTPS so no local resolver or dig is needed.
dns_answers() { # host type
  curl -fsS --max-time 10 -H 'accept: application/dns-json' \
    "https://cloudflare-dns.com/dns-query?name=$1&type=$2" |
    python3 -c '
import json, sys
types = {"A": 1, "AAAA": 28}
for answer in json.load(sys.stdin).get("Answer", []):
    if answer["type"] == types[sys.argv[1]]:
        print(answer["data"])
' "$2"
}

if [[ -t 1 ]]; then BOLD=$'\e[1m'; RED=$'\e[31m'; GREEN=$'\e[32m'; YELLOW=$'\e[33m'; RESET=$'\e[0m'
else BOLD=; RED=; GREEN=; YELLOW=; RESET=; fi
step() { printf '\n%s==> %s%s\n' "$BOLD" "$*" "$RESET"; }
warn() { printf '%sWARN%s %s\n' "$YELLOW" "$RESET" "$*" >&2; }
die()  { printf '%sERROR%s %s\n' "$RED" "$RESET" "$*" >&2; exit 1; }

# The newest published release's tag, from GitHub's API.
latest_release_tag() {
  curl -fsS --max-time 15 https://api.github.com/repos/leodip/goiabada/releases/latest |
    python3 -c 'import json, sys; print(json.load(sys.stdin)["tag_name"])'
}

# The Playwright suite's packages and Chromium, installed the first time and when package-lock.json
# changes. Run from anywhere; leaves the working directory as it was.
ensure_suite_packages() {
  command -v npm >/dev/null || die "npm is not installed"
  local suite="$E2E_DIR/playwright"
  if [[ ! -d "$suite/node_modules" || "$suite/package-lock.json" -nt "$suite/node_modules/.package-lock.json" ]]; then
    step "Installing the suite's packages"
    (cd "$suite" && npm ci --no-fund --no-audit) || die "npm ci failed"
    (cd "$suite" && npx playwright install chromium) || die "could not install Chromium"
  fi
}

# The scripts that reach the VPS call this first; the test run does not need it.
require_vps() {
  [[ -n "$E2E_VPS_HOST" ]] || die "set E2E_VPS_HOST, the VPS address, in e2e/.env or the environment (see e2e/.env.example)"
}
