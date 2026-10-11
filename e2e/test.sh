#!/usr/bin/env bash
# Run the Playwright suite against the environment e2e/reset.sh built.
#
#   e2e/test.sh                          # every test, headless
#   e2e/test.sh --headed                 # watch the browser
#   e2e/test.sh --ui                     # Playwright's UI mode
#   e2e/test.sh tests/admin-console      # one area (any Playwright argument passes through)
#
# Installs the suite's packages and Chromium the first time, and when package-lock.json changes.
set -uo pipefail
# shellcheck source=infra/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/infra/lib.sh"

case "${1:-}" in
  -h | --help) sed -n '2,9s/^# \{0,1\}//p' "$0"; exit 0 ;;
esac

suite="$E2E_DIR/playwright"
state="$STATE_DIR/environment.env"

[[ -f "$state" && -f "$STATE_DIR/admin-password" ]] ||
  die "no environment prepared from this machine: run e2e/reset.sh first"
tag="$(sed -n 's/^E2E_TAG=//p' "$state")"
prepared="$(sed -n 's/^E2E_PREPARED_AT=//p' "$state")"
auth_url="$(sed -n 's/^E2E_AUTH_URL=//p' "$state")"

ensure_suite_packages
cd "$suite" || die "no $suite"

curl -fsS -o /dev/null --max-time 10 "$auth_url/health" ||
  die "$auth_url does not answer: check it with e2e/infra/verify.sh, or rebuild with e2e/reset.sh"

# Mailpit's API listens on the VPS's loopback only; the tests read the mail through this tunnel, on a
# free local port, closed when the run ends.
require_vps
tunnel_port="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
ssh "${SSH_OPTS[@]}" -o ExitOnForwardFailure=yes -N -L "127.0.0.1:$tunnel_port:127.0.0.1:$E2E_MAILPIT_PORT" \
  "$E2E_VPS_USER@$E2E_VPS_HOST" &
tunnel_pid=$!
trap 'kill "$tunnel_pid" 2>/dev/null' EXIT
for _ in $(seq 1 20); do
  curl -fsS -o /dev/null --max-time 2 "http://127.0.0.1:$tunnel_port/api/v1/info" && break
  sleep 0.5
done
curl -fsS -o /dev/null --max-time 2 "http://127.0.0.1:$tunnel_port/api/v1/info" ||
  die "Mailpit does not answer through the SSH tunnel: rebuild with e2e/reset.sh"
export E2E_MAILPIT_URL="http://127.0.0.1:$tunnel_port"

step "Running the suite against $tag (prepared $prepared)"
started=$SECONDS
npx playwright test "$@"
status=$?

echo
if ((status == 0)); then
  printf '%sAll tests passed%s against %s (%ds).\n' "$GREEN" "$RESET" "$tag" $((SECONDS - started))
else
  printf '%sTests failed%s against %s (%ds). Traces and screenshots: (cd e2e/playwright && npx playwright show-report)\n' \
    "$RED" "$RESET" "$tag" $((SECONDS - started))
fi
exit "$status"
