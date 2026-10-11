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

command -v npm >/dev/null || die "npm is not installed"
cd "$suite" || die "no $suite"
if [[ ! -d node_modules || package-lock.json -nt node_modules/.package-lock.json ]]; then
  step "Installing the suite's packages"
  npm ci --no-fund --no-audit || die "npm ci failed"
  npx playwright install chromium || die "could not install Chromium"
fi

curl -fsS -o /dev/null --max-time 10 "$auth_url/health" ||
  die "$auth_url does not answer: check it with e2e/infra/verify.sh, or rebuild with e2e/reset.sh"

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
