#!/usr/bin/env bash
# Run the rate-limits suite against the environment e2e/reset.sh built: the limits the auth server
# counts by a client's address, with its rate limiter switched on for the run and off again after.
#
#   e2e/test-rate-limits.sh              # every test, headless
#   e2e/test-rate-limits.sh --headed     # watch the browser (any Playwright argument passes through)
#
# Each test starts from a restarted auth server, so from whole budgets (lib/rate-limits.ts).
set -uo pipefail
# shellcheck source=infra/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/infra/lib.sh"

case "${1:-}" in
  -h | --help) sed -n '2,8s/^# \{0,1\}//p' "$0"; exit 0 ;;
esac

suite="$E2E_DIR/playwright"
state="$STATE_DIR/environment.env"

[[ -f "$state" && -f "$STATE_DIR/admin-password" ]] ||
  die "no environment prepared from this machine: run e2e/reset.sh first"
tag="$(sed -n 's/^E2E_TAG=//p' "$state")"
prepared="$(sed -n 's/^E2E_PREPARED_AT=//p' "$state")"
auth_url="$(sed -n 's/^E2E_AUTH_URL=//p' "$state")"

hold_suite_lock
ensure_suite_packages
cd "$suite" || die "no $suite"

npm run --silent typecheck || die "the suite has type errors (cd e2e/playwright && npm run typecheck)"

curl -fsS -o /dev/null --max-time 10 "$auth_url/health" ||
  die "$auth_url does not answer: check it with e2e/infra/verify.sh, or rebuild with e2e/reset.sh"

require_vps
turnstile_off
trap '"$E2E_DIR/infra/rate-limiter.sh" off || warn "the rate limiter may still be on: e2e/infra/rate-limiter.sh off"' EXIT
"$E2E_DIR/infra/rate-limiter.sh" on || exit 1

step "Running the rate-limits suite against $tag (prepared $prepared)"
started=$SECONDS
npx playwright test --config rate-limits.config.ts "$@"
status=$?

echo
if ((status == 0)); then
  printf '%sAll rate-limits tests passed%s against %s (%ds).\n' "$GREEN" "$RESET" "$tag" $((SECONDS - started))
else
  printf '%sRate-limits tests failed%s against %s (%ds). Traces and screenshots: (cd e2e/playwright && npx playwright show-report playwright-report-rate-limits)\n' \
    "$RED" "$RESET" "$tag" $((SECONDS - started))
fi
exit "$status"
