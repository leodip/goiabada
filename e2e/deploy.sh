#!/usr/bin/env bash
# Build the e2e environment to try Goiabada by hand, and say how to reach it. No test runs.
#
#   e2e/deploy.sh             # the latest GitHub release
#   e2e/deploy.sh vX.Y.Z      # a given tag, a release after v1.7.0
#   e2e/deploy.sh --source    # this checkout's src/, built on the VPS
#   e2e/deploy.sh --show      # how to reach the environment this machine last built, building nothing
#
# Building replaces the environment, as e2e/reset.sh does, so it refuses to start while a run of the
# e2e or the rate-limits suite holds e2e/.state/suite.lock. It ends with the addresses of the auth
# server, the admin console and the test app, and the administrator's email and password.
set -euo pipefail
# shellcheck source=infra/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/infra/lib.sh"

show_only=false
tag=""
case "${1:-}" in
  -h | --help) sed -n '2,11s/^# \{0,1\}//p' "$0"; exit 0 ;;
  --show) show_only=true ;;
  v[0-9]* | --source) tag="$1" ;;
  "") ;;
  *) die "unknown argument $1; see e2e/deploy.sh --help" ;;
esac

if [[ "$show_only" == false ]]; then
  require_vps
  hold_suite_lock
  if [[ -z "$tag" ]]; then
    tag="$(latest_release_tag)" || die "could not read the latest release from GitHub; pass the tag of a release after v1.7.0"
    echo "No tag given: using the latest release, ${BOLD}$tag${RESET}."
  fi
  started=$SECONDS
  "$E2E_DIR/infra/prepare.sh" "$tag"
  printf '\n%sBuilt in %ds.%s\n' "$GREEN" $((SECONDS - started)) "$RESET"
fi

state="$STATE_DIR/environment.env"
[[ -f "$state" && -f "$STATE_DIR/admin-password" ]] ||
  die "no environment built from this machine: run e2e/deploy.sh first"
setting() { sed -n "s/^$1=//p" "$state"; }

step "The environment runs $(setting E2E_TAG), built $(setting E2E_PREPARED_AT)"
cat <<EOF

  Auth server     $(setting E2E_AUTH_URL)
  Admin console   $(setting E2E_ADMIN_URL)
  Test app        $(setting E2E_WEBTEST1_URL)/   (a page per guide: web apps, SPAs, a service, an API)
                  $(setting E2E_WEBTEST2_URL)/web2   (the second web app, for single sign-on across sites)

  Administrator   $(setting E2E_ADMIN_EMAIL)
  Password        $(cat "$STATE_DIR/admin-password")

  Mail            ssh -o ServerAliveInterval=15 -N -L 8025:127.0.0.1:$E2E_MAILPIT_PORT $E2E_VPS_USER@${E2E_VPS_HOST:-<the VPS>}
                  then open http://localhost:8025: Mailpit holds every email the auth server sends.

  The environment rests with the rate limiter and the Turnstile challenge off. To call the test app's
  API as a user, give them product-api:read on their Permissions tab in the admin console.
EOF
