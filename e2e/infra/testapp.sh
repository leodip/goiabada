#!/usr/bin/env bash
# Sets up the test app (e2e/testapp) in the e2e environment: its clients and API in Goiabada, then the
# app itself on the two test app hosts. prepare.sh runs it; run it on its own after changing the app.
#
#   e2e/infra/testapp.sh                 # set up the clients again (new secrets), build and deploy
#   e2e/infra/testapp.sh --deploy-only   # build and deploy with the clients already set up
#
# The clients are set up through the admin console, by the Playwright script in
# playwright/provision/, the way the guides tell a person to. It removes the test app's clients and
# the product-api resource first, so they always end up as the guides say, and leaves their secrets in
# e2e/.state/testapp.env, which goes to the VPS and nowhere else.
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
require_vps

provision=true
case "${1:-}" in
  "") ;;
  --deploy-only) provision=false ;;
  -h | --help) sed -n '2,11s/^# \{0,1\}//p' "$0"; exit 0 ;;
  *) die "usage: $0 [--deploy-only]" ;;
esac

[[ -f "$STATE_DIR/environment.env" && -f "$STATE_DIR/admin-password" ]] ||
  die "no environment prepared from this machine: run e2e/reset.sh first"
secrets="$STATE_DIR/testapp.env"

if [[ "$provision" == true ]]; then
  step "Setting up the test app's clients and API"
  ensure_suite_packages
  rm -f "$secrets"
  (cd "$E2E_DIR/playwright" && npx playwright test --config provision.config.ts) ||
    die "setting up the test app's clients failed: (cd e2e/playwright && npx playwright show-report)"
fi
[[ -f "$secrets" ]] || die "no e2e/.state/testapp.env: run $0 without --deploy-only"

step "Deploying the test app"
stage="$(ssh_vps 'mktemp -d /tmp/goiabada-e2e-testapp.XXXXXX')"
archive="$(mktemp)"
trap 'rm -f "$archive"' EXIT
# The source only: no dependencies, build output or local configuration.
tar -C "$E2E_DIR/testapp" --exclude=./node_modules --exclude=./.next --exclude='./.env*' -czf "$archive" .
scp_vps "$E2E_DIR/infra/remote-testapp.sh" "$secrets" "$E2E_VPS_USER@$E2E_VPS_HOST:$stage/"
scp_vps "$archive" "$E2E_VPS_USER@$E2E_VPS_HOST:$stage/testapp.tar.gz"
settings=""
for name in E2E_AUTH_HOST E2E_WEBTEST1_HOST E2E_WEBTEST2_HOST E2E_REMOTE_DIR E2E_TESTAPP_IMAGE; do
  settings+=" $name=$(printf %q "${!name}")"
done
ssh_vps "env $settings bash $stage/remote-testapp.sh $stage; status=\$?; rm -rf $stage; exit \$status" ||
  die "deploying the test app failed"

echo "the test app runs on https://$E2E_WEBTEST1_HOST and https://$E2E_WEBTEST2_HOST"
