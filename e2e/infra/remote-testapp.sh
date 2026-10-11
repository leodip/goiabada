#!/usr/bin/env bash
# Runs on the VPS. testapp.sh copies it, the test app's source (testapp.tar.gz) and its secrets
# (testapp.env) into a staging directory there, passes that directory as $1 and the settings in the
# environment (E2E_*), and removes the directory afterwards.
#
# Builds the test app's image, and runs it in the environment's Compose project twice: testapp1 for
# the first test app host on 127.0.0.1:9092, testapp2 for the second on 9093. Both read the auth server
# at its public address, as a deployed app would.
set -euo pipefail

stage="$1"
log()  { printf '    [vps] %s\n' "$*"; }
fail() { printf '    [vps] ERROR %s\n' "$*" >&2; exit 1; }

[[ -f "$E2E_REMOTE_DIR/docker-compose.yml" ]] || fail "no environment in $E2E_REMOTE_DIR: run e2e/reset.sh first"
cd "$E2E_REMOTE_DIR"

log "building $E2E_TESTAPP_IMAGE"
rm -rf testapp-src
mkdir testapp-src
tar -xzf "$stage/testapp.tar.gz" -C testapp-src
# The label marks the images this script built, so the one the new build replaces can be removed
# without touching anyone else's.
if ! docker build --label goiabada-e2e=testapp -t "$E2E_TESTAPP_IMAGE" testapp-src >testapp-build.log 2>&1; then
  tail -40 testapp-build.log >&2
  fail "the test app's image did not build"
fi
docker image prune -f --filter label=goiabada-e2e=testapp >/dev/null

install -m 600 "$stage/testapp.env" testapp.env
cat >testapp.yml <<EOF
services:
  testapp1:
    image: $E2E_TESTAPP_IMAGE
    pull_policy: never
    restart: unless-stopped
    env_file: testapp.env
    environment:
      GOIABADA_ISSUER: https://$E2E_AUTH_HOST
      APP_URL: https://$E2E_WEBTEST1_HOST
    ports:
      - "127.0.0.1:9092:3000"
  testapp2:
    image: $E2E_TESTAPP_IMAGE
    pull_policy: never
    restart: unless-stopped
    env_file: testapp.env
    environment:
      GOIABADA_ISSUER: https://$E2E_AUTH_HOST
      APP_URL: https://$E2E_WEBTEST2_HOST
    ports:
      - "127.0.0.1:9093:3000"
EOF
# Every docker compose command in this directory takes testapp.yml too from now on.
grep -q ':testapp.yml$' .env || sed -i 's/^COMPOSE_FILE=.*/&:testapp.yml/' .env

log "starting testapp1 and testapp2"
# Recreated whether or not Compose sees a change: the secrets may be new, and the image is.
docker compose up -d --force-recreate testapp1 testapp2 >testapp-up.log 2>&1 ||
  { cat testapp-up.log >&2; fail "docker compose up -d testapp1 testapp2 failed"; }

for port in 9092 9093; do
  for _ in $(seq 1 30); do
    curl -fsS -o /dev/null --max-time 5 "http://127.0.0.1:$port/" 2>/dev/null && break
    sleep 2
  done
  curl -fsS -o /dev/null --max-time 5 "http://127.0.0.1:$port/" 2>/dev/null || {
    docker compose logs --no-color --tail 50 testapp1 testapp2 >&2
    fail "the test app did not answer on 127.0.0.1:$port within a minute"
  }
done
log "the test app answers on 127.0.0.1:9092 and 9093"
