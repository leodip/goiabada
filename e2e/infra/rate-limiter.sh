#!/usr/bin/env bash
# Switch the auth server's rate limiter in the e2e environment, or start the auth server afresh.
#
#   e2e/infra/rate-limiter.sh off     # how the environment rests, and what the e2e suite runs against
#   e2e/infra/rate-limiter.sh on      # for the rate-limits suite, which switches it off again after
#   e2e/infra/rate-limiter.sh reset   # restart the auth server, the limiter on, so every count is zero
#
# The switch is GOIABADA_AUTHSERVER_RATELIMITER_ENABLED, set in ratelimiter.yml beside the wizard's
# Compose files, over the value the wizard wrote. The limits counted by an address live in the auth
# server's memory, so a restart empties them. Each command ends once the auth server answers again,
# and fails unless the running container was started with the value asked for.
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

case "${1:-}" in
  on) want=true ;;
  off) want=false ;;
  reset) want=true ;;
  -h | --help) sed -n '2,11s/^# \{0,1\}//p' "$0"; exit 0 ;;
  *) die "unknown command ${1:-(none)}; see e2e/infra/rate-limiter.sh --help" ;;
esac
action="$1"

require_vps
running="$(ssh_vps "cd $(printf %q "$E2E_REMOTE_DIR") && action=$action want=$want bash -s" <<'REMOTE'
set -euo pipefail
service=goiabada-authserver
[[ -f .env ]] || { echo "no e2e Compose project here: build it with e2e/reset.sh" >&2; exit 1; }
# COMPOSE_FILE in .env makes every docker compose command run here take ratelimiter.yml too.
grep -Eq '^COMPOSE_FILE=(.*:)?ratelimiter\.yml(:|$)' .env || sed -i 's/^COMPOSE_FILE=.*/&:ratelimiter.yml/' .env
if [[ "$action" == reset ]]; then
  docker compose restart "$service" >ratelimiter.log 2>&1 || { cat ratelimiter.log >&2; exit 1; }
else
  printf 'services:\n  %s:\n    environment:\n      GOIABADA_AUTHSERVER_RATELIMITER_ENABLED: "%s"\n' "$service" "$want" >ratelimiter.yml
  # Recreates the container when the value changed, and leaves it running when it did not.
  docker compose up -d --no-deps "$service" >ratelimiter.log 2>&1 || { cat ratelimiter.log >&2; exit 1; }
fi
for _ in $(seq 1 120); do
  curl -fsS -o /dev/null --max-time 2 http://127.0.0.1:9090/health 2>/dev/null && break
  sleep 0.5
done
curl -fsS -o /dev/null --max-time 2 http://127.0.0.1:9090/health 2>/dev/null || {
  docker compose logs --no-color --tail 30 "$service" >&2
  echo "the auth server did not answer within a minute" >&2
  exit 1
}
docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$(docker compose ps -q "$service")" |
  sed -n 's/^GOIABADA_AUTHSERVER_RATELIMITER_ENABLED=//p'
REMOTE
)" || die "could not $action the rate limiter on $E2E_VPS_HOST"

if [[ "$running" != "$want" ]]; then
  [[ "$action" == reset ]] && die "the auth server runs with the rate limiter ${running:-unset}, not on: run the rate-limits suite with e2e/test-rate-limits.sh"
  die "the auth server runs with GOIABADA_AUTHSERVER_RATELIMITER_ENABLED=${running:-unset}, not $want"
fi
case "$action" in
  on) echo "The auth server's rate limiter is on." ;;
  off) echo "The auth server's rate limiter is off." ;;
  reset) echo "The auth server restarted, its rate limiter's counts empty." ;;
esac
