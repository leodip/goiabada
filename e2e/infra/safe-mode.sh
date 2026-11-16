#!/usr/bin/env bash
# Switch the auth server's brand safe mode in the e2e environment.
#
#   e2e/infra/safe-mode.sh off   # how the environment rests, and what the e2e suite runs against
#   e2e/infra/safe-mode.sh on    # for the system test of the switch, which switches it off again
#
# The switch is GOIABADA_AUTHSERVER_BRAND_SAFE_MODE, set in safemode.yml beside the wizard's Compose
# files, over the value the wizard wrote (none). The auth server reads it when it starts, so each
# command recreates its container when the value changes, ends once the auth server answers again,
# and fails unless the running container was started with the value asked for.
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

case "${1:-}" in
  on) want=true ;;
  off) want=false ;;
  -h | --help) sed -n '2,10s/^# \{0,1\}//p' "$0"; exit 0 ;;
  *) die "unknown command ${1:-(none)}; see e2e/infra/safe-mode.sh --help" ;;
esac

require_vps
running="$(ssh_vps "cd $(printf %q "$E2E_REMOTE_DIR") && want=$want bash -s" <<'REMOTE'
set -euo pipefail
service=goiabada-authserver
[[ -f .env ]] || { echo "no e2e Compose project here: build it with e2e/reset.sh" >&2; exit 1; }
# COMPOSE_FILE in .env makes every docker compose command run here take safemode.yml too.
grep -Eq '^COMPOSE_FILE=(.*:)?safemode\.yml(:|$)' .env || sed -i 's/^COMPOSE_FILE=.*/&:safemode.yml/' .env
printf 'services:\n  %s:\n    environment:\n      GOIABADA_AUTHSERVER_BRAND_SAFE_MODE: "%s"\n' "$service" "$want" >safemode.yml
# Recreates the container when the value changed, and leaves it running when it did not.
docker compose up -d --no-deps "$service" >safemode.log 2>&1 || { cat safemode.log >&2; exit 1; }
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
  sed -n 's/^GOIABADA_AUTHSERVER_BRAND_SAFE_MODE=//p'
REMOTE
)" || die "could not switch safe mode $1 on $E2E_VPS_HOST"

[[ "$running" == "$want" ]] || die "the auth server runs with GOIABADA_AUTHSERVER_BRAND_SAFE_MODE=${running:-unset}, not $want"
case "$want" in
  true) echo "The auth server's brand safe mode is on." ;;
  false) echo "The auth server's brand safe mode is off." ;;
esac
