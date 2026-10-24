#!/usr/bin/env bash
# placido's last gate for Goiabada: rebuild the e2e environment on the VPS from this
# worktree's src/, then run the e2e suite against it (e2e/run.sh --source). The
# rate-limits suite is not part of it: it runs by hand, before a release.
#
#   .placido/e2e.sh                  # the whole e2e suite
#   .placido/e2e.sh tests/oauth      # one area; any Playwright argument passes through
#
# There is one environment, so a lock keeps two placido runs from rebuilding it at
# once. The machine's settings (e2e/.env) come from the main checkout, and what the
# run leaves in e2e/.state (the URLs, the admin password) goes back to it, so
# e2e/test.sh there runs against the environment this run built.
set -uo pipefail

case "${1:-}" in
  -h | --help) sed -n '2,12s/^# \{0,1\}//p' "$0"; exit 0 ;;
esac

worktree="$(git rev-parse --show-toplevel)" || exit 1
main="$(dirname "$(git rev-parse --path-format=absolute --git-common-dir)")" || exit 1

[[ -f "$main/e2e/.env" ]] || { echo "no $main/e2e/.env: copy e2e/.env.example there and set E2E_VPS_HOST" >&2; exit 1; }
if [[ "$main" != "$worktree" ]]; then
  cp "$main/e2e/.env" "$worktree/e2e/.env"
fi

mkdir -p "$main/e2e/.state"
exec 9>"$main/e2e/.state/placido.lock"
if ! flock -n 9; then
  echo "Another run is using the e2e environment; waiting for it."
  flock 9
fi

"$worktree/e2e/run.sh" --source "$@"
status=$?

if [[ "$main" != "$worktree" && -d "$worktree/e2e/.state" ]]; then
  cp -a "$worktree/e2e/.state/." "$main/e2e/.state/"
fi
exit "$status"
