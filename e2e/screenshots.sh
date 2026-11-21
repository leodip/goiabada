#!/usr/bin/env bash
# Retakes the screenshots the docs home page and the README show, from this checkout, and writes them
# over site/src/assets. Run it from the repository root on a machine with Docker; it needs no VPS,
# no dev container and no Node.js.
#
#   e2e/screenshots.sh
#
# It builds both servers from the release Dockerfiles, starts them on a new database beside Mailpit
# and the browser of Playwright's image, captures the images listed in
# e2e/playwright/screenshots/images.json, and removes everything it started. The committed images
# are replaced only once the capture and that removal have both succeeded; a run that fails leaves
# them as they were and says which step failed.
set -euo pipefail

case "${1:-}" in
  -h | --help) sed -n '2,12s/^# \{0,1\}//p' "$0"; exit 0 ;;
  "") ;;
  *) echo "screenshots: unknown argument: $1 (see --help)" >&2; exit 2 ;;
esac

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
assets="$root/site/src/assets"
list="$root/e2e/playwright/screenshots/images.json"

# A project name of this checkout's own, so two checkouts can run the command at once.
project="goiabada-screenshots-$(printf '%s' "$root" | cksum | cut -d ' ' -f 1)"
capture="$project-capture"
compose=(docker compose --project-name "$project" --file "$root/e2e/screenshots.yml")

# The Playwright the e2e suite pins, whose image the browser runs in.
SCREENSHOTS_PLAYWRIGHT_VERSION="$(sed -n 's/^ *"@playwright\/test": *"\([^"]*\)".*/\1/p' "$root/e2e/playwright/package.json")"
[ -n "$SCREENSHOTS_PLAYWRIGHT_VERSION" ] || { echo "screenshots: e2e/playwright/package.json pins no @playwright/test" >&2; exit 1; }

# The images to write, one file name to a line.
images=()
while IFS= read -r name; do images+=("$name"); done < <(sed -n 's/^ *"\([^"]*\)",\{0,1\} *$/\1/p' "$list")
[ "${#images[@]}" -gt 0 ] || { echo "screenshots: $list lists no image" >&2; exit 1; }

# Keys and a password for this run alone, the form the servers take them in.
random_hex() { od -An -vtx1 -N "$1" /dev/urandom | tr -d ' \n'; }
SCREENSHOTS_AES_ENCRYPTION_KEY="$(random_hex 32)"
SCREENSHOTS_AUTHSERVER_SESSION_AUTHENTICATION_KEY="$(random_hex 64)"
SCREENSHOTS_AUTHSERVER_SESSION_ENCRYPTION_KEY="$(random_hex 32)"
SCREENSHOTS_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY="$(random_hex 64)"
SCREENSHOTS_ADMINCONSOLE_SESSION_ENCRYPTION_KEY="$(random_hex 32)"
SCREENSHOTS_ADMINCONSOLE_OAUTH_CLIENT_SECRET="$(random_hex 32)"
SCREENSHOTS_ADMIN_PASSWORD="$(random_hex 16)"
export SCREENSHOTS_PLAYWRIGHT_VERSION SCREENSHOTS_AES_ENCRYPTION_KEY \
  SCREENSHOTS_AUTHSERVER_SESSION_AUTHENTICATION_KEY SCREENSHOTS_AUTHSERVER_SESSION_ENCRYPTION_KEY \
  SCREENSHOTS_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY SCREENSHOTS_ADMINCONSOLE_SESSION_ENCRYPTION_KEY \
  SCREENSHOTS_ADMINCONSOLE_OAUTH_CLIENT_SECRET SCREENSHOTS_ADMIN_PASSWORD

stage="$(mktemp -d "${TMPDIR:-/tmp}/goiabada-screenshots.XXXXXX")"
mkdir "$stage/new" "$stage/old"
step=""
started=false
removed=false

# Removes the containers, the network and the volumes of the project, and the capture's container.
remove_project() {
  docker rm -f "$capture" >/dev/null 2>&1 || true
  "${compose[@]}" down --volumes --remove-orphans --timeout 5 >/dev/null 2>&1
}

# Leaving, pass or fail, Ctrl-C or SIGTERM, removes what the run started and its staging folder. A
# failure names the step, with the servers' last log lines when they had been started.
finish() {
  local status=$?
  trap - EXIT
  if [ "$status" -ne 0 ]; then
    echo "screenshots: failed while $step" >&2
    if [ "$started" = true ] && [ "$removed" = false ]; then
      echo "--- the servers' last log lines" >&2
      "${compose[@]}" logs --no-color --tail 40 authserver adminconsole >&2 || true
    fi
  fi
  if [ "$removed" = false ]; then
    remove_project || echo "screenshots: could not remove Compose project $project; remove it with: docker compose -p $project down --volumes" >&2
  fi
  rm -rf "$stage"
  exit "$status"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

step="building the servers"
echo "screenshots: $step"
"${compose[@]}" build --quiet authserver adminconsole

step="starting the servers"
echo "screenshots: $step"
started=true
"${compose[@]}" up --detach --wait --wait-timeout 300 --quiet-pull authserver adminconsole mailpit

step="capturing the images"
echo "screenshots: $step"
"${compose[@]}" run --no-TTY --quiet-pull --name "$capture" capture
docker cp --quiet "$capture:/out/." "$stage/new/"

step="checking the images captured"
for name in "${images[@]}"; do
  [ -s "$stage/new/$name" ] || { echo "screenshots: the capture wrote no $name" >&2; exit 1; }
done

step="removing the containers"
echo "screenshots: $step"
remove_project
removed=true

# Each image replaces the committed one by a rename in its own folder, the committed one copied
# aside first, so an image whose replacement fails is left as it was. When one fails, the ones
# already replaced are put back, the same way, and one that was not there before is removed.
replaced=()
put_back() {
  local name
  for name in "${replaced[@]}"; do
    if [ -e "$stage/old/$name" ]; then
      { cp -p "$stage/old/$name" "$assets/.$name.old" && mv -f "$assets/.$name.old" "$assets/$name"; } ||
        echo "screenshots: could not put back site/src/assets/$name; restore it with: git checkout -- site/src/assets/$name" >&2
    else
      rm -f "$assets/$name"
    fi
  done
}
step="replacing the committed images"
for name in "${images[@]}"; do
  if ! {
    { [ ! -e "$assets/$name" ] || cp -p "$assets/$name" "$stage/old/$name"; } &&
      cp "$stage/new/$name" "$assets/.$name.new" &&
      mv -f "$assets/.$name.new" "$assets/$name"
  }; then
    rm -f "$assets/.$name.new"
    echo "screenshots: could not replace site/src/assets/$name; putting back the images replaced before it" >&2
    put_back
    exit 1
  fi
  replaced+=("$name")
done

for name in "${images[@]}"; do echo "screenshots: wrote site/src/assets/$name"; done
