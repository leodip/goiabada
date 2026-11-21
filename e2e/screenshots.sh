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
# them as they were and says which step failed, with the servers' last log lines.
set -euo pipefail

case "${1:-}" in
  -h | --help) sed -n '2,12s/^# \{0,1\}//p' "$0"; exit 0 ;;
  "") ;;
  *) echo "screenshots: unknown argument: $1 (see --help)" >&2; exit 2 ;;
esac

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
assets="$root/site/src/assets"

# A project name of this checkout's own, so two checkouts can run the command at once.
project="goiabada-screenshots-$(printf '%s' "$root" | cksum | cut -d ' ' -f 1)"
capture="$project-capture"
checker="$project-check"
compose=(docker compose --project-name "$project" --file "$root/e2e/screenshots.yml")

# The Playwright the e2e suite pins, whose image the browser runs in.
SCREENSHOTS_PLAYWRIGHT_VERSION="$(sed -n 's/^ *"@playwright\/test": *"\([^"]*\)".*/\1/p' "$root/e2e/playwright/package.json")"
[ -n "$SCREENSHOTS_PLAYWRIGHT_VERSION" ] || { echo "screenshots: e2e/playwright/package.json pins no @playwright/test" >&2; exit 1; }

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
mkdir "$stage/new"
step=""
started=false
removed=false
images=()
preparing=false
installed=false

# Removes the containers, the network and the volumes of the project, and the capture's and the
# check's containers.
remove_project() {
  docker rm -f "$capture" "$checker" >/dev/null 2>&1 || true
  "${compose[@]}" down --volumes --remove-orphans --timeout 5 >/dev/null 2>&1
}

# The servers' last log lines, kept in the staging folder before the project is removed, so a step
# that fails after the removal still shows them.
server_logs() { "${compose[@]}" logs --no-color --tail 40 authserver adminconsole; }

# Leaving, pass or fail, Ctrl-C or SIGTERM, removes what the run started, the replacements it
# prepared and had not yet used, and its staging folder. A failure names the step, with the servers'
# last log lines when they had been started.
# Once every image is replaced the run has succeeded, so nothing after that point, a cleanup step that
# fails or an interrupt, makes it exit non-zero: a run that does leaves the committed images as they
# were. The cleanup itself never stops short of the exit.
finish() {
  local status=$?
  trap - EXIT
  set +e
  if [ "$installed" = true ] && [ "$status" -ne 0 ]; then
    echo "screenshots: warning: stopped while $step, after every image was written; delete site/src/assets/${prepared##*/} if it is left" >&2
    status=0
  fi
  if [ "$status" -ne 0 ]; then
    echo "screenshots: failed while $step" >&2
    if [ "$started" = true ] && [ "$removed" = false ]; then
      echo "--- the servers' last log lines" >&2
      server_logs >&2 || true
    elif [ -s "$stage/server-logs" ]; then
      echo "--- the servers' last log lines" >&2
      cat "$stage/server-logs" >&2
    fi
  fi
  if [ "$removed" = false ]; then
    remove_project || echo "screenshots: could not remove Compose project $project; remove it with: docker compose -p $project down --volumes" >&2
  fi
  if [ "$preparing" = true ]; then discard_prepared; fi
  rm -rf "$stage" ||
    echo "screenshots: warning: could not delete the staging folder $stage; delete it by hand" >&2
  exit "$status"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

step="building the servers"
echo "screenshots: $step"
"${compose[@]}" build --quiet authserver adminconsole check

step="starting the servers"
echo "screenshots: $step"
started=true
"${compose[@]}" up --detach --wait --wait-timeout 300 --quiet-pull authserver adminconsole mailpit

step="capturing the images"
echo "screenshots: $step"
"${compose[@]}" run --no-TTY --quiet-pull --name "$capture" capture
docker cp --quiet "$capture:/out/." "$stage/new/"
# Done with, and removed now so the check's run does not warn of it as an orphan of the project.
docker rm -f "$capture" >/dev/null 2>&1 || true

# The images to write, one file name to a line: the capture's own reading of images.json, so the
# script writes exactly the images the capture took.
# docker cp keeps a link the capture made as a link, which the host would follow into its own files,
# so the list and each image have to be regular files, read only once they are known to be, and
# each image a PNG: an 8-byte signature, then an IHDR chunk of 13 bytes, and an IEND chunk to end it.
# Then the check service decodes each one whole, in the Go image the releases build in, so the host
# needs nothing but Docker for it. tar hands it the images without following a link, and with
# COPYFILE_DISABLE macOS's tar adds no file of attributes beside each one.
step="checking the images captured"
regular_file() { [ ! -L "$1" ] && [ -f "$1" ]; }
png_start="89504e470d0a1a0a0000000d49484452"
png_end="0000000049454e44ae426082"
hex_bytes() { od -An -vtx1 | tr -d ' \n'; }
regular_file "$stage/new/images.txt" || { echo "screenshots: the capture wrote no images.txt, or one that is not a regular file" >&2; exit 1; }
while IFS= read -r name; do
  [[ "$name" =~ ^screenshot[A-Za-z0-9._-]*$ ]] || { echo "screenshots: images.txt names '$name', which is not a screenshot's file name" >&2; exit 1; }
  images+=("$name")
done <"$stage/new/images.txt"
[ "${#images[@]}" -gt 0 ] || { echo "screenshots: the capture lists no image" >&2; exit 1; }
for name in "${images[@]}"; do
  image="$stage/new/$name"
  [ -e "$image" ] || [ -L "$image" ] || { echo "screenshots: the capture wrote no $name" >&2; exit 1; }
  regular_file "$image" || { echo "screenshots: the capture's $name is not a regular file" >&2; exit 1; }
  [ "$(head -c 16 "$image" | hex_bytes)" = "$png_start" ] && [ "$(tail -c 12 "$image" | hex_bytes)" = "$png_end" ] ||
    { echo "screenshots: the capture's $name is not a PNG" >&2; exit 1; }
done
COPYFILE_DISABLE=1 tar -cf - -C "$stage/new" -- "${images[@]}" |
  "${compose[@]}" run --rm --no-TTY --name "$checker" check "${images[@]}"

step="removing the containers"
echo "screenshots: $step"
server_logs >"$stage/server-logs" 2>&1 || true
remove_project
removed=true

# Every new image and a copy of every committed one are first written into a folder of this run's
# own beside the committed images, as <name>.new and <name>.old, so what follows writes no data:
# each image replaces the committed one by a rename, and when one fails, the ones already replaced
# are put back by renaming their copies over them, one that was not there before is removed, and
# the rest of the folder is deleted. A copy that cannot be put back is left in the folder, which
# the run names. Once every image is replaced the run has succeeded; a copy it then cannot delete
# is only reported. The folder is this run's alone, so a later run never touches what one left.
prepared=""
discard_prepared() {
  [ -z "$prepared" ] || rm -rf "$prepared"
}
replaced=()
put_back() {
  local name kept=false
  for name in "${images[@]}"; do
    rm -f "$prepared/$name.new"
    case " ${replaced[*]-} " in
      *" $name "*) ;;
      *) rm -f "$prepared/$name.old"; continue ;;
    esac
    if [ -e "$prepared/$name.old" ]; then
      if ! mv -f "$prepared/$name.old" "$assets/$name"; then
        kept=true
        echo "screenshots: could not put back site/src/assets/$name; the committed one is site/src/assets/${prepared##*/}/$name.old, or restore it with: git checkout -- site/src/assets/$name" >&2
      fi
    else
      rm -f "$assets/$name" || echo "screenshots: could not remove site/src/assets/$name, which the run added" >&2
    fi
  done
  if [ "$kept" = false ]; then discard_prepared; fi
}

step="preparing the replacements"
preparing=true
prepared="$(mktemp -d "$assets/.screenshots-XXXXXX")"
for name in "${images[@]}"; do
  cp "$stage/new/$name" "$prepared/$name.new"
  if [ -e "$assets/$name" ]; then cp -p "$assets/$name" "$prepared/$name.old"; fi
done
preparing=false

step="replacing the committed images"
for name in "${images[@]}"; do
  if ! mv -f "$prepared/$name.new" "$assets/$name"; then
    echo "screenshots: could not replace site/src/assets/$name; putting back the images replaced before it" >&2
    put_back
    exit 1
  fi
  replaced+=("$name")
done
installed=true

step="deleting the copies of the committed images"
for name in "${images[@]}"; do
  rm -f "$prepared/$name.old" ||
    echo "screenshots: warning: could not delete site/src/assets/${prepared##*/}/$name.old, a copy of the image it replaced; delete it by hand" >&2
done
rmdir "$prepared" 2>/dev/null ||
  echo "screenshots: warning: could not delete the folder site/src/assets/${prepared##*/}; delete it by hand" >&2

for name in "${images[@]}"; do echo "screenshots: wrote site/src/assets/$name"; done
