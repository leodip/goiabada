#!/bin/bash
# Starts each release image with no configuration, before a release pushes it,
# and checks the two things only a started image can show (#331).
#
# The images carry no zone database: the binaries embed their own, and each
# server resolves TZ against it before its first record. Every unit and
# integration host has zone data, so no test there can tell that fix from its
# reversal; these images are the one host where it is observable. So each image
# is started twice:
#
#   - With TZ=Asia/Kolkata, which has no daylight saving, its first record must
#     carry +05:30, and its "build information" record the version the image was
#     built with. A reverted fix logs in UTC here.
#   - With a TZ naming no zone, it must exit 2, a malformed variable's code. A
#     reverted fix logs in UTC and goes on to fail later, on something else.
#
# With no configuration both servers stop on their own after those records, so
# each run ends without anything to connect to. The timeout is for a server that
# does not stop: the run fails rather than hang the job.
#
# Usage: ./smoke-test-images.sh --version <version> <image>...
set -euo pipefail

VERSION=""
IMAGES=()
while [ $# -gt 0 ]; do
    case "$1" in
        --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
        -*) echo "unknown argument: $1" >&2; exit 2 ;;
        *) IMAGES+=("$1"); shift ;;
    esac
done
[ -n "$VERSION" ] || { echo "--version is required" >&2; exit 2; }
[ "${#IMAGES[@]}" -gt 0 ] || { echo "at least one image is required" >&2; exit 2; }

RUN_TIMEOUT=60
UNKNOWN_TZ="Not/AZone"
failed=0

fail() {
    echo "::error::$1"
    failed=1
}

# Runs an image with one TZ and no other configuration, printing its combined
# output and setting STATUS to its exit code. The container is named so that a
# run the timeout cuts short is still removed.
run_image() {
    local image="$1" tz="$2" name
    name="goiabada-smoke-$$-$RANDOM"
    STATUS=0
    OUTPUT=$(timeout "$RUN_TIMEOUT" docker run --rm --name "$name" -e TZ="$tz" "$image" 2>&1) || STATUS=$?
    docker rm -f "$name" >/dev/null 2>&1 || true
}

for image in "${IMAGES[@]}"; do
    echo "=== $image, TZ=Asia/Kolkata"
    run_image "$image" "Asia/Kolkata"
    echo "$OUTPUT"
    if [ "$STATUS" -eq 124 ]; then
        fail "$image did not stop within ${RUN_TIMEOUT}s with no configuration"
    fi
    first="${OUTPUT%%$'\n'*}"
    # The text handler writes the time first: time=2026-10-02T23:41:07.123+05:30
    if [[ ! "$first" =~ ^time=[^[:space:]]+\+05:30[[:space:]] ]]; then
        fail "$image with TZ=Asia/Kolkata: the first record does not carry +05:30: $first"
    fi
    if ! grep -q -F -e "msg=\"build information\" version=$VERSION " <<<"$OUTPUT"; then
        fail "$image: no build information record carries version $VERSION"
    fi

    echo "=== $image, TZ=$UNKNOWN_TZ"
    run_image "$image" "$UNKNOWN_TZ"
    echo "$OUTPUT"
    if [ "$STATUS" -ne 2 ]; then
        fail "$image with TZ=$UNKNOWN_TZ exited $STATUS, not 2"
    fi
done

exit "$failed"
