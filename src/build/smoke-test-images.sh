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
# Each image is then read as the user it is configured to run as, with a shell in
# place of its entrypoint, because which user that is no Go test can see (#396):
#
#   - It must be uid and gid 10001, the numeric ids a Kubernetes runAsNonRoot can
#     verify without a passwd lookup and the ones the docs tell an operator to
#     make a mounted file readable to.
#   - It must not be able to write its own binary, or the directory holding it,
#     so a process that is compromised cannot replace what the next start runs.
#   - The auth server's image must give it /data and /bootstrap to write. Docker
#     copies a mount point's ownership into an empty named volume, and creates a
#     mount point the image lacks owned by root, so these two directories are what
#     lets a fresh SQLite volume or bootstrap volume be written at all.
#
# Each image's packages are then held to the floors PACKAGE_FLOORS names, read
# from the image's own package database with no network: a package older than its
# floor fails the run, and one the image doesn't carry passes. zlib 1.3.2-r1 fixes
# CVE-2026-85091, which alpine:3.24 ships without; the release Dockerfiles' final
# stage runs apk upgrade to get it, and this is what proves an image has it,
# whatever its Dockerfile says (#542). A floor costs nothing once the base image
# carries the fix, so it can stay.
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
RUN_AS="10001:10001"
AUTHSERVER_WRITABLE_DIRS=(/data /bootstrap)
PACKAGE_FLOORS=("zlib 1.3.2-r1")
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

# Prints, from inside the image and as the user it runs as, its uid:gid and
# whether each path after the image is writable to it. A shell replaces the
# entrypoint and nothing else, so the user is the one the image configures.
read_user() {
    local image="$1"
    shift
    docker run --rm --network none --entrypoint /bin/sh "$image" -c '
        echo "id $(id -u):$(id -g)"
        for path in "$@"; do
            if [ -w "$path" ]; then echo "$path writable"; else echo "$path not writable"; fi
        done
    ' sh "$@"
}

# Prints, from inside the image and with no network, each floor's package with its
# installed version and how that compares with the floor: "<", "=" or ">", or the
# word absent when the image doesn't carry it. A shell replaces the entrypoint and
# nothing else, as in read_user.
read_packages() {
    local image="$1"
    docker run --rm --network none --entrypoint /bin/sh "$image" -c '
        for floor in "$@"; do
            name=${floor%% *}
            min=${floor#* }
            version=$(awk -v p="$name" "/^P:/ { current = substr(\$0, 3) } /^V:/ { if (current == p) print substr(\$0, 3) }" /lib/apk/db/installed)
            if [ -z "$version" ]; then
                echo "$name absent"
                continue
            fi
            echo "$name $version $(apk version -t "$version" "$min" 2>/dev/null || echo "?") $min"
        done
    ' sh "${PACKAGE_FLOORS[@]}"
}

# Fails unless the read_user output in USER_OUTPUT carries the line exactly.
expect_line() {
    local image="$1" line="$2"
    if ! grep -q -x -F -e "$line" <<<"$USER_OUTPUT"; then
        fail "$image: its user does not report \"$line\""
    fi
}

for image in "${IMAGES[@]}"; do
    echo "=== $image, its user"
    # The entrypoint's first element is the binary.
    binary=$(docker image inspect --format '{{index .Config.Entrypoint 0}}' "$image")
    writable_dirs=()
    if [[ "$binary" == */goiabada-authserver ]]; then
        writable_dirs=("${AUTHSERVER_WRITABLE_DIRS[@]}")
    fi
    USER_OUTPUT=$(read_user "$image" "$binary" "$(dirname "$binary")" "${writable_dirs[@]}" 2>&1) ||
        fail "$image: unable to read its user: $USER_OUTPUT"
    echo "$USER_OUTPUT"
    expect_line "$image" "id $RUN_AS"
    expect_line "$image" "$binary not writable"
    expect_line "$image" "$(dirname "$binary") not writable"
    for dir in "${writable_dirs[@]}"; do
        expect_line "$image" "$dir writable"
    done

    echo "=== $image, its package floors"
    PACKAGES_OUTPUT=$(read_packages "$image" 2>&1) ||
        fail "$image: unable to read its packages: $PACKAGES_OUTPUT"
    echo "$PACKAGES_OUTPUT"
    while read -r name version comparison floor; do
        case "$version $comparison" in
            "absent "|*" ="|*" >") ;;
            *) fail "$image: $name $version is older than $floor, or could not be compared with it" ;;
        esac
    done <<<"$PACKAGES_OUTPUT"

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
