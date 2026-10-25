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
# Each image's contents are then read from inside it with no network, and held to
# what the release Dockerfiles' final stage keeps (#520):
#
#   - Its package database must list exactly FINAL_STAGE_PACKAGES, which
#     src/core/guard/release_final_stage_test.go holds to the list both
#     Dockerfiles check in each platform's build. A package missing or one more,
#     at any version, fails the run, and so does a database it cannot read.
#   - It must have no apk command, so nothing installs a package at run time.
#   - It must have /etc/ssl/certs/ca-certificates.crt, the CA bundle the servers'
#     TLS reads, which deleting apk-tools with --purge removes unless it is added.
#
# Last, the two images are started together and configured, as OpenShift runs them
# under its restricted-v2 SCC (#686): an arbitrary uid with group 0, a read-only
# root, every capability dropped and no network, the admin console in the auth
# server's network namespace. The keys are generated for the run, and the database
# is SQLite in memory. Each must answer healthy on /health within RUN_TIMEOUT: the
# auth server only after migrating, seeding and listening, the admin console only
# after the auth server has issued its token. So anything that start reads or runs
# that only uid 10001 may, or any write it makes to the image's file system, fails
# the run. It needs both images, and is skipped when either is missing.
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
ARBITRARY_USER="1000680000:0"
AUTHSERVER_WRITABLE_DIRS=(/data /bootstrap)
FINAL_STAGE_PACKAGES=(alpine-baselayout alpine-baselayout-data alpine-keys alpine-release busybox busybox-binsh ca-certificates-bundle musl)
CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
failed=0

fail() {
    echo "::error::$1"
    failed=1
}

# The containers this run has started. Leaving, by the last line, a failure,
# Ctrl-C or SIGTERM, removes them all, so a run cut short leaves none running.
CONTAINERS=()
# shellcheck disable=SC2329 # the EXIT trap below invokes it
remove_containers() {
    [ "${#CONTAINERS[@]}" -eq 0 ] || docker rm -f "${CONTAINERS[@]}" >/dev/null 2>&1 || true
}
trap remove_containers EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Runs an image with one TZ and no other configuration, printing its combined
# output and setting STATUS to its exit code. The container is named so that a
# run the timeout cuts short is still removed.
run_image() {
    local image="$1" tz="$2" name
    name="goiabada-smoke-$$-$RANDOM"
    CONTAINERS+=("$name")
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

# Prints, from inside the image and with no network, one "package <name>" line per
# package its database lists, or "packages unreadable" when it can't be read; then
# "apk <path>" or "apk absent", and "<path> present" or "<path> absent" for the CA
# bundle. A shell replaces the entrypoint and nothing else, as in read_user.
read_contents() {
    local image="$1"
    docker run --rm --network none --entrypoint /bin/sh "$image" -c '
        if [ -r /lib/apk/db/installed ]; then
            awk "/^P:/ { print \"package \" substr(\$0, 3) }" /lib/apk/db/installed
        else
            echo "packages unreadable"
        fi
        if apk=$(command -v apk); then echo "apk $apk"; else echo "apk absent"; fi
        if [ -f "$1" ]; then echo "$1 present"; else echo "$1 absent"; fi
    ' sh "$CA_BUNDLE"
}

# Prints count random bytes as hex, the form the servers' keys take.
random_hex() {
    od -An -vtx1 -N "$1" /dev/urandom | tr -d ' \n'
}

# Waits up to RUN_TIMEOUT seconds for the running container name to answer healthy
# on /health at port, setting HEALTHY, and stops waiting once the container has
# exited. Each probe has its own limits, since a server that accepts the connection
# and never answers would hold BusyBox's wget far longer than RUN_TIMEOUT.
wait_healthy() {
    local name="$1" port="$2" deadline=$((SECONDS + RUN_TIMEOUT))
    HEALTHY=false
    while [ "$SECONDS" -lt "$deadline" ]; do
        if [ "$(timeout 5 docker exec "$name" wget -q -T 2 -O - "http://localhost:$port/health" 2>/dev/null)" = healthy ]; then
            HEALTHY=true
            return
        fi
        [ "$(timeout 5 docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null)" = true ] || return 0
        sleep 1
    done
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

    echo "=== $image, its packages"
    CONTENTS_OUTPUT=$(read_contents "$image" 2>&1) ||
        fail "$image: unable to read its contents: $CONTENTS_OUTPUT"
    echo "$CONTENTS_OUTPUT"
    if grep -q -x -F -e "packages unreadable" <<<"$CONTENTS_OUTPUT"; then
        fail "$image: unable to read its package database"
    else
        packages=$(sed -n 's/^package //p' <<<"$CONTENTS_OUTPUT" | sort)
        expected=$(printf '%s\n' "${FINAL_STAGE_PACKAGES[@]}" | sort)
        extra=$(comm -13 <(echo "$expected") <(echo "$packages") | xargs)
        missing=$(comm -23 <(echo "$expected") <(echo "$packages") | xargs)
        [ -z "$extra" ] || fail "$image holds packages the final stage must not: $extra"
        [ -z "$missing" ] || fail "$image lacks packages the final stage keeps: $missing"
    fi
    if ! grep -q -x -F -e "apk absent" <<<"$CONTENTS_OUTPUT"; then
        fail "$image still has an apk command: $(sed -n 's/^apk //p' <<<"$CONTENTS_OUTPUT")"
    fi
    if ! grep -q -x -F -e "$CA_BUNDLE present" <<<"$CONTENTS_OUTPUT"; then
        fail "$image has no CA bundle at $CA_BUNDLE"
    fi

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

    case "$binary" in
        */goiabada-authserver) authserver_image="$image" ;;
        */goiabada-adminconsole) adminconsole_image="$image" ;;
    esac
done

if [ -z "${authserver_image:-}" ] || [ -z "${adminconsole_image:-}" ]; then
    echo "=== skipping the start as $ARBITRARY_USER: it needs both images"
else
    echo "=== $authserver_image and $adminconsole_image, configured, as $ARBITRARY_USER"
    authserver_name="goiabada-smoke-$$-$RANDOM"
    adminconsole_name="goiabada-smoke-$$-$RANDOM"
    restricted=(--user "$ARBITRARY_USER" --read-only --cap-drop ALL --security-opt no-new-privileges)
    urls=(-e GOIABADA_AUTHSERVER_BASEURL=http://localhost:9090 -e GOIABADA_ADMINCONSOLE_BASEURL=http://localhost:9091)
    client_secret=$(random_hex 32)
    CONTAINERS+=("$authserver_name" "$adminconsole_name")
    docker run -d --name "$authserver_name" --network none "${restricted[@]}" "${urls[@]}" \
        -e GOIABADA_DB_TYPE=sqlite \
        -e GOIABADA_AES_ENCRYPTION_KEY="$(random_hex 32)" \
        -e GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY="$(random_hex 64)" \
        -e GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY="$(random_hex 32)" \
        -e GOIABADA_ADMIN_EMAIL=admin@example.com \
        -e GOIABADA_ADMIN_PASSWORD="$(random_hex 16)" \
        -e GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET="$client_secret" \
        "$authserver_image" >/dev/null || fail "$authserver_image: unable to start it as $ARBITRARY_USER"
    wait_healthy "$authserver_name" 9090
    docker logs "$authserver_name" 2>&1 || true
    if [ "$HEALTHY" = true ]; then
        docker run -d --name "$adminconsole_name" --network "container:$authserver_name" "${restricted[@]}" "${urls[@]}" \
            -e GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY="$(random_hex 64)" \
            -e GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY="$(random_hex 32)" \
            -e GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET="$client_secret" \
            "$adminconsole_image" >/dev/null || fail "$adminconsole_image: unable to start it as $ARBITRARY_USER"
        wait_healthy "$adminconsole_name" 9091
        docker logs "$adminconsole_name" 2>&1 || true
        [ "$HEALTHY" = true ] ||
            fail "$adminconsole_image as $ARBITRARY_USER on a read-only root did not answer healthy within ${RUN_TIMEOUT}s"
    else
        fail "$authserver_image as $ARBITRARY_USER on a read-only root did not answer healthy within ${RUN_TIMEOUT}s"
    fi
    docker rm -f "$adminconsole_name" "$authserver_name" >/dev/null 2>&1 || true
fi

exit "$failed"
