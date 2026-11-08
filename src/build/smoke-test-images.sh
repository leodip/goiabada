#!/bin/bash
# Checks each release image before a release pushes it, for what only a built image shows. The
# images are built FROM scratch (#808): they hold no shell, so everything here reads them from
# outside, through Docker.
#
# Each image's configuration, read with docker image inspect:
#
#   - Its user must be 10001:10001, the numeric ids a Kubernetes runAsNonRoot can verify without a
#     passwd file and the ones the docs tell an operator to make a mounted file readable to (#396).
#   - Its entrypoint must be its server's binary, /app/goiabada-<server>.
#   - Its health check must be that binary's healthcheck command, every 10 seconds, a 5-second
#     timeout, a 5-minute start period and 3 retries.
#
# Each image's contents, read from an export of a container created from it and never started: the
# exact set of paths, with their owners and modes, AUTHSERVER_CONTENTS or ADMINCONSOLE_CONTENTS,
# which src/core/guard/release_final_stage_test.go holds to the list it holds the Dockerfiles to.
# Docker adds a few entries of its own to every container it creates, DOCKER_CREATED, which are
# left out of the comparison; any other path, one missing, or another owner or mode fails the run.
# So the binary and /app must be root's and not writable by 10001, so a compromised process cannot
# replace what the next start runs; /data and /bootstrap, in the auth server's, must be 10001's,
# since Docker copies a mount point's ownership into an empty named volume; /tmp must be sticky and
# world-writable; and the CA bundle the servers' TLS reads must be at
# /etc/ssl/certs/ca-certificates.crt.
#
# The images carry no zone database: the binaries embed their own, and each server resolves TZ
# against it before its first record. Every unit and integration host has zone data, so no test
# there can tell that fix from its reversal; these images are the one host where it is observable
# (#331). So each image is started twice with no configuration:
#
#   - With TZ=Asia/Kolkata, which has no daylight saving, its first record must carry +05:30, and
#     its "build information" record the version the image was built with. A reverted fix logs in
#     UTC here.
#   - With a TZ naming no zone, it must exit 2, a malformed variable's code. A reverted fix logs in
#     UTC and goes on to fail later, on something else.
#
# With no configuration both servers stop on their own after those records, so each run ends
# without anything to connect to. The timeout is for a server that does not stop: the run fails
# rather than hang the job.
#
# Last, the two images are started together and configured, as OpenShift runs them under its
# restricted-v2 SCC (#686): an arbitrary uid with group 0, a read-only root, every capability
# dropped and no network, the admin console in the auth server's network namespace. The keys are
# generated for the run, and the database is SQLite in memory. Each container's own health status,
# which Docker sets by running the image's health check inside it under those constraints, must
# read healthy within HEALTH_TIMEOUT: the auth server's only after migrating, seeding and
# listening, the admin console's only after the auth server has issued its token. So anything that
# start reads or runs that only uid 10001 may, any write it makes to the image's file system, or a
# health check that cannot run there fails the run. The wait has a deadline of its own, and stops
# as soon as the container has exited; on any failure it prints the server's log and the
# container's health-check history, each probe's exit code and output. It needs both images, and is
# skipped when either is missing.
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
# Independent of the check's own timings: the first probe runs 10 seconds after the start, and a
# server not yet listening then is probed again 10 seconds later.
HEALTH_TIMEOUT=120
UNKNOWN_TZ="Not/AZone"
RUN_AS="10001:10001"
ARBITRARY_USER="1000680000:0"

# What each image holds, "<mode> <uid>/<gid> <path>" as tar lists an export of it.
AUTHSERVER_CONTENTS=(
    "drwxr-xr-x 0/0 app/"
    "-rwxr-xr-x 0/0 app/goiabada-authserver"
    "drwxr-xr-x 10001/10001 bootstrap/"
    "drwxr-xr-x 10001/10001 data/"
    "drwxr-xr-x 0/0 etc/"
    "drwxr-xr-x 0/0 etc/ssl/"
    "drwxr-xr-x 0/0 etc/ssl/certs/"
    "-rw-r--r-- 0/0 etc/ssl/certs/ca-certificates.crt"
    "drwxrwxrwt 0/0 tmp/"
)
ADMINCONSOLE_CONTENTS=(
    "drwxr-xr-x 0/0 app/"
    "-rwxr-xr-x 0/0 app/goiabada-adminconsole"
    "drwxr-xr-x 0/0 etc/"
    "drwxr-xr-x 0/0 etc/ssl/"
    "drwxr-xr-x 0/0 etc/ssl/certs/"
    "-rw-r--r-- 0/0 etc/ssl/certs/ca-certificates.crt"
    "drwxrwxrwt 0/0 tmp/"
)
# The paths Docker adds to every container it creates, whatever the image holds.
DOCKER_CREATED=(.dockerenv dev/ dev/console dev/pts/ dev/shm/ etc/hostname etc/hosts etc/mtab etc/resolv.conf proc/ sys/)
failed=0

fail() {
    echo "::error::$1"
    failed=1
}

# The containers this run has created. Leaving, by the last line, a failure, Ctrl-C or SIGTERM,
# removes them all, so a run cut short leaves none behind.
CONTAINERS=()
# shellcheck disable=SC2329 # the EXIT trap below invokes it
remove_containers() {
    [ "${#CONTAINERS[@]}" -eq 0 ] || docker rm -f "${CONTAINERS[@]}" >/dev/null 2>&1 || true
}
trap remove_containers EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Runs an image with one TZ and no other configuration, printing its combined output and setting
# STATUS to its exit code. The container is named so that a run the timeout cuts short is still
# removed.
run_image() {
    local image="$1" tz="$2" name
    name="goiabada-smoke-$$-$RANDOM"
    CONTAINERS+=("$name")
    STATUS=0
    OUTPUT=$(timeout "$RUN_TIMEOUT" docker run --rm --name "$name" -e TZ="$tz" "$image" 2>&1) || STATUS=$?
    docker rm -f "$name" >/dev/null 2>&1 || true
}

# Prints what the container name, created and never started, holds, one "<mode> <uid>/<gid> <path>"
# line per entry, sorted, without the paths Docker adds to every container. A symbolic link's line
# ends in "-> <target>". It fails when the export or its listing does.
read_contents() {
    docker export "$1" | tar --numeric-owner -tvf - |
        awk -v created="${DOCKER_CREATED[*]}" '
            BEGIN { n = split(created, list, " "); for (i = 1; i <= n; i++) skip[list[i]] = 1 }
            {
                line = $1 " " $2 " " $6
                for (i = 7; i <= NF; i++) line = line " " $i
                if (!($6 in skip)) print line
            }' | LC_ALL=C sort
}

# Prints count random bytes as hex, the form the servers' keys take.
random_hex() {
    od -An -vtx1 -N "$1" /dev/urandom | tr -d ' \n'
}

# Waits up to HEALTH_TIMEOUT seconds for the running container name's own health status to read
# healthy, setting HEALTHY, and setting WAIT_RESULT to why it stopped waiting otherwise: the
# container exited, it has no health check, or the deadline passed.
wait_healthy() {
    local name="$1" deadline=$((SECONDS + HEALTH_TIMEOUT)) state
    HEALTHY=false
    while :; do
        state=$(timeout 10 docker inspect --format '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}} {{.State.ExitCode}}' "$name" 2>/dev/null) ||
            state="unknown unknown unknown"
        read -r status health code <<<"$state"
        if [ "$health" = healthy ]; then
            HEALTHY=true
            return
        fi
        if [ "$status" != running ]; then
            WAIT_RESULT="the container is $status, exit code $code"
            return
        fi
        if [ "$health" = none ]; then
            WAIT_RESULT="the container has no health check"
            return
        fi
        if [ "$SECONDS" -ge "$deadline" ]; then
            WAIT_RESULT="its health status is still $health after ${HEALTH_TIMEOUT}s"
            return
        fi
        sleep 1
    done
}

# Prints a container's log and its health-check history, each probe's exit code and output.
print_diagnosis() {
    local name="$1"
    echo "--- $name: its log"
    docker logs "$name" 2>&1 || true
    echo "--- $name: its health checks"
    docker inspect --format '{{if .State.Health}}{{range .State.Health.Log}}exit {{.ExitCode}} at {{.Start}}: {{printf "%q" .Output}}{{"\n"}}{{end}}{{else}}no health check{{end}}' "$name" 2>&1 || true
}

# Waits for the started container name, from image, to turn healthy, and fails the run with its log
# and health history when it does not.
expect_healthy() {
    local image="$1" name="$2"
    wait_healthy "$name"
    if [ "$HEALTHY" = true ]; then
        echo "$image as $ARBITRARY_USER on a read-only root: healthy"
    else
        fail "$image as $ARBITRARY_USER on a read-only root did not turn healthy: $WAIT_RESULT"
        print_diagnosis "$name"
    fi
}

# Fails unless the image's configuration field, read with the Go template format, is want.
expect_config() {
    local image="$1" what="$2" format="$3" want="$4" got
    got=$(docker image inspect --format "$format" "$image" 2>&1) || { fail "$image: unable to read its $what: $got"; return; }
    echo "$what: $got"
    [ "$got" = "$want" ] || fail "$image: its $what is $got, where it must be $want"
}

for image in "${IMAGES[@]}"; do
    echo "=== $image, its configuration"
    # The entrypoint's first element names the server.
    binary=$(docker image inspect --format '{{index .Config.Entrypoint 0}}' "$image" 2>/dev/null) || binary=""
    case "$binary" in
        */goiabada-authserver) server=authserver; contents=("${AUTHSERVER_CONTENTS[@]}"); authserver_image="$image" ;;
        */goiabada-adminconsole) server=adminconsole; contents=("${ADMINCONSOLE_CONTENTS[@]}"); adminconsole_image="$image" ;;
        *) fail "$image: its entrypoint, \"$binary\", runs neither server"; continue ;;
    esac
    expect_config "$image" user '{{.Config.User}}' "$RUN_AS"
    expect_config "$image" entrypoint '{{json .Config.Entrypoint}}' "[\"/app/goiabada-$server\"]"
    expect_config "$image" "health check" '{{json .Config.Healthcheck}}' \
        "{\"Test\":[\"CMD\",\"/app/goiabada-$server\",\"healthcheck\"],\"Interval\":10000000000,\"Timeout\":5000000000,\"StartPeriod\":300000000000,\"Retries\":3}"

    echo "=== $image, its contents"
    created="goiabada-smoke-$$-$RANDOM"
    CONTAINERS+=("$created")
    if ! got=$(docker create --name "$created" "$image" 2>&1); then
        fail "$image: unable to create a container to read its contents from: $got"
    elif got=$(read_contents "$created" 2>&1); then
        echo "$got"
        want=$(printf '%s\n' "${contents[@]}" | LC_ALL=C sort)
        extra=$(LC_ALL=C comm -13 <(echo "$want") <(echo "$got"))
        missing=$(LC_ALL=C comm -23 <(echo "$want") <(echo "$got"))
        [ -z "$extra" ] || fail "$image holds what it must not: $(paste -sd ';' <<<"$extra")"
        [ -z "$missing" ] || fail "$image lacks what it must hold: $(paste -sd ';' <<<"$missing")"
    else
        fail "$image: unable to read its contents: $got"
    fi
    docker rm -f "$created" >/dev/null 2>&1 || true

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
    if docker run -d --name "$authserver_name" --network none "${restricted[@]}" "${urls[@]}" \
        -e GOIABADA_DB_TYPE=sqlite \
        -e GOIABADA_AES_ENCRYPTION_KEY="$(random_hex 32)" \
        -e GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY="$(random_hex 64)" \
        -e GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY="$(random_hex 32)" \
        -e GOIABADA_ADMIN_EMAIL=admin@example.com \
        -e GOIABADA_ADMIN_PASSWORD="$(random_hex 16)" \
        -e GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET="$client_secret" \
        "$authserver_image" >/dev/null; then
        expect_healthy "$authserver_image" "$authserver_name"
    else
        fail "$authserver_image: unable to start it as $ARBITRARY_USER"
        HEALTHY=false
    fi
    if [ "$HEALTHY" = true ]; then
        if docker run -d --name "$adminconsole_name" --network "container:$authserver_name" "${restricted[@]}" "${urls[@]}" \
            -e GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY="$(random_hex 64)" \
            -e GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY="$(random_hex 32)" \
            -e GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET="$client_secret" \
            "$adminconsole_image" >/dev/null; then
            expect_healthy "$adminconsole_image" "$adminconsole_name"
            # The console's failure can be the auth server's refusal, which only its log shows.
            [ "$HEALTHY" = true ] || print_diagnosis "$authserver_name"
        else
            fail "$adminconsole_image: unable to start it as $ARBITRARY_USER"
        fi
    fi
    docker rm -f "$adminconsole_name" "$authserver_name" >/dev/null 2>&1 || true
fi

exit "$failed"
