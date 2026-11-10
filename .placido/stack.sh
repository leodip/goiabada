#!/usr/bin/env bash
# The Docker stack of one placido issue: a compose project named after the issue
# ($PLACIDO_NAME, such as goiabada-439) from src/.devcontainer, with every database,
# and no fixed published ports (docker-compose.worktree.yml), so issues never collide
# with each other or with the human stack, `goiabada`. Tests run inside its devcontainer
# with the environment devcontainer.json declares, which `docker exec` does not apply
# by itself (see src/.devcontainer/README.md).
#
#   stack.sh up          build what changed, start the stack, and wait for every database (placido's setup)
#   stack.sh down        remove its containers, volumes, network and image (teardown)
#   stack.sh run ARGS    src/authserver/run-tests.sh ARGS, in the devcontainer
#   stack.sh vet         go vet in every module, in the devcontainer
#   stack.sh exec CMD    any shell command, from src/authserver, in the devcontainer
#   stack.sh serve       start the auth server and admin console from this worktree, for a browser
#   stack.sh serve stop  stop them
#   stack.sh ps          the stack's containers
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WT="${PLACIDO_WORKTREE:-$(cd "$here/.." && pwd)}"
NAME="${PLACIDO_NAME:-goiabada-$(basename "$WT")}"
NAME="$(printf '%s' "$NAME" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9_-' '-')"
WAIT="${PLACIDO_STACK_WAIT:-300}"
DC="$WT/src/.devcontainer"
CONTAINER="$NAME-devcontainer-1"
REPO_IN_CONTAINER=/workspaces/goiabada

die() { echo "stack.sh: $*" >&2; exit 1; }
[[ "$NAME" != goiabada ]] || die "the project name goiabada belongs to the human stack."
[[ -f "$DC/docker-compose.worktree.yml" ]] || die "$DC has no docker-compose.worktree.yml."

# Builds use the Docker context's own builder, not the one `docker buildx use` picked
# last: src/build/build-docker-images.sh picks goiabada-multiarch, a container that
# cannot start again once Docker Desktop restarts, which failed #616's setup.
BUILDX_BUILDER="${BUILDX_BUILDER:-$(docker context show)}"
export BUILDX_BUILDER

compose() {
    docker compose -p "$NAME" --project-directory "$DC" \
        -f "$DC/docker-compose.yml" -f "$DC/docker-compose.worktree.yml" "$@"
}

# devcontainer.json is JSON with comments and trailing commas; read its containerEnv
# and remoteEnv as `-e KEY=VALUE` arguments for docker exec.
env_args() {
    python3 - "$DC/devcontainer.json" <<'PY'
import json, re, sys
raw = open(sys.argv[1], encoding="utf-8").read()
out, i, n, in_str, esc = [], 0, len(raw), False, False
while i < n:
    c = raw[i]
    if in_str:
        out.append(c)
        if esc: esc = False
        elif c == "\\": esc = True
        elif c == '"': in_str = False
        i += 1
        continue
    if c == '"':
        in_str = True; out.append(c); i += 1; continue
    if raw.startswith("//", i):
        j = raw.find("\n", i); i = n if j < 0 else j; continue
    if raw.startswith("/*", i):
        j = raw.find("*/", i + 2); i = n if j < 0 else j + 2; continue
    out.append(c); i += 1
cfg = json.loads(re.sub(r",(\s*[}\]])", r"\1", "".join(out)))
env = {}
for section in ("containerEnv", "remoteEnv"):
    env.update({str(k): str(v) for k, v in (cfg.get(section) or {}).items()})
for key, value in env.items():
    sys.stdout.write(f"-e\0{key}={value}\0")
PY
}

in_container() {  # in_container WORKDIR COMMAND...
    local workdir="$1"; shift
    docker ps --format '{{.Names}}' | grep -qx "$CONTAINER" \
        || die "$CONTAINER is not running; start the stack with: $0 up"
    local args=()
    while IFS= read -r -d '' item; do args+=("$item"); done < <(env_args)
    docker exec -u vscode -w "$workdir" "${args[@]}" "$CONTAINER" "$@"
}

# Each probe uses the address, port and login the tests use; the engines are not on
# their default ports. The password is the one the server's own container was started
# with, read from its environment there: a literal in the compose files, or one
# generate-env.sh drew for the worktree (#627).
probe() {
    case "$1" in
        mysql) docker exec "$NAME-mysql-server-1" sh -c 'mysql --connect-timeout=3 -h mysql-server -P 13306 \
                   -uroot -p"$MYSQL_ROOT_PASSWORD" -e "select 1"' >/dev/null 2>&1 ;;
        postgres) docker exec -e PGCONNECT_TIMEOUT=3 "$NAME-postgres-server-1" sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" \
                   psql -h postgres-server -p 15432 -U postgres -c "select 1"' >/dev/null 2>&1 ;;
        mssql) docker exec "$NAME-mssql-server-1" bash -c \
                   "\$(ls /opt/mssql-tools*/bin/sqlcmd | head -1) -C -S mssql-server,11433 -U sa \
                    -P \"\$MSSQL_SA_PASSWORD\" -l 3 -t 3 -Q 'SELECT 1'" >/dev/null 2>&1 ;;
    esac
}

# A server that exited will never answer: say why at once, not after the wait. MySQL
# and SQL Server each take a share of the kernel's async I/O contexts, a limit for the
# whole machine (Docker Desktop's engine shares WSL's kernel), which several stacks up
# at once can run out of.
exited() {
    docker logs --tail 15 "$2" 2>&1 | sed 's/^/  /' >&2
    if grep -q -i -e 'aio-max-nr' -e 'io_setup() failed' <(docker logs "$2" 2>&1); then  # no pipe: grep -q would break it
        die "$1 exited: the kernel ran out of async I/O contexts ($(cat /proc/sys/fs/aio-nr 2>/dev/null || echo '?')" \
            "in use of $(cat /proc/sys/fs/aio-max-nr 2>/dev/null || echo '?')). Raise the limit, once and for good:" \
            "echo 'fs.aio-max-nr = 1048576' | sudo tee /etc/sysctl.d/60-aio-max-nr.conf && sudo sysctl --system"
    fi
    die "$1 exited with code $(docker inspect -f '{{.State.ExitCode}}' "$2" 2>/dev/null); its last lines are above"
}

wait_for_databases() {
    local engine container deadline started
    for engine in mysql postgres mssql; do
        container="$NAME-$engine-server-1"
        started=$(date +%s); deadline=$(( started + WAIT ))
        until probe "$engine"; do
            [[ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null)" == true ]] || exited "$engine" "$container"
            [[ $(date +%s) -lt $deadline ]] || die "$engine did not answer within ${WAIT}s; see: docker logs $container"
            sleep 2
        done
        echo "$engine ready after $(( $(date +%s) - started ))s"
    done
}

# `serve`: the auth server and the admin console built from this worktree, for an agent
# to look at in a browser. They listen on 19290 and 19291 with a SQLite database of their
# own, apart from everything a test run uses: run-tests.sh kills whatever listens on
# 19090, 19091 and 19190 and removes /tmp/goiabada*.db*. The host reaches them on the
# loopback ports Docker picked for this stack (docker-compose.worktree.yml), and each
# base URL names that address, since the pages redirect to it and the cookies are set
# for it; the admin console reaches the auth server inside the container. The database
# starts empty each time, because the seed writes the admin console's sign-in address
# from its base URL, which changes when the stack is created again. The servers embed
# the stylesheets the worktree holds; serve does not regenerate them.
SERVE_DIR=/tmp/placido-serve

host_port() {  # host_port CONTAINER_PORT: the loopback port the host reaches it on
    compose port devcontainer "$1" 2>/dev/null | sed -n 's/.*:\([0-9][0-9]*\)$/\1/p' | head -1
}

serve_env() {  # serve_env AUTH_PORT CONSOLE_PORT: what differs from devcontainer.json, as -e arguments
    local setting
    for setting in GOIABADA_DB_TYPE=sqlite "GOIABADA_DB_DSN=$SERVE_DIR/goiabada.db" \
        GOIABADA_DB_USERNAME= GOIABADA_DB_PASSWORD= GOIABADA_DB_HOST= GOIABADA_DB_PORT= GOIABADA_DB_NAME= \
        "GOIABADA_AUTHSERVER_BASEURL=http://localhost:$1" GOIABADA_AUTHSERVER_INTERNALBASEURL=http://localhost:19290 \
        GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP=19290 GOIABADA_AUTHSERVER_LISTEN_PORT_HTTPS=19292 \
        GOIABADA_AUTHSERVER_METRICS_ENABLED=false \
        "GOIABADA_ADMINCONSOLE_BASEURL=http://localhost:$2" \
        GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTP=19291 GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTPS=19293; do
        printf -- '-e\0%s\0' "$setting"
    done
}

wait_for_page() {  # wait_for_page NAME URL: until it answers, or die with its log
    local deadline=$(( $(date +%s) + 60 ))
    until curl -s -o /dev/null -m 3 "$2"; do
        if [[ $(date +%s) -ge $deadline ]] || ! docker exec "$CONTAINER" pgrep -f "^$SERVE_DIR/goiabada-$1" >/dev/null; then
            docker exec "$CONTAINER" tail -n 20 "$SERVE_DIR/$1.log" 2>&1 | sed 's/^/  /' >&2
            die "the $1 did not answer at $2; its last lines are above"
        fi
        sleep 1
    done
}

case "${1:-}" in
    up)
        # Compose files that read the data key and database passwords from a generated
        # .env (#627) refuse to start without one: write it first, when the worktree has
        # the script. It keeps a .env already there.
        if [[ -f "$DC/generate-env.sh" ]]; then sh "$DC/generate-env.sh"; fi
        # Each database keeps the password its volume was first started with. A volume older
        # than .env was started with another, such as the literal main had before #627, so
        # the stack starts over without its volumes (#628). Their data are the tests', which
        # make their own.
        if [[ -f "$DC/.env" ]]; then
            written=$(stat -c %Y "$DC/.env")
            for volume in mysql-data postgres-data mssql-data; do
                created=$(docker volume inspect -f '{{.CreatedAt}}' "${NAME}_$volume" 2>/dev/null) || continue
                if (( $(date -d "$created" +%s) < written )); then
                    echo "stack.sh: ${NAME}_$volume predates $DC/.env, so it holds another password; removing the stack's volumes"
                    compose down -v --remove-orphans
                    break
                fi
            done
        fi
        # --build: an image left from an earlier run, or built before placido merged main
        # in, lacks what src/.devcontainer has since added, such as Node for #626's unit
        # gate. Docker's layer cache makes the build quick when nothing changed.
        compose up -d --build --wait --wait-timeout "$WAIT"
        wait_for_databases
        # The devcontainer must mount this worktree, not another checkout. Docker Desktop
        # on WSL can report the mount by its own proxy instead, named after the SHA-256
        # of the host path compose gave it.
        mounted=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "'"$REPO_IN_CONTAINER"'"}}{{.Source}}{{end}}{{end}}' "$CONTAINER")
        if [[ "$mounted" == /run/desktop/mnt/host/wsl/docker-desktop-bind-mounts/*/* \
              && "${mounted##*/}" == "$(realpath -s "$WT" | tr -d '\n' | sha256sum | cut -d' ' -f1)" ]]; then
            mounted="$WT"
        fi
        [[ "$(cd "$mounted" 2>/dev/null && pwd -P)" == "$(cd "$WT" && pwd -P)" ]] \
            || die "$CONTAINER mounts $mounted, not $WT."
        echo "stack $NAME is up"
        ;;
    down)
        compose down -v --rmi local --remove-orphans || echo "stack.sh: compose down failed; removing by label" >&2
        label="label=com.docker.compose.project=$NAME"
        docker ps -aq --filter "$label" | xargs -r docker rm -f >/dev/null
        docker volume ls -q --filter "$label" | xargs -r docker volume rm -f >/dev/null
        docker network ls -q --filter "$label" | xargs -r docker network rm >/dev/null
        echo "stack $NAME is down"
        ;;
    run)
        shift
        in_container "$REPO_IN_CONTAINER/src/authserver" ./run-tests.sh "$@"
        ;;
    vet)
        in_container "$REPO_IN_CONTAINER/src" bash -lc \
            'for m in core authserver adminconsole cmd/goiabada-setup; do (cd "$m" && echo "go vet $m" && go vet ./...) || exit 1; done'
        ;;
    exec)
        shift
        in_container "$REPO_IN_CONTAINER/src/authserver" bash -lc "$*"
        ;;
    serve)
        # The servers an earlier serve started stop, and their database goes with them.
        in_container / bash -c "pkill -f '^$SERVE_DIR/' || true; rm -rf '$SERVE_DIR' && mkdir -p '$SERVE_DIR'"
        if [[ "${2:-}" == stop ]]; then echo "the auth server and admin console are stopped"; exit 0; fi
        auth=$(host_port 19290); console=$(host_port 19291)
        [[ -n "$auth" && -n "$console" ]] \
            || die "$CONTAINER publishes no ports for serve, so it predates them; start the stack again with: $0 up"
        in_container "$REPO_IN_CONTAINER/src/authserver" \
            go build -buildvcs=false -o "$SERVE_DIR/goiabada-authserver" ./cmd/goiabada-authserver
        in_container "$REPO_IN_CONTAINER/src/adminconsole" \
            go build -buildvcs=false -o "$SERVE_DIR/goiabada-adminconsole" ./cmd/goiabada-adminconsole
        env=()
        while IFS= read -r -d '' item; do env+=("$item"); done < <(env_args; serve_env "$auth" "$console")
        for server in authserver adminconsole; do  # the console asks the auth server as it starts
            docker exec -d -u vscode -w "$SERVE_DIR" "${env[@]}" "$CONTAINER" \
                bash -c "exec $SERVE_DIR/goiabada-$server >$SERVE_DIR/$server.log 2>&1"
            if [[ $server == authserver ]]; then url="http://localhost:$auth/health"; else url="http://localhost:$console/"; fi
            wait_for_page "$server" "$url"
        done
        login=$(printf '%s\n' "${env[@]}" | sed -n 's/^GOIABADA_ADMIN_\(EMAIL\|PASSWORD\)=//p' | paste -sd ' ')
        echo "auth server    http://localhost:$auth"
        echo "admin console  http://localhost:$console  (sign in as ${login/ / with password })"
        echo "Built from this worktree's code, with an empty database seeded by the auth server."
        echo "Logs: $0 exec 'tail $SERVE_DIR/*.log'. Run serve again after a change; serve stop ends them."
        ;;
    ps)
        compose ps
        ;;
    *)
        sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
        exit 2
        ;;
esac
