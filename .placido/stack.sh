#!/usr/bin/env bash
# The Docker stack of one placido issue: a compose project named after the issue
# ($PLACIDO_NAME, such as goiabada-439) from src/.devcontainer, with every database,
# and no published ports (docker-compose.worktree.yml), so issues never collide with
# each other or with the human stack, `goiabada`. Tests run inside its devcontainer
# with the environment devcontainer.json declares, which `docker exec` does not apply
# by itself (see src/.devcontainer/README.md).
#
#   stack.sh up          start the stack and wait for every database (placido's setup)
#   stack.sh down        remove its containers, volumes, network and image (teardown)
#   stack.sh run ARGS    src/authserver/run-tests.sh ARGS, in the devcontainer
#   stack.sh vet         go vet in every module, in the devcontainer
#   stack.sh exec CMD    any shell command, from src/authserver, in the devcontainer
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
# their default ports.
probe() {
    case "$1" in
        mysql) docker exec "$NAME-mysql-server-1" mysql --connect-timeout=3 -h mysql-server -P 13306 \
                   -uroot -pmySqlPass123 -e 'select 1' >/dev/null 2>&1 ;;
        postgres) docker exec -e PGCONNECT_TIMEOUT=3 -e PGPASSWORD=myPostgresPass123 "$NAME-postgres-server-1" \
                   psql -h postgres-server -p 15432 -U postgres -c 'select 1' >/dev/null 2>&1 ;;
        mssql) docker exec "$NAME-mssql-server-1" bash -c \
                   "\$(ls /opt/mssql-tools*/bin/sqlcmd | head -1) -C -S mssql-server,11433 -U sa \
                    -P 'YourStr0ngPassw0rd!' -l 3 -t 3 -Q 'SELECT 1'" >/dev/null 2>&1 ;;
    esac
}

wait_for_databases() {
    local engine deadline started
    for engine in mysql postgres mssql; do
        started=$(date +%s); deadline=$(( started + WAIT ))
        until probe "$engine"; do
            [[ $(date +%s) -lt $deadline ]] || die "$engine did not answer within ${WAIT}s; see: docker logs $NAME-$engine-server-1"
            sleep 2
        done
        echo "$engine ready after $(( $(date +%s) - started ))s"
    done
}

case "${1:-}" in
    up)
        compose up -d --wait --wait-timeout "$WAIT"
        wait_for_databases
        # The devcontainer must mount this worktree, not another checkout.
        mounted=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "'"$REPO_IN_CONTAINER"'"}}{{.Source}}{{end}}{{end}}' "$CONTAINER")
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
    ps)
        compose ps
        ;;
    *)
        sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
        exit 2
        ;;
esac
