# Dev container

`devcontainer.json` plus `docker-compose.yml` is the stack VS Code opens for human development:
a `devcontainer` service with the checkout mounted at `/workspaces/goiabada`, MySQL, PostgreSQL,
SQL Server and Mailpit on a private network, and four ports published to the host so a person can
reach the databases and the Mailpit UI: 13306, 15432, 11433 and 8025. Nothing below changes that
stack.

## A second stack beside it

`docker-compose.worktree.yml` is an override for **automated** stacks: independent copies of the
same five services, one per git worktree, so a test run in one worktree cannot touch another's
files or databases, and a rebuild or reopen of the human container in VS Code cannot kill a run
in flight. Its whole content is `ports: !reset []` on the four services that publish a port. That
is the only thing that stops a plain `docker compose up` with a new project name from starting
next to the live stack: the tests reach the databases by service name on the project's own
network with fixed internal ports, and Compose prefixes the network, the volumes and the built
image with the project name. Everything else is inherited, so `run-tests.sh` runs inside the
second stack unchanged.

### Start

Run from anywhere. `--project-directory` pins the compose files' relative paths (the build
context, the `../..` bind mount) to the worktree, so the stack mounts that checkout rather than
whichever directory you happen to be in. Pick a project name that is not `goiabada`.

```sh
WT=/path/to/worktree          # the checkout this stack must mount
NAME=goiabada-wt-130          # any name but goiabada, which is the human stack

docker compose -p "$NAME" \
  --project-directory "$WT/src/.devcontainer" \
  -f "$WT/src/.devcontainer/docker-compose.yml" \
  -f "$WT/src/.devcontainer/docker-compose.worktree.yml" \
  up -d --wait --wait-timeout 300
```

`!reset` in an override needs Compose 2.24 or later.

### Wait for readiness

`up --wait` returns when every service is running, or healthy where the image declares a
healthcheck. Only Mailpit declares one. MySQL, PostgreSQL and above all SQL Server report
`running` well before they accept connections, and a fresh stack has no warm server to hide
that, so wait for each database before running anything. The devcontainer image ships no
database client; each database image ships its own, so ask each server through its own
container:

Every probe is bounded twice: a short client timeout, so one hung connection cannot stall the
loop (the MySQL image's default `--connect-timeout` is 43,200 seconds), and a deadline on the
whole wait, so a server that is running but broken, or a wrong password, fails the run instead
of holding it forever:

```sh
wait_for() {  # wait_for <label> <deadline-seconds> <probe command...>
  local label=$1 deadline=$2; shift 2
  local t0=$SECONDS
  until "$@" >/dev/null 2>&1; do
    if (( SECONDS - t0 >= deadline )); then echo "$label not ready after ${deadline}s" >&2; return 1; fi
    sleep 2
  done
}
wait_for mysql    120 docker exec "$NAME-mysql-server-1"    mysql --connect-timeout=3 -h 127.0.0.1 -P 13306 -uroot -pmySqlPass123 -e 'select 1' &&
wait_for postgres 120 docker exec "$NAME-postgres-server-1" pg_isready -t 3 -p 15432 -U postgres &&
wait_for mssql    300 docker exec "$NAME-mssql-server-1"    /opt/mssql-tools18/bin/sqlcmd -l 3 -t 3 -S localhost,11433 -U sa -P 'YourStr0ngPassw0rd!' -C -Q 'select 1' ||
exit 1
```

The three are chained so the first database that misses its deadline ends the wait with a
failure; without the chain a later success would hide an earlier timeout.

SQL Server gets the longest deadline because it is the slowest to accept its first login on a
fresh volume. Each probe is a real login over TCP on the port the tests use, and each exits
non-zero on a refused login as well as on an unreachable server, so a wrong password hits the
deadline rather than looping past it. The MySQL probe is `mysql -e 'select 1'` with an explicit
`-h 127.0.0.1` rather than `mysqladmin ping`: with no host the client takes the Unix socket and
ignores `-P`, which answers during first-run initialisation while networking is still off, and
`mysqladmin ping` exits zero on access denied.

### Use

The devcontainer's environment comes from `containerEnv` in `devcontainer.json`, which Compose
never reads. VS Code injects it for the human container; for an automated stack pass every
entry as `-e KEY=VALUE` on each `docker exec`, or the launched authserver has no configuration,
drops into first-run setup and the integration tier times out with zero tests. `CGO_ENABLED=0`
is among those entries and matters for the build.

```sh
docker exec -u vscode -w /workspaces/goiabada/src/authserver \
  -e GOIABADA_DB_TYPE=mssql -e ... \
  "$NAME-devcontainer-1" ./run-tests.sh --type data
```

One invocation of `run-tests.sh` per container at a time. It removes `/tmp/goiabada*.db*` and
kills whatever listens on 19090 and 19091 in its own container, so two concurrent runs in one
container would collide; separate stacks are unaffected.

From Git Bash on Windows, export `MSYS_NO_PATHCONV=1` first. Otherwise the shell rewrites the
`-w /workspaces/...` and `/opt/mssql-tools18/...` arguments above into Windows paths before
docker sees them, and the exec fails with `Cwd must be an absolute path` or a missing binary.

### Stop

Take the stack down with its volumes, or the next stack under the same name inherits its
databases:

```sh
docker compose -p "$NAME" \
  --project-directory "$WT/src/.devcontainer" \
  -f "$WT/src/.devcontainer/docker-compose.yml" \
  -f "$WT/src/.devcontainer/docker-compose.worktree.yml" \
  down -v
```

### How many

Each stack costs roughly what the human one does, most of it SQL Server, which needs at least
2 GB and is capped at 4 GB in `docker-compose.yml`. Measure before assuming there is room for
another:

```sh
docker stats --no-stream
```

The override deliberately tunes nothing: a `command` in an override replaces rather than
appends, so a MySQL buffer-pool flag would silently drop `--port=13306`, and SQL Server cannot
safely go below its minimum.
