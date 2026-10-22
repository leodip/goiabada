# Dev container

`devcontainer.json` plus `docker-compose.yml` is the stack VS Code opens for human development:
a `devcontainer` service with the checkout mounted at `/workspaces/goiabada`, MySQL, PostgreSQL,
SQL Server and Mailpit on a private network, and four ports published to the host so a person can
reach the databases and the Mailpit UI: 13306, 15432, 11433 and 8025. Nothing in
[A second stack beside it](#a-second-stack-beside-it) changes that stack.

## Secrets

No file in the repository holds the stack's data key or its database passwords (#501).
`generate-env.sh` writes them into `.env` in this directory, once, with fresh values:
`GOIABADA_AES_ENCRYPTION_KEY`, `MYSQL_ROOT_PASSWORD`, `POSTGRES_PASSWORD` and
`MSSQL_SA_PASSWORD`. `.gitignore` keeps the file out of git. Compose reads `.env` from this
directory and hands the passwords to the three databases and all four values to the
devcontainer, where `run-tests.sh` and `schemadump` read them; `docker-compose.yml` refuses to
start without them. `devcontainer.json` runs the script as its `initializeCommand`, on the host,
before every start. It keeps every value a `.env` already holds, and adds any of the four the file
lacks or holds empty, so a `.env` written by hand for `USER_UID` and `USER_GID`, which Compose
also reads from it, gains them. A `.env` it cannot read, such as one a `sudo` run left owned by
root, stops it with the file untouched, since writing a new one would lose the values the volumes
hold. It runs with no shell around it, so the host needs `sh` on its
`PATH`. Linux and macOS have it. Windows doesn't: neither WSL nor Git for Windows' default
install puts `sh` on the Windows `PATH`. On Windows, clone the repository inside WSL and open it
from there, or add Git for Windows' `usr\bin` directory to the `PATH`.

Keep `.env` as long as the stack's volumes: each database keeps the password its volume was
first initialised with, and a dev database seeded under one key can't be read under another.
Deleting `.env` means taking the volumes down with it (`down -v`) and seeding again.

A stack created before #627 has the published sample data key, which the auth server refuses, and
the old literal passwords baked into its volumes. Rebuild it once: take the stack down with its
volumes (from VS Code, `docker compose -p goiabada down -v` in this directory, or as
[Stop](#stop) shows for a second stack), then reopen the container or start it again, which
writes `.env`, initialises new volumes with its passwords and lets the auth server seed a new
dev database.

## TLS from a test authority

The three databases serve TLS with a certificate from a test authority, so the data tier can show a
connection whose certificate is checked succeeding (#502). `db-tls`, a service that runs once and
exits, writes the authority and a certificate naming `mysql-server`, `postgres-server` and
`mssql-server` into the `db-tls` volume with `generate-db-tls.sh`, before any database starts; each
database and the devcontainer mount that volume at `/db-tls`, and `run-tests.sh` hands the data
tier `/db-tls/ca.crt`. The script keeps a set that still verifies, so starting the stack again
changes nothing, and `down -v` takes the authority with the volume. CI's database jobs generate
theirs with the same script after checkout and restart their database container to serve it,
through `.github/actions/serve-db-tls`. A stack created before this needs `docker compose up` once
to recreate its databases with it.

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
whichever directory you happen to be in, and is where Compose reads `.env` from. Pick a project
name that is not `goiabada`. Run `generate-env.sh` first, as [Secrets](#secrets) says.

```sh
WT=/path/to/worktree          # the checkout this stack must mount
NAME=goiabada-wt-130          # any name but goiabada, which is the human stack

sh "$WT/src/.devcontainer/generate-env.sh"
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
wait_for mysql    120 docker exec "$NAME-mysql-server-1"   sh -c 'mysql --connect-timeout=3 -h mysql-server -P 13306 -uroot -p"$MYSQL_ROOT_PASSWORD" -e "select 1"' &&
wait_for postgres 120 docker exec -e PGCONNECT_TIMEOUT=3 "$NAME-postgres-server-1"   sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" psql -h postgres-server -p 15432 -U postgres -c "select 1"' &&
wait_for mssql    300 docker exec "$NAME-mssql-server-1"   sh -c '/opt/mssql-tools18/bin/sqlcmd -l 3 -t 3 -S mssql-server,11433 -U sa -P "$MSSQL_SA_PASSWORD" -C -Q "select 1"' ||
exit 1
```

Each probe runs in its database's own container and reads the password from that container's
environment, the one the server was started with, so it is never typed here.

The three are chained so the first database that misses its deadline ends the wait with a
failure; without the chain a later success would hide an earlier timeout.

SQL Server gets the longest deadline because it is the slowest to accept its first login on a
fresh volume. Each probe is an authenticated query over TCP through the same service name, port
and credentials the tests use, so it is answered by the same rule the tests will be, and each
exits non-zero on a refused login as well as on an unreachable server, so a wrong password hits
the deadline rather than looping past it. Two shortcuts that look equivalent are not:
`mysqladmin ping` and `pg_isready` do not authenticate, and both take a Unix socket when no host
is given, which answers before networking is up. And `127.0.0.1` is not the tests' path either:
PostgreSQL's `pg_hba.conf` trusts loopback without a password, so only the service name reaches
the `scram-sha-256` rule the tests are held to.

### Use

The devcontainer's environment comes from `containerEnv` in `devcontainer.json`, which Compose
never reads. VS Code injects it for the human container; for an automated stack pass every
entry as `-e KEY=VALUE` on each `docker exec`, or the launched authserver has no configuration,
drops into first-run setup and the integration tier times out with zero tests. `CGO_ENABLED=0`
is among those entries and matters for the build. The data key and the database passwords are
not among them: Compose set those on the container from `.env`, and `docker exec` inherits them.

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
