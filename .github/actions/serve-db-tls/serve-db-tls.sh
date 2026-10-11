#!/usr/bin/env bash
#
# serve-db-tls.sh ENGINE CONTAINER - restart a database job's service container serving TLS from
# the test authority (#502).
#
# GitHub starts service containers before checkout and passes them no command, so a database job's
# server cannot be told at start where a certificate is that does not exist yet. This runs after
# checkout, in the job container, and does what the dev stack's compose file does at start:
#
#   1. generates the authority into /db-tls, the named volume the job container and its service
#      both mount there, with src/.devcontainer/generate-db-tls.sh, the dev stack's own generator;
#   2. copies into the service container the one file that names it, through the Docker socket
#      GitHub mounts into a job container (there is no docker CLI here, and curl is enough):
#        mysql     /etc/mysql/conf.d/tls.cnf, read at every start
#        postgres  /docker-entrypoint-initdb.d/tls.sh, run when the data directory is initialised
#        mssql     /var/opt/mssql/mssql.conf, read at every start
#      each naming the files the dev stack's compose file names on its command line or in its
#      environment;
#   3. restarts the container and waits for its health check. Every service keeps its data on a
#      tmpfs, which a restart empties, so each server comes back as a fresh one: PostgreSQL's
#      init scripts run again, which is the only reason its tls.sh is run at all.
#
# The data tier's TestDatabaseServer_ServesTheTestAuthority is what fails when any of this did not
# take: it connects with the certificate checked against /db-tls/ca.crt.
set -euo pipefail

engine=${1:?usage: serve-db-tls.sh ENGINE CONTAINER}
container=${2:?usage: serve-db-tls.sh ENGINE CONTAINER}
dir=/db-tls
socket=/var/run/docker.sock
deadline_seconds=300

[[ -S "$socket" ]] || { echo "serve-db-tls: no Docker socket at $socket in the job container" >&2; exit 1; }

docker_api() {  # docker_api METHOD PATH [curl arguments...]
    local method=$1 path=$2; shift 2
    curl -sS --fail-with-body --unix-socket "$socket" -X "$method" "$@" "http://localhost$path"
}

"${GITHUB_WORKSPACE:?}/src/.devcontainer/generate-db-tls.sh" "$dir"

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
case "$engine" in
    mysql)
        target=/etc/mysql/conf.d file=tls.cnf owner=0
        cat >"$stage/$file" <<EOF
[mysqld]
ssl_ca=$dir/ca.crt
ssl_cert=$dir/server.crt
ssl_key=$dir/server.key
EOF
        ;;
    postgres)
        target=/docker-entrypoint-initdb.d file=tls.sh owner=0
        cat >"$stage/$file" <<EOF
cat >>"\$PGDATA/postgresql.conf" <<'CONF'
ssl = on
ssl_cert_file = '$dir/server.crt'
ssl_key_file = '$dir/postgres.key'
CONF
EOF
        ;;
    mssql)
        target=/var/opt/mssql file=mssql.conf owner=10001
        cat >"$stage/$file" <<EOF
[network]
tlscert = $dir/server.crt
tlskey = $dir/server.key
EOF
        ;;
    *)
        echo "serve-db-tls: unknown engine $engine; expected mysql, postgres or mssql" >&2
        exit 1
        ;;
esac
echo "serve-db-tls: $target/$file in $engine's container:"
sed 's/^/  /' "$stage/$file"

tar -C "$stage" --owner="$owner" --group=0 --mode=0644 -cf - "$file" |
    docker_api PUT "/containers/$container/archive?path=$target" \
        -H 'Content-Type: application/x-tar' --data-binary @- >/dev/null

docker_api POST "/containers/$container/restart?t=30" >/dev/null
echo "serve-db-tls: restarted $engine's container; waiting for its health check"

started=$SECONDS
while :; do
    state=$(docker_api GET "/containers/$container/json")
    health=$(grep -o '"Health":{"Status":"[a-z]*"' <<<"$state" | cut -d'"' -f6 || true)
    case "$health" in
        healthy)
            echo "serve-db-tls: $engine healthy after $((SECONDS - started))s"
            exit 0
            ;;
        "")
            echo "serve-db-tls: $engine's container declares no health check" >&2
            exit 1
            ;;
    esac
    if grep -q '"Status":"exited"' <<<"$state" || ((SECONDS - started >= deadline_seconds)); then
        echo "serve-db-tls: $engine did not come back healthy (health: $health); its log:" >&2
        docker_api GET "/containers/$container/logs?stdout=1&stderr=1&tail=60" --output - >&2 || true
        exit 1
    fi
    sleep 2
done
