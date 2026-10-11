#!/usr/bin/env bash
#
# generate-db-tls.sh DIR - the test authority the test databases serve TLS from (#502).
#
# Writes into DIR a certificate authority and one server certificate naming mysql-server,
# postgres-server and mssql-server, the names the data and integration tiers dial, so a test
# can connect with the certificate checked against that authority and against the host name:
#
#   ca.crt        the authority's certificate, which the tests trust and nothing else does
#   server.crt    the server certificate, signed by it
#   server.key    its key, readable by every user, for MySQL (uid 999) and SQL Server (uid 10001)
#   postgres.key  the same key owned by the postgres image's postgres user (uid 999) with mode
#                 0600, the only form PostgreSQL loads a key in
#
# The authority's own key is deleted once it has signed, so nothing else can be issued under it.
# Nothing here is a secret and nothing is committed: every stack generates its own, the dev stack
# in its db-tls service before the databases start, CI in a step after checkout before it restarts
# its database container (.github/actions/serve-db-tls).
#
# A run over a set that still verifies, and is not within 30 days of expiring, keeps it, so
# starting the stack again leaves the running servers and the tests agreeing on one authority.
#
# Runs as root, for the chown; needs bash and openssl, which the postgres image and CI's golang
# image both carry.
set -euo pipefail

dir=${1:?usage: generate-db-tls.sh DIR}
names=(mysql-server postgres-server mssql-server)
postgres_uid=999

mkdir -p "$dir"
cd "$dir"

if [[ -f ca.crt && -f server.crt && -f server.key && -f postgres.key ]] &&
    openssl verify -CAfile ca.crt server.crt >/dev/null 2>&1 &&
    openssl x509 -checkend $((30 * 86400)) -noout -in server.crt >/dev/null; then
    echo "generate-db-tls: keeping the test authority in $dir"
    exit 0
fi

work=$(mktemp -d "$dir/.generate.XXXXXX")
trap 'rm -rf "$work"' EXIT

openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
    -subj "/CN=Goiabada test database authority" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "$work/ca.key" -out "$work/ca.crt" 2>/dev/null

san=$(printf 'DNS:%s,' "${names[@]}")
cat >"$work/server.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=${san%,}
EOF

openssl req -new -newkey rsa:2048 -nodes -sha256 \
    -subj "/CN=${names[0]}" \
    -keyout "$work/server.key" -out "$work/server.csr" 2>/dev/null
openssl x509 -req -sha256 -days 3650 -set_serial "0x$(openssl rand -hex 16)" \
    -in "$work/server.csr" -CA "$work/ca.crt" -CAkey "$work/ca.key" \
    -extfile "$work/server.ext" -out "$work/server.crt" 2>/dev/null

cp "$work/server.key" "$work/postgres.key"
chown "$postgres_uid:$postgres_uid" "$work/postgres.key"
chmod 0600 "$work/postgres.key"
chmod 0644 "$work/ca.crt" "$work/server.crt" "$work/server.key"

mv -f "$work/ca.crt" "$work/server.crt" "$work/server.key" "$work/postgres.key" .
echo "generate-db-tls: wrote a new test authority and server certificate to $dir"
