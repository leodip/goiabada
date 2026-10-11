#!/usr/bin/env bash
# Runs on the VPS. prepare.sh copies it, the nginx template and the admin password into a staging
# directory there, passes that directory as $1 and the settings in the environment (E2E_*), and
# removes the directory afterwards.
#
# It replaces whatever environment ran before, from scratch: the Compose project and its volumes go,
# the release's own setup wizard writes new Compose files, and nginx is pointed at the new servers.
# The certificate is the one thing kept, and requested only when it is missing or does not cover
# the four hosts.
set -euo pipefail

stage="$1"
log()  { printf '    [vps] %s\n' "$*"; }
fail() { printf '    [vps] ERROR %s\n' "$*" >&2; exit 1; }

version="${E2E_TAG#v}"
project="$(basename "$E2E_REMOTE_DIR")"
hosts=("$E2E_AUTH_HOST" "$E2E_ADMIN_HOST" "$E2E_WEBTEST1_HOST" "$E2E_WEBTEST2_HOST")

for cmd in docker nginx certbot curl sha256sum openssl ss; do
  command -v "$cmd" >/dev/null || fail "$cmd is not installed"
done
docker compose version >/dev/null 2>&1 || fail "the docker compose plugin is not installed"

case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) fail "unsupported architecture $(uname -m)" ;;
esac

# --- 1. Remove the previous environment -----------------------------------------------------------

log "removing the previous environment ($project), its containers and volumes"
if [[ -f "$E2E_REMOTE_DIR/docker-compose.yml" ]]; then
  (cd "$E2E_REMOTE_DIR" && docker compose down -v --remove-orphans --timeout 30 >/dev/null 2>&1) || true
fi
# Also when the directory is gone but the project is not.
docker compose -p "$project" down -v --remove-orphans --timeout 30 >/dev/null 2>&1 || true
docker volume ls -q --filter "label=com.docker.compose.project=$project" | xargs -r docker volume rm >/dev/null
rm -rf "$E2E_REMOTE_DIR"

# The generated Compose files publish the servers on 127.0.0.1:9090 and 9091.
for port in 9090 9091; do
  if ss -ltnH "sport = :$port" | grep -q .; then
    fail "port $port is taken by something outside $project: $(ss -ltnpH "sport = :$port")"
  fi
done

# --- 2. Generate the Compose files with the release's setup wizard --------------------------------

mkdir -m 700 "$E2E_REMOTE_DIR"
cd "$E2E_REMOTE_DIR"

wizard="goiabada-setup-linux-$arch"
base="https://github.com/leodip/goiabada/releases/download/$E2E_TAG"
log "downloading $wizard from release $E2E_TAG"
curl -fsSLO "$base/$wizard" || fail "release $E2E_TAG has no $wizard"
curl -fsSLO "$base/checksums.txt" || fail "release $E2E_TAG has no checksums.txt"
grep " $wizard\$" checksums.txt | sha256sum -c --quiet - || fail "$wizard does not match checksums.txt"
chmod +x "$wizard"
log "$("./$wizard" --version)"

log "running the setup wizard: production, $E2E_DB, rate limiter $E2E_RATE_LIMITER"
umask 077
if ! "./$wizard" --no-color --type production --db "$E2E_DB" \
  --auth-url "https://$E2E_AUTH_HOST" --admin-url "https://$E2E_ADMIN_HOST" \
  --admin-email "$E2E_ADMIN_EMAIL" --admin-password-file "$stage/admin-password" \
  --rate-limiter="$E2E_RATE_LIMITER" >wizard.log 2>&1; then
  cat wizard.log >&2
  fail "the setup wizard failed"
fi
rm -f "$stage/admin-password"

for server in authserver adminconsole; do
  grep -q "image: leodip/goiabada:$server-$version\$" docker-compose.yml ||
    fail "docker-compose.yml does not name leodip/goiabada:$server-$version"
done

# Mailpit, beside the wizard's two files rather than in them: the override holds the secrets and is the
# wizard's. COMPOSE_FILE in .env makes every docker compose command run in this directory take all
# three, the scripts' and a person's alike. The auth server reaches it as mailpit:1025; its API listens
# on the VPS's loopback, for the tests' SSH tunnel.
log "adding Mailpit ($E2E_MAILPIT_IMAGE), its API on 127.0.0.1:$E2E_MAILPIT_PORT"
cat >mailpit.yml <<EOF
services:
  mailpit:
    image: $E2E_MAILPIT_IMAGE
    restart: unless-stopped
    environment:
      MP_SMTP_AUTH_ACCEPT_ANY: "true"
      MP_SMTP_AUTH_ALLOW_INSECURE: "true"
      MP_MAX_MESSAGES: "5000"
    ports:
      - "127.0.0.1:$E2E_MAILPIT_PORT:8025"
    networks:
      - goiabada-network
EOF
printf 'COMPOSE_FILE=docker-compose.yml:docker-compose.override.yml:mailpit.yml\n' >.env

# --- 3. Start it ------------------------------------------------------------------------------------

log "pulling images"
docker compose pull --quiet >pull.log 2>&1 || { cat pull.log >&2; fail "docker compose pull failed"; }

log "starting"
# On a fresh volume the first up -d can fail: PostgreSQL's healthcheck passes against the image's
# init server, and the auth server's first connection is refused (#551). The auth server restarts on
# its own; a second up -d starts the admin console.
for attempt in 1 2 3; do
  if docker compose up -d >up.log 2>&1; then
    break
  fi
  if ((attempt == 3)); then
    cat up.log >&2
    fail "docker compose up -d failed three times"
  fi
  log "WARN docker compose up -d failed (attempt $attempt), retrying in 10s: $(tail -1 up.log)"
  sleep 10
done

wait_for() { # name url
  for _ in $(seq 1 60); do
    if curl -fsS -o /dev/null --max-time 5 "$2" 2>/dev/null; then
      log "$1 answers on $2"
      return 0
    fi
    sleep 5
  done
  docker compose ps -a >&2
  docker compose logs --no-color --tail 50 >&2
  fail "$1 did not answer on $2 within 5 minutes"
}
wait_for "the auth server" http://127.0.0.1:9090/health
wait_for "the admin console" http://127.0.0.1:9091/
wait_for "Mailpit" "http://127.0.0.1:$E2E_MAILPIT_PORT/api/v1/info"

docker compose ps --format '{{.Service}}: {{.Image}} ({{.Status}})' | sed 's/^/    [vps]   /'

# --- 4. nginx and the certificate -------------------------------------------------------------------

umask 022
www=/var/www/goiabada-e2e
rm -rf "$www"
for host in "$E2E_WEBTEST1_HOST" "$E2E_WEBTEST2_HOST"; do
  mkdir -p "$www/$host"
  printf '<!doctype html>\n<html><head><meta charset="utf-8"><title>%s</title></head>\n<body><h1>Hello from %s</h1></body></html>\n' \
    "$host" "$host" >"$www/$host/index.html"
done

conf=/etc/nginx/conf.d/goiabada-e2e.conf
rendered="$(sed -e "s/__AUTH_HOST__/$E2E_AUTH_HOST/g" -e "s/__ADMIN_HOST__/$E2E_ADMIN_HOST/g" \
  -e "s/__WEBTEST1_HOST__/$E2E_WEBTEST1_HOST/g" -e "s/__WEBTEST2_HOST__/$E2E_WEBTEST2_HOST/g" \
  -e "s/__CERT_NAME__/$E2E_CERT_NAME/g" "$stage/nginx.conf.template")"

reload_nginx() {
  nginx -t -q 2>/dev/null || { nginx -t; fail "nginx refused $conf"; }
  systemctl reload nginx
}

cert="/etc/letsencrypt/live/$E2E_CERT_NAME/cert.pem"
covered=true
if [[ -f "$cert" ]]; then
  sans="$(openssl x509 -in "$cert" -noout -ext subjectAltName)"
  for host in "${hosts[@]}"; do
    grep -qE "DNS:$host(,|\$)" <<<"$sans" || covered=false
  done
else
  covered=false
fi

if [[ "$covered" == false ]]; then
  log "requesting certificate $E2E_CERT_NAME for ${hosts[*]}"
  # The full configuration names a certificate that does not exist yet, so serve the HTTP block
  # alone, which answers Let's Encrypt's challenge, until it does.
  printf '%s\n' "$rendered" | sed -n '/^# HTTP:/,$p' >"$conf"
  reload_nginx
  domains=()
  for host in "${hosts[@]}"; do domains+=(-d "$host"); done
  certbot certonly --webroot -w /var/www/certbot --non-interactive --quiet \
    --cert-name "$E2E_CERT_NAME" "${domains[@]}" || fail "certbot could not issue $E2E_CERT_NAME"
else
  log "certificate $E2E_CERT_NAME covers the four hosts, $(openssl x509 -in "$cert" -noout -enddate)"
fi

printf '%s\n' "$rendered" >"$conf"
reload_nginx
log "nginx serves ${hosts[*]}"
