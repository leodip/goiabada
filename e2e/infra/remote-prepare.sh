#!/usr/bin/env bash
# Runs on the VPS. prepare.sh copies it, the nginx template and the admin password into a staging
# directory there, passes that directory as $1 and the settings in the environment (E2E_*), and
# removes the directory afterwards. For a build of a checkout (E2E_SOURCE_BUILD=true) it copies the
# checkout's src/ there too, as src.tar.gz.
#
# It replaces whatever environment ran before, from scratch: the Compose project and its volumes go,
# the release's own setup wizard writes new Compose files, and nginx is pointed at the new servers.
# For a build of a checkout, the wizard and both images are built here from that source first.
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

# The generated Compose files publish the servers on 127.0.0.1:9090 and 9091, and testapp.sh the test
# app on 9092 and 9093.
for port in 9090 9091 9092 9093; do
  if ss -ltnH "sport = :$port" | grep -q .; then
    fail "port $port is taken by something outside $project: $(ss -ltnpH "sport = :$port")"
  fi
done

# --- 2. Generate the Compose files with the release's setup wizard --------------------------------

mkdir -m 700 "$E2E_REMOTE_DIR"
cd "$E2E_REMOTE_DIR"

wizard="goiabada-setup-linux-$arch"
if [[ "${E2E_SOURCE_BUILD:-false}" == true ]]; then
  # What a release ships, built from the checkout's source as the release builds it: both servers from
  # their Dockerfiles with the same build arguments, and the wizard with the same tag and -X values,
  # imageTag naming the images built here. The images are labelled so the next build, and
  # teardown.sh, remove them without touching anyone else's.
  tar -xzf "$stage/src.tar.gz" -C "$stage"
  src="$stage/src"
  commit="${E2E_TAG#e2e-}"
  for server in authserver adminconsole; do
    log "building leodip/goiabada:$server-$version"
    if ! docker build --label goiabada-e2e=server -f "$src/build/Dockerfile-$server" \
      -t "leodip/goiabada:$server-$version" --build-arg "version=$version" \
      --build-arg "buildDate=$(date -u +%Y-%m-%d)" --build-arg "gitCommit=${commit%-dirty}" "$src" \
      >"$stage/build-$server.log" 2>&1; then
      tail -40 "$stage/build-$server.log" >&2
      fail "the $server image did not build"
    fi
  done
  docker image ls --filter label=goiabada-e2e=server --format '{{.Repository}}:{{.Tag}}' |
    { grep -v -e "-$version\$" -e '<none>' || true; } | xargs -r docker image rm >/dev/null
  docker image prune -f --filter label=goiabada-e2e=server >/dev/null

  golang="$(sed -n 's/^FROM \(golang:[^ ]*\) AS build$/\1/p' "$src/build/Dockerfile-authserver")"
  [[ -n "$golang" ]] || fail "build/Dockerfile-authserver names no golang image"
  log "building $wizard with $golang"
  if ! docker build --output "type=local,dest=$E2E_REMOTE_DIR" --build-arg "version=$version" \
    -f - "$src" >"$stage/build-wizard.log" 2>&1 <<EOF
FROM $golang AS build
COPY core /src/core
COPY cmd/goiabada-setup /src/cmd/goiabada-setup
WORKDIR /src/cmd/goiabada-setup
ARG version
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \\
  CGO_ENABLED=0 go build -buildvcs=false -tags=production \\
  -ldflags "-w -X main.version=\${version} -X main.imageTag=\${version}" -o /out/$wizard .
FROM scratch
COPY --from=build /out/$wizard /
EOF
  then
    tail -40 "$stage/build-wizard.log" >&2
    fail "the setup wizard did not build"
  fi
else
  base="https://github.com/leodip/goiabada/releases/download/$E2E_TAG"
  log "downloading $wizard from release $E2E_TAG"
  curl -fsSLO "$base/$wizard" || fail "release $E2E_TAG has no $wizard"
  curl -fsSLO "$base/checksums.txt" || fail "release $E2E_TAG has no checksums.txt"
  grep " $wizard\$" checksums.txt | sha256sum -c --quiet - || fail "$wizard does not match checksums.txt"
fi
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
# Not the two servers' for a build of a checkout: they were built here, and no registry has them.
pull=()
if [[ "${E2E_SOURCE_BUILD:-false}" == true ]]; then
  mapfile -t pull < <(docker compose config --services | grep -vx -e goiabada-authserver -e goiabada-adminconsole)
fi
docker compose pull --quiet "${pull[@]}" >pull.log 2>&1 || { cat pull.log >&2; fail "docker compose pull failed"; }

log "starting"
# The environment targets releases after v1.7.0, whose wizard probes PostgreSQL over TCP, so a failed
# first up -d is a defect (#551) and fails the build at once, printing its output.
docker compose up -d >up.log 2>&1 || { cat up.log >&2; fail "docker compose up -d failed"; }

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
# The placeholder pages the test app hosts served before the test app was deployed there.
rm -rf /var/www/goiabada-e2e

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
