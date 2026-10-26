#!/usr/bin/env bash
# Checks that the e2e environment is up and reachable from this machine: DNS, HTTPS on every host,
# the auth server, the admin console and its sign-in hop to the auth server, the test app, and
# that the VPS runs the release asked for.
#
#   e2e/infra/verify.sh [tag]     # the tag defaults to the one prepare.sh last deployed
#
# Exits non-zero when any check fails.
set -uo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
require_vps

tag="${1:-}"
if [[ -z "$tag" && -f "$STATE_DIR/environment.env" ]]; then
  tag="$(sed -n 's/^E2E_TAG=//p' "$STATE_DIR/environment.env")"
fi
[[ -n "$tag" ]] || die "usage: $0 <release tag>; no e2e/.state/environment.env to read it from"
version="${tag#v}"

passed=0
failed=0
check() { # description command...
  local description="$1" output
  shift
  if output="$("$@" 2>&1)"; then
    printf '  %sPASS%s %s%s\n' "$GREEN" "$RESET" "$description" "${output:+ ($output)}"
    passed=$((passed + 1))
  else
    printf '  %sFAIL%s %s%s\n' "$RED" "$RESET" "$description" "${output:+: $output}"
    failed=$((failed + 1))
  fi
}

http_code() { curl -sS -o /dev/null --max-time 15 -w '%{http_code}' "$@"; }

dns_resolves() { # host
  local a aaaa
  a="$(dns_answers "$1" A | tr '\n' ' ')"
  aaaa="$(dns_answers "$1" AAAA | tr '\n' ' ')"
  [[ -n "$a" ]] || { echo "no A record"; return 1; }
  if [[ "$E2E_VPS_HOST" =~ ^[0-9.]+$ && " $a" != *" $E2E_VPS_HOST "* ]]; then
    echo "A is $a, not $E2E_VPS_HOST"
    return 1
  fi
  [[ -n "$aaaa" ]] || { echo "A $a, no AAAA record"; return 0; }
  echo "A ${a% }, AAAA ${aaaa% }"
}

tls_valid() { # host: curl checks the chain and the name; this adds the expiry
  local host="$1" end
  http_code "https://$host/" >/dev/null || return 1
  end="$(openssl s_client -connect "$host:443" -servername "$host" </dev/null 2>/dev/null |
    openssl x509 -noout -enddate | cut -d= -f2)"
  [[ -n "$end" ]] || { echo "no certificate read"; return 1; }
  if ! openssl s_client -connect "$host:443" -servername "$host" </dev/null 2>/dev/null |
    openssl x509 -noout -checkend $((14 * 86400)) >/dev/null; then
    echo "expires within 14 days: $end"
    return 1
  fi
  echo "until $end"
}

redirects_to_https() { # host
  local location
  location="$(curl -sS -o /dev/null --max-time 15 -w '%{http_code} %{redirect_url}' "http://$1/e2e-probe")"
  [[ "$location" == "301 https://$1/e2e-probe" ]] || { echo "got $location"; return 1; }
}

auth_health() {
  local code
  code="$(http_code "https://$E2E_AUTH_HOST/health")"
  [[ "$code" == 200 ]] || { echo "HTTP $code"; return 1; }
}

auth_discovery() {
  curl -fsS --max-time 15 "https://$E2E_AUTH_HOST/.well-known/openid-configuration" |
    python3 -c '
import json, sys
d = json.load(sys.stdin)
issuer, want = d.get("issuer"), sys.argv[1]
if issuer != want:
    sys.exit(f"issuer is {issuer}, not {want}")
print("issuer", issuer)
' "https://$E2E_AUTH_HOST"
}

auth_jwks() {
  curl -fsS --max-time 15 "https://$E2E_AUTH_HOST/certs" |
    python3 -c '
import json, sys
keys = json.load(sys.stdin).get("keys", [])
if not keys:
    sys.exit("no keys")
print(len(keys), "keys")
'
}

mailpit_answers() {
  ssh_vps "curl -fsS --max-time 10 http://127.0.0.1:$E2E_MAILPIT_PORT/api/v1/info" |
    python3 -c 'import json, sys; print("Mailpit", json.load(sys.stdin)["Version"])'
}

admin_page() {
  local body
  body="$(curl -fsS --max-time 15 "https://$E2E_ADMIN_HOST/")" || return 1
  grep -q "https://$E2E_AUTH_HOST/.well-known/openid-configuration" <<<"$body" ||
    { echo "the page does not link the auth server's discovery document"; return 1; }
}

admin_sign_in_reaches_auth() {
  # The admin console sends a visitor with no session to the auth server's password page: this is
  # the admin console's client, seeded for these URLs, and its redirect URI, end to end.
  local jar result
  jar="$(mktemp)"
  result="$(curl -sS -L -c "$jar" -b "$jar" --max-time 30 -w '\n%{http_code} %{url_effective}' \
    "https://$E2E_ADMIN_HOST/account/profile")"
  rm -f "$jar"
  local last="${result##*$'\n'}"
  [[ "$last" == "200 https://$E2E_AUTH_HOST/auth/pwd?"* ]] || { echo "ended at $last"; return 1; }
  grep -q 'name="password"' <<<"$result" || { echo "no password field at $last"; return 1; }
  echo "ends at /auth/pwd"
}

testapp_page() { # host
  local body
  body="$(curl -fsS --max-time 15 "https://$1/")" || return 1
  grep -q "Goiabada test app" <<<"$body" || { echo "not the test app"; return 1; }
  if grep -q "Not configured yet" <<<"$body"; then
    echo "not configured: $(grep -o 'Not configured yet: [^.]*' <<<"$body" | head -1)"
    return 1
  fi
}

testapp_api_refuses_anonymous() {
  local result
  result="$(curl -sS -o /dev/null --max-time 15 -w '%{http_code} %header{www-authenticate}' "https://$E2E_WEBTEST1_HOST/api/products")" ||
    return 1
  [[ "$result" == "401 Bearer "* ]] || { echo "answered $result"; return 1; }
  echo "401"
}

vps_runs_testapp() {
  local states
  states="$(ssh_vps "cd $(printf %q "$E2E_REMOTE_DIR") && docker compose ps --format '{{.Service}} {{.State}}' testapp1 testapp2")" ||
    { echo "cannot read the Compose project"; return 1; }
  for service in testapp1 testapp2; do
    grep -qx "$service running" <<<"$states" || { echo "$service is not running: $(tr '\n' ';' <<<"$states")"; return 1; }
  done
}

vps_runs_release() {
  local images
  images="$(ssh_vps "cd $(printf %q "$E2E_REMOTE_DIR") && docker compose ps --format '{{.Image}} {{.State}}'")" ||
    { echo "cannot read the Compose project"; return 1; }
  for server in authserver adminconsole; do
    # As the Compose file names it: in full, and pinned, by a release's wizard after 1.8.0 (#686
    # section 5).
    grep -Eqx "(docker\.io/)?leodip/goiabada:$server-$version(@sha256:[0-9a-f]{64})? running" <<<"$images" ||
      { echo "no running leodip/goiabada:$server-$version in: $(tr '\n' ';' <<<"$images")"; return 1; }
  done
  echo "authserver-$version, adminconsole-$version"
}

step "Verifying the e2e environment for $tag"
for host in "${E2E_ALL_HOSTS[@]}"; do check "DNS $host" dns_resolves "$host"; done
for host in "${E2E_ALL_HOSTS[@]}"; do check "HTTPS $host" tls_valid "$host"; done
for host in "${E2E_ALL_HOSTS[@]}"; do check "HTTP redirects to HTTPS on $host" redirects_to_https "$host"; done
check "VPS runs $tag" vps_runs_release
check "auth server /health" auth_health
check "auth server discovery" auth_discovery
check "auth server JWKS" auth_jwks
check "admin console home page" admin_page
check "admin console sign-in reaches the auth server" admin_sign_in_reaches_auth
check "Mailpit on the VPS" mailpit_answers
check "VPS runs the test app" vps_runs_testapp
check "test app on $E2E_WEBTEST1_HOST, configured" testapp_page "$E2E_WEBTEST1_HOST"
check "test app on $E2E_WEBTEST2_HOST, configured" testapp_page "$E2E_WEBTEST2_HOST"
check "test app API refuses a request with no token" testapp_api_refuses_anonymous

echo
if ((failed > 0)); then
  printf '%s%d failed%s, %d passed\n' "$RED" "$failed" "$RESET" "$passed"
  exit 1
fi
printf '%sAll %d checks passed%s\n' "$GREEN" "$passed" "$RESET"
