#!/usr/bin/env bash
# Prepares the e2e environment from scratch for one release tag, or for this checkout, then verifies it.
#
#   e2e/infra/prepare.sh vX.Y.Z     # a release after v1.7.0
#   e2e/infra/prepare.sh --source   # the servers and the setup wizard built from this checkout's src/
#
# Runs from your machine and reaches the VPS over SSH as E2E_VPS_USER@E2E_VPS_HOST (see
# e2e/.env.example). It replaces whatever environment ran before: see remote-prepare.sh.
# Leaves e2e/.state/environment.env (URLs, tag, admin email, rate limiter) and
# e2e/.state/admin-password for the steps after it. Then sets up the test app with testapp.sh, which
# adds e2e/.state/testapp.env.
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
require_vps

source_build=false
case "${1:-}" in
  --source) source_build=true ;;
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) die "usage: $0 <release tag, of a release after v1.7.0> | --source" ;;
esac

step "Checking prerequisites"
for cmd in ssh scp curl openssl python3 tar npm git; do
  command -v "$cmd" >/dev/null || die "$cmd is not installed"
done
if [[ "$source_build" == true ]]; then
  # A build of this checkout stands in for a release: the VPS builds both images and the wizard from
  # src/ as it is on disk, under a version naming the commit, and -dirty when src/ has uncommitted
  # changes, so the images can never be taken for a release's.
  tag="e2e-$(git -C "$E2E_DIR/.." rev-parse --short=8 HEAD)" || die "cannot read this checkout's commit"
  [[ -z "$(git -C "$E2E_DIR/.." status --porcelain -- src)" ]] || tag+="-dirty"
  echo "building $tag from $(cd "$E2E_DIR/.." && pwd)/src"
else
  tag="$1"
  curl -fsS -o /dev/null --head "https://github.com/leodip/goiabada/releases/tag/$tag" ||
    die "no GitHub release $tag"
  echo "release $tag exists"
fi
ssh_vps true || die "cannot reach $E2E_VPS_USER@$E2E_VPS_HOST over SSH"
echo "$E2E_VPS_USER@$E2E_VPS_HOST answers over SSH"

step "Checking DNS"
# Every name must reach the VPS before anything asks Let's Encrypt for it.
for host in "${E2E_ALL_HOSTS[@]}"; do
  answers="$(dns_answers "$host" A)"
  if [[ "$E2E_VPS_HOST" =~ ^[0-9.]+$ ]]; then
    grep -qx "$E2E_VPS_HOST" <<<"$answers" || die "$host has A ${answers:-nothing}, not $E2E_VPS_HOST"
  else
    [[ -n "$answers" ]] || die "$host has no A record"
  fi
  echo "$host -> $(tr '\n' ' ' <<<"$answers")$(dns_answers "$host" AAAA | tr '\n' ' ')"
done

step "Generating the admin password"
mkdir -p "$STATE_DIR" && chmod 700 "$STATE_DIR"
rm -f "$STATE_DIR/environment.env" "$STATE_DIR/admin-password" "$STATE_DIR/testapp.env"
(umask 077 && openssl rand -base64 48 | tr -d '/+=\n' | head -c 32 >"$STATE_DIR/admin-password")
echo "written to e2e/.state/admin-password"

step "Preparing the VPS"
stage="$(ssh_vps 'mktemp -d /tmp/goiabada-e2e.XXXXXX')"
scp_vps "$E2E_DIR/infra/remote-prepare.sh" "$E2E_DIR/infra/nginx.conf.template" \
  "$STATE_DIR/admin-password" "$E2E_VPS_USER@$E2E_VPS_HOST:$stage/"
if [[ "$source_build" == true ]]; then
  # The tracked and untracked files under src/ as they are on disk, without what .gitignore ignores
  # (build output, binaries) or what has been deleted and not yet committed.
  archive="$(mktemp)"
  trap 'rm -f "$archive"' EXIT
  (cd "$E2E_DIR/.." && git ls-files -z --cached --others --exclude-standard --deduplicate -- src |
    python3 -c 'import os, sys; sys.stdout.buffer.write(b"".join(f + b"\0" for f in sys.stdin.buffer.read().split(b"\0") if f and os.path.isfile(f)))' |
    tar --null -T - -czf "$archive") || die "could not archive src/"
  scp_vps "$archive" "$E2E_VPS_USER@$E2E_VPS_HOST:$stage/src.tar.gz"
fi
settings="E2E_TAG=$(printf %q "$tag") E2E_SOURCE_BUILD=$source_build"
for name in E2E_AUTH_HOST E2E_ADMIN_HOST E2E_WEBTEST1_HOST E2E_WEBTEST2_HOST E2E_ADMIN_EMAIL \
  E2E_DB E2E_REMOTE_DIR E2E_CERT_NAME E2E_MAILPIT_IMAGE E2E_MAILPIT_PORT; do
  settings+=" $name=$(printf %q "${!name}")"
done
ssh_vps "env $settings bash $stage/remote-prepare.sh $stage; status=\$?; rm -rf $stage; exit \$status" ||
  die "preparing the VPS failed"

cat >"$STATE_DIR/environment.env" <<EOF
E2E_TAG=$tag
E2E_PREPARED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
E2E_AUTH_URL=https://$E2E_AUTH_HOST
E2E_ADMIN_URL=https://$E2E_ADMIN_HOST
E2E_WEBTEST1_URL=https://$E2E_WEBTEST1_HOST
E2E_WEBTEST2_URL=https://$E2E_WEBTEST2_HOST
E2E_ADMIN_EMAIL=$E2E_ADMIN_EMAIL
EOF

# The wizard turned the rate limiter on, as it does for production; the environment rests with it off.
"$E2E_DIR/infra/rate-limiter.sh" off

"$E2E_DIR/infra/testapp.sh"

exec "$E2E_DIR/infra/verify.sh" "$tag"
