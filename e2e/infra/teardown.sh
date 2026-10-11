#!/usr/bin/env bash
# Removes the e2e environment from the VPS.
#
#   e2e/infra/teardown.sh          # the Compose project, its volumes and directory
#   e2e/infra/teardown.sh --all    # also the nginx configuration, the static pages and the certificate
#
# DNS records are left alone.
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
require_vps

all=false
case "${1:-}" in
  "") ;;
  --all) all=true ;;
  *) die "usage: $0 [--all]" ;;
esac

dir="$(printf %q "$E2E_REMOTE_DIR")"
project="$(basename "$E2E_REMOTE_DIR")"

step "Removing the Compose project $project"
ssh_vps "set -e
  if [ -f $dir/docker-compose.yml ]; then (cd $dir && docker compose down -v --remove-orphans --timeout 30); fi
  docker compose -p $project down -v --remove-orphans --timeout 30 >/dev/null 2>&1 || true
  rm -rf $dir"

if [[ "$all" == true ]]; then
  step "Removing nginx configuration, static pages and certificate $E2E_CERT_NAME"
  ssh_vps "set -e
    rm -f /etc/nginx/conf.d/goiabada-e2e.conf
    nginx -t -q && systemctl reload nginx
    rm -rf /var/www/goiabada-e2e
    if [ -d /etc/letsencrypt/live/$E2E_CERT_NAME ]; then certbot delete --non-interactive --cert-name $E2E_CERT_NAME; fi"
fi

rm -f "$STATE_DIR/environment.env" "$STATE_DIR/admin-password"
echo "done"
