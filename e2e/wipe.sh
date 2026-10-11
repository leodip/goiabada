#!/usr/bin/env bash
# Remove the e2e environment from the VPS: the servers, the database and everything in it.
#
#   e2e/wipe.sh          # the Compose project, its volumes and directory
#   e2e/wipe.sh --all    # also nginx's configuration, the placeholder pages and the certificate
#   e2e/wipe.sh -y       # do not ask first (combine with --all as needed)
#
# DNS records are never touched. e2e/reset.sh builds it again.
set -euo pipefail
# shellcheck source=infra/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/infra/lib.sh"

all=()
yes=false
for arg in "$@"; do
  case "$arg" in
    --all) all=(--all) ;;
    -y | --yes) yes=true ;;
    -h | --help) sed -n '2,9s/^# \{0,1\}//p' "$0"; exit 0 ;;
    *) die "unknown option $arg; see e2e/wipe.sh --help" ;;
  esac
done

require_vps
what="the e2e environment on $E2E_VPS_HOST ($E2E_REMOTE_DIR and its database)"
[[ ${#all[@]} -gt 0 ]] && what+=", its nginx configuration and certificate $E2E_CERT_NAME"

if [[ "$yes" == false ]]; then
  [[ -t 0 ]] || die "not a terminal, so cannot ask: pass -y to wipe without asking"
  read -r -p "This removes $what. Continue? [y/N] " answer
  [[ "$answer" =~ ^[Yy]$ ]] || { echo "Nothing removed."; exit 0; }
fi

"$E2E_DIR/infra/teardown.sh" "${all[@]}"
printf '%sWiped.%s Build it again with e2e/reset.sh\n' "$GREEN" "$RESET"
