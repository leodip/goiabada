#!/usr/bin/env bash
# Wipe the e2e environment and build it again from a release, then check it is reachable.
#
#   e2e/reset.sh            # the latest GitHub release
#   e2e/reset.sh vX.Y.Z     # a given tag, a release after v1.7.0
set -euo pipefail
# shellcheck source=infra/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/infra/lib.sh"

case "${1:-}" in
  -h | --help) sed -n '2,6s/^# \{0,1\}//p' "$0"; exit 0 ;;
esac

tag="${1:-}"
if [[ -z "$tag" ]]; then
  tag="$(latest_release_tag)" || die "could not read the latest release from GitHub; pass the tag of a release after v1.7.0"
  echo "No tag given: using the latest release, ${BOLD}$tag${RESET}."
fi

started=$SECONDS
"$E2E_DIR/infra/prepare.sh" "$tag"
printf '\n%sThe environment runs %s%s (%ds). Next: e2e/test.sh\n' "$GREEN" "$tag" "$RESET" $((SECONDS - started))
