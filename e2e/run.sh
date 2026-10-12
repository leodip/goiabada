#!/usr/bin/env bash
# Everything from scratch: rebuild the environment from a release, then run the whole suite.
#
#   e2e/run.sh                       # the latest GitHub release
#   e2e/run.sh vX.Y.Z                # a given tag, a release after v1.7.0
#   e2e/run.sh vX.Y.Z --headed       # anything after the tag goes to Playwright
set -euo pipefail
here="$(dirname "${BASH_SOURCE[0]}")"

case "${1:-}" in
  -h | --help) sed -n '2,7s/^# \{0,1\}//p' "$0"; exit 0 ;;
  v[0-9]*) tag="$1"; shift ;;
  *) tag="" ;;
esac

"$here/reset.sh" ${tag:+"$tag"}
exec "$here/test.sh" "$@"
