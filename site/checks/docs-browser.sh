#!/usr/bin/env bash
# Runs the site's browser tests (browser/*.spec.mjs) against a built docs image: its pages work under
# their Content-Security-Policy, and nothing reaches Google before the visitor accepts Analytics.
# What scripts do at run time shows only in a browser, against the pages nginx serves.
#
#   site/checks/docs-browser.sh <image> [playwright args]
#
# Needs docker, the site's dependencies (npm ci in site/) and Playwright's Chromium
# (npx playwright install chromium). Exits non-zero when a test fails; the report is in
# site/playwright-report/.

set -euo pipefail

image=${1:?usage: docs-browser.sh <image> [playwright args]}
shift
site=$(cd "$(dirname "$0")/.." && pwd)

container=$(docker run -d --rm -p 127.0.0.1::80 "$image")
trap 'docker rm -f "$container" >/dev/null 2>&1 || true' EXIT

port=$(docker port "$container" 80/tcp | head -n 1 | sed 's/.*://')
base="http://127.0.0.1:$port"
for _ in $(seq 50); do
	curl -s -o /dev/null "$base/" && break
	sleep 0.2
done

cd "$site"
DOCS_URL=$base npx playwright test "$@"
