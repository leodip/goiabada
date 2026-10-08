#!/usr/bin/env bash
# Asserts what a built docs image answers over HTTP: 200 for a page, 404 with the
# site's 404 page, its search and its sidebar, for any path that is not a built file, a 301 to the relative
# path with the slash for a page asked without it, and UTF-8 text. These answers
# are nginx's, so only a running image shows them.
#
#   site/checks/docs-image.sh <image>
#
# Needs docker and curl. Exits 1 naming every answer that is wrong.

set -euo pipefail

image=${1:?usage: docs-image.sh <image>}

tmp=$(mktemp -d)
container=$(docker run -d --rm -p 127.0.0.1::80 "$image")
cleanup() {
	docker rm -f "$container" >/dev/null 2>&1 || true
	rm -rf "$tmp"
}
trap cleanup EXIT

port=$(docker port "$container" 80/tcp | head -n 1 | sed 's/.*://')
base="http://127.0.0.1:$port"
for _ in $(seq 50); do
	curl -s -o /dev/null "$base/" && break
	sleep 0.2
done

failures=0
fail() {
	echo "FAIL: $*"
	failures=$((failures + 1))
}

# Requests a path, leaving its status, Location and Content-Type in the variables
# of those names and its body in $tmp/body.
request() {
	status=$(curl -s -o "$tmp/body" -D "$tmp/headers" -w '%{http_code}' "$base$1")
	location=$(header Location)
	content_type=$(header Content-Type)
}
header() {
	grep -i "^$1:" "$tmp/headers" | head -n 1 | cut -d: -f2- | sed 's/^ *//; s/\r$//' || true
}
expect() {
	local what=$1 actual=$2 expected=$3
	[ "$actual" = "$expected" ] || fail "$what: got '$actual', want '$expected'"
}
expect_body() {
	local what=$1 text=$2
	grep -qF -- "$text" "$tmp/body" || fail "$what: the body does not contain '$text'"
}

# Any page the image holds below the home page, so the check follows the site's
# pages wherever they move.
page=$(docker exec "$container" sh -c 'cd /usr/share/nginx/html && find . -mindepth 2 -name index.html | sort | head -n 1' |
	sed 's|^\.||; s|index\.html$||')
[ -n "$page" ] || fail "the image holds no page below the home page"

request /
expect "GET / status" "$status" 200
expect "GET / Content-Type" "$content_type" "text/html; charset=utf-8"

request "$page"
expect "GET $page status" "$status" 200
expect "GET $page Content-Type" "$content_type" "text/html; charset=utf-8"

# Relative, so a proxy terminating TLS in front of nginx keeps the reader on https.
request "${page%/}"
expect "GET ${page%/} status" "$status" 301
expect "GET ${page%/} Location" "$location" "$page"

request "${page%/}?q=1"
expect "GET ${page%/}?q=1 status" "$status" 301
expect "GET ${page%/}?q=1 Location" "$location" "$page?q=1"

# /_astro/ is a directory every Astro build writes and no page: neither it nor its
# path without the slash is a page. The /production-deployment/ links are pages
# released binaries print, which moved when the docs were reorganized and are not
# redirected.
for path in /no/such/page/ /no/such/page /getting-started/no-such-page/ /404 /404/ /404.html /index \
	/_astro/ /_astro /_astro/no-such-file.js \
	/production-deployment/monitoring/ /production-deployment/cloudflare-nginx/ \
	/production-deployment/reverse-proxy/; do
	request "$path"
	expect "GET $path status" "$status" 404
	expect "GET $path Content-Type" "$content_type" "text/html; charset=utf-8"
	expect_body "GET $path" "may have moved when the docs were reorganized"
	expect_body "GET $path" "<site-search"
	expect_body "GET $path" 'id="starlight__sidebar"'
	expect_body "GET $path" 'href="/get-started/introduction/"'
	expect_body "GET $path" 'href="/"'
done

# A text file the image is given here, with non-ASCII text, and every text file
# it was built with.
docker exec "$container" sh -c 'printf "Goiabada \342\200\224 autentica\303\247\303\243o\n" > /usr/share/nginx/html/charset-probe.txt'
for path in /charset-probe.txt $(docker exec "$container" sh -c 'cd /usr/share/nginx/html && find . -name "*.txt" ! -name charset-probe.txt' | sed 's|^\.||'); do
	request "$path"
	expect "GET $path status" "$status" 200
	expect "GET $path Content-Type" "$content_type" "text/plain; charset=utf-8"
done

if [ "$failures" -gt 0 ]; then
	echo "$failures answer(s) of $image are wrong"
	exit 1
fi
echo "every answer of $image is right"
