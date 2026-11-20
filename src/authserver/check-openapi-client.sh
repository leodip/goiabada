#!/bin/bash
#
# check-openapi-client.sh - Generate a Go client from the auth server's OpenAPI document with
# oapi-codegen, then build and vet it (#261).
#
# Usage:
#   ./check-openapi-client.sh [document]
#
# The document defaults to web/openapi.yaml, the one the auth server embeds and serves at
# /openapi.yaml. The docs tell app developers to generate a client from it, and every other check
# on it compares it with this repository's own Go source, so a document that passes them all could
# still generate a client that does not compile. This is the check that runs a generator. It
# passes when oapi-codegen exits 0 and the client it wrote builds and vets; nothing it generates is
# kept. Go's compiler refuses the name collisions and reserved words a structurally typed language
# forgives, which is why the one generator checked is a Go one.
#
# response-type-suffix is set because oapi-codegen's default names the type wrapping each
# operation's answer <OperationId>Response, which dozens of the document's own schemas are already
# called, and the client then fails on every such name. With Result each wrapper has one predictable
# name and no schema is renamed. The docs' API authentication page tells Go callers to set the same
# one; core/guard holds that page to the value below.
#
# CI's Lint job and run-tests.sh's lint tier both run this script, so the two cannot disagree. The
# generator and the runtime library its client imports are fetched and built at the versions
# src/authserver/versions.yaml pins, tools.oapi-codegen and tools.oapi-codegen-runtime, when this
# runs, so it needs no binary installed in the dev container, only Go, yq and the module proxy.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
VERSIONS_FILE="$SCRIPT_DIR/versions.yaml"
DOCUMENT=$(realpath "${1:-$SCRIPT_DIR/web/openapi.yaml}")

for tool in go yq; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "check-openapi-client.sh: $tool is not on PATH; run this inside the dev container" >&2
        exit 1
    fi
done
[ -f "$DOCUMENT" ] || { echo "check-openapi-client.sh: no document at $DOCUMENT" >&2; exit 1; }

pin() {
    local v
    v=$(yq -r ".tools.\"$1\"" "$VERSIONS_FILE")
    if [ -z "$v" ] || [ "$v" = "null" ]; then
        echo "check-openapi-client.sh: tools.$1 is missing from $VERSIONS_FILE" >&2
        exit 1
    fi
    printf '%s' "$v"
}
GO_VERSION=$(pin go)
GENERATOR_VERSION=$(pin oapi-codegen)
RUNTIME_VERSION=$(pin oapi-codegen-runtime)

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# A module of its own, outside the repository's four, so the client's dependencies touch none of
# their go.mod files.
cat > "$work/go.mod" <<EOF
module openapiclientcheck

go $GO_VERSION

require github.com/oapi-codegen/runtime v$RUNTIME_VERSION
EOF

cat > "$work/config.yaml" <<'EOF'
package: client
output: client.gen.go
generate:
  models: true
  client: true
output-options:
  response-type-suffix: Result
EOF

echo "Generating a Go client from $DOCUMENT with oapi-codegen v$GENERATOR_VERSION..."
(cd "$work" && go run "github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v$GENERATOR_VERSION" -config config.yaml "$DOCUMENT")

# tidy fetches what the client imports at the runtime's pin and writes go.sum; it does not move
# the required version.
(cd "$work" && go mod tidy)

# -gcflags=-e reports every compile error, not the first ten, so a failure names every collision.
echo "Building and vetting the generated client..."
if ! (cd "$work" && go build -gcflags=-e ./... && go vet ./...); then
    echo "check-openapi-client.sh: the Go client oapi-codegen generates from $DOCUMENT does not compile" >&2
    exit 1
fi
echo "The Go client generated from $DOCUMENT builds and vets."
