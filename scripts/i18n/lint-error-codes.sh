#!/usr/bin/env bash
#
# Lint i18n error code parity:
#   - Every Err* constant whose value is a "validator.*" or "handler.*"
#     catalog key in src/core/i18n/error_codes.go must have a matching
#     entry in src/core/i18n/catalogs/active.en.toml.
#   - Every "validator.*" / "handler.*" key in active.en.toml must have
#     a code constant in error_codes.go.
#
# Exits 0 on parity, 1 on any mismatch. Diagnostics go to stderr.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CODES_GO="$ROOT/src/core/i18n/error_codes.go"
CATALOG="$ROOT/src/core/i18n/catalogs/active.en.toml"

if [[ ! -f "$CODES_GO" ]]; then
    echo "lint-error-codes: $CODES_GO not found" >&2
    exit 2
fi
if [[ ! -f "$CATALOG" ]]; then
    echo "lint-error-codes: $CATALOG not found" >&2
    exit 2
fi

# Extract code-constant values that point at validator.*/handler.* keys.
# Match lines like:   ErrCodeFoo = "validator.bar.baz"
codes_from_go="$(grep -oE '"(validator|handler)\.[a-zA-Z0-9_.]+"' "$CODES_GO" | tr -d '"' | sort -u)"

# Extract validator.*/handler.* keys defined in the English catalog.
# Match lines like:   "validator.bar.baz" = "..."
keys_from_catalog="$(grep -oE '^"(validator|handler)\.[a-zA-Z0-9_.]+"' "$CATALOG" | tr -d '"' | sort -u)"

missing_in_catalog="$(comm -23 <(echo "$codes_from_go") <(echo "$keys_from_catalog"))"
missing_in_codes="$(comm -13 <(echo "$codes_from_go") <(echo "$keys_from_catalog"))"

status=0

if [[ -n "$missing_in_catalog" ]]; then
    echo "lint-error-codes: code constants without a matching catalog entry:" >&2
    while IFS= read -r line; do
        echo "  - $line" >&2
    done <<< "$missing_in_catalog"
    status=1
fi

if [[ -n "$missing_in_codes" ]]; then
    echo "lint-error-codes: catalog entries without a matching code constant:" >&2
    while IFS= read -r line; do
        echo "  - $line" >&2
    done <<< "$missing_in_codes"
    status=1
fi

if [[ $status -eq 0 ]]; then
    count_codes="$(wc -l <<< "$codes_from_go" | tr -d ' ')"
    count_keys="$(wc -l <<< "$keys_from_catalog" | tr -d ' ')"
    echo "lint-error-codes: ok ($count_codes codes, $count_keys catalog entries)"
fi

exit $status
