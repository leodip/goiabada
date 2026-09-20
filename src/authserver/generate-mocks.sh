#!/bin/bash

set -e

echo "========================================"
echo "Generating mocks with mockery v3"
echo "========================================"

# The "//go:build !production" constraint on each mock comes from
# template-data.mock-build-tags in the .mockery.yaml files, not from this script.
#
# Three modules have a config and each writes only inside itself. That was not true
# until #385: authserver/.mockery.yaml wrote the HttpHelper mock into
# ../core/handlerhelpers/mocks and both applications imported it from there, which the
# renderer split ended -- each module now declares its own HttpHelper port and
# generates its own mock beside its own renderer. Never add a config that writes a file
# another one writes; whichever module runs last silently wins, with nothing saying so.
# adminconsole gained its config in #385, when the JWT session middleware and its two
# mocked ports moved there out of core/middleware.

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SRC_DIR="$( cd "$SCRIPT_DIR/.." && pwd )"

# Refuse any mockery but the pinned one.
#
# Every generated mock carries the generator's version in its header, inlined from
# src/mockery-header.txt, which ./version-manager.sh update writes from
# versions.yaml. That line is only worth reading if the generator that ran is the
# one it names, so a mismatch stops here rather than stamping a version that did
# not write the file.
#
# #338 is what this is for. Sixteen committed mocks predated the mockery
# versions.yaml pins, so this script was not idempotent against its own tree: any
# change that regenerated mocks for its own reasons collected sixteen files of
# unrelated churn, and the drift was discovered by whoever happened to regenerate
# rather than by anything that checks. It is now checked in three places -- here,
# every module's unit tier through testutil.AssertGeneratedMocksArePinned, and the
# Lint job in .github/workflows/check.yml, which runs this script and fails on a
# dirty tree.
echo ""
echo "Checking the generator is the pinned version..."
echo "------------------------------------"
if ! command -v mockery > /dev/null 2>&1; then
    echo "  ✗ Error: mockery is not on PATH; run this inside the dev container, which installs the version versions.yaml pins"
    exit 1
fi
if ! command -v yq > /dev/null 2>&1; then
    echo "  ✗ Error: yq is required to read tools.mockery from versions.yaml"
    exit 1
fi
PINNED_MOCKERY="$( yq -r '.tools.mockery' "$SCRIPT_DIR/versions.yaml" )"
if [ -z "$PINNED_MOCKERY" ] || [ "$PINNED_MOCKERY" = "null" ]; then
    echo "  ✗ Error: tools.mockery is missing from $SCRIPT_DIR/versions.yaml"
    exit 1
fi
# `mockery version` prints a leading v, versions.yaml does not.
INSTALLED_MOCKERY="$( mockery version | head -1 )"
INSTALLED_MOCKERY="${INSTALLED_MOCKERY#v}"
if [ "$INSTALLED_MOCKERY" != "$PINNED_MOCKERY" ]; then
    echo "  ✗ Error: mockery on PATH is $INSTALLED_MOCKERY, but versions.yaml pins $PINNED_MOCKERY."
    echo "    Generating now would write mocks whose header names a version that did not produce them."
    echo "    Run ./version-manager.sh update and rebuild the dev container, so the installed"
    echo "    generator and the pin agree, then run this again."
    exit 1
fi
echo "  ✓ mockery $INSTALLED_MOCKERY matches the versions.yaml pin"

# Generate mocks for authserver
echo ""
echo "1. Generating authserver mocks..."
echo "------------------------------------"
cd "$SRC_DIR/authserver"
if [ -f .mockery.yaml ]; then
    mockery
    echo "  ✓ Authserver mocks generated"
else
    echo "  ✗ Error: .mockery.yaml not found in authserver/"
    exit 1
fi

# Generate mocks for core
echo ""
echo "2. Generating core mocks..."
echo "------------------------------------"
cd "$SRC_DIR/core"
if [ -f .mockery.yaml ]; then
    mockery
    echo "  ✓ Core mocks generated"
else
    echo "  ✗ Error: .mockery.yaml not found in core/"
    exit 1
fi

# Generate mocks for adminconsole
echo ""
echo "3. Generating adminconsole mocks..."
echo "------------------------------------"
cd "$SRC_DIR/adminconsole"
if [ -f .mockery.yaml ]; then
    mockery
    echo "  ✓ Adminconsole mocks generated"
else
    echo "  ✗ Error: .mockery.yaml not found in adminconsole/"
    exit 1
fi

echo ""
echo "========================================"
echo "✓ Mock generation completed successfully!"
echo "========================================"
