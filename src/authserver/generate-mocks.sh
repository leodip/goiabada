#!/bin/bash

set -e

echo "========================================"
echo "Generating mocks with mockery v3"
echo "========================================"

# The "//go:build !production" constraint on each mock comes from
# template-data.mock-build-tags in the .mockery.yaml files, not from this script.
#
# adminconsole has no .mockery.yaml on purpose: it imports no mocks at all. If it
# ever needs them, give it a config that writes inside adminconsole (for example
# ./internal/handlers/mocks) and never into ../core/. Two configs writing the same
# file means whichever module runs last silently wins.

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SRC_DIR="$( cd "$SCRIPT_DIR/.." && pwd )"

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

echo ""
echo "========================================"
echo "✓ Mock generation completed successfully!"
echo "========================================"
