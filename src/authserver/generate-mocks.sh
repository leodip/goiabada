#!/bin/bash

set -e

echo "========================================"
echo "Generating mocks with mockery v3"
echo "========================================"

# Function to add build tags to generated mock files
add_build_tags() {
    local mock_dir=$1
    echo "Adding build tags to mocks in: $mock_dir"

    if [ ! -d "$mock_dir" ]; then
        echo "Warning: Directory not found: $mock_dir"
        return
    fi

    find "$mock_dir" -type f -name "*_mock.go" | while read -r file; do
        if ! grep -q "//go:build !production" "$file"; then
            # Add build tag at the beginning of the file
            sed -i '1i//go:build !production\n' "$file"
            echo "  ✓ Added build tag to: $file"
        fi
    done
}

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

# Generate mocks for adminconsole
echo ""
echo "2. Generating adminconsole mocks..."
echo "------------------------------------"
cd "$SRC_DIR/adminconsole"
if [ -f .mockery.yaml ]; then
    mockery
    echo "  ✓ Adminconsole mocks generated"
else
    echo "  ✗ Error: .mockery.yaml not found in adminconsole/"
    exit 1
fi

# Generate mocks for core
echo ""
echo "3. Generating core mocks..."
echo "------------------------------------"
cd "$SRC_DIR/core"
if [ -f .mockery.yaml ]; then
    mockery
    echo "  ✓ Core mocks generated"
else
    echo "  ✗ Error: .mockery.yaml not found in core/"
    exit 1
fi

# Add build tags to all generated mocks
echo ""
echo "4. Adding build tags..."
echo "------------------------------------"
add_build_tags "$SRC_DIR/core/validators/mocks"
add_build_tags "$SRC_DIR/core/oauth/mocks"
add_build_tags "$SRC_DIR/core/communication/mocks"
add_build_tags "$SRC_DIR/core/handlerhelpers/mocks"
add_build_tags "$SRC_DIR/core/audit/mocks"
add_build_tags "$SRC_DIR/core/user/mocks"
add_build_tags "$SRC_DIR/core/otp/mocks"
add_build_tags "$SRC_DIR/core/inputsanitizer/mocks"
add_build_tags "$SRC_DIR/core/data/mocks"
add_build_tags "$SRC_DIR/core/sessionstore/mocks"
add_build_tags "$SRC_DIR/adminconsole/internal/tcputils/mocks"

echo ""
echo "========================================"
echo "✓ Mock generation completed successfully!"
echo "========================================"
