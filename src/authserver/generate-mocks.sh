#!/bin/bash

# Base mock directory
MOCK_DIR="../mocks"

# Function to process a mock group
process_group() {
    local group_name=$1
    local dest_dir=$2
    shift 2
    local files=("$@")

    echo "Processing group: $group_name"
    mkdir -p "$dest_dir"
    for file in "${files[@]}"; do
        if [ -f "$file" ]; then
            mv "$file" "$dest_dir/"
            sed -i "s/package mocks/package mocks_$group_name/g" "$dest_dir/$(basename "$file")"
            echo "Moved and updated: $file -> $dest_dir/$(basename "$file")"
        else
            echo "Warning: File not found: $file"
        fi
    done
}

# Generate mocks
echo "Generating mocks..."
mockery --dir=. --all --keeptree --output="$MOCK_DIR"
(cd ../adminconsole && mockery --dir=. --all --keeptree --output="$MOCK_DIR")
(cd ../core && mockery --dir=. --all --keeptree --output="$MOCK_DIR")

# Add build tags and rename files
echo "Adding build tags and renaming files..."
find "$MOCK_DIR" -type f -name "*.go" | while read -r file; do
    if ! grep -q "//go:build !production" "$file"; then
        sed -i '1i//go:build !production\n' "$file"
        echo "Added build tag to: $file"
    fi
    dir=$(dirname "$file")
    base=$(basename "$file" .go)
    if [[ $base != *_mock ]]; then
        new_name=$(echo "$base" | sed -r 's/([a-z0-9])([A-Z])/\1_\L\2/g' | tr '[:upper:]' '[:lower:]')_mock.go
        mv "$file" "$dir/$new_name"
        echo "Renamed: $file -> $dir/$new_name"
    fi
done

# Process mock groups
echo "Processing mock groups..."

process_group "data" "../core/data/mocks" \
    "$MOCK_DIR/data/database_mock.go"

process_group "validator" "../core/validators/mocks" \
    "$MOCK_DIR/internal_/handlers/address_validator_mock.go" \
    "$MOCK_DIR/internal_/handlers/authorize_validator_mock.go" \
    "$MOCK_DIR/internal_/handlers/email_validator_mock.go" \
    "$MOCK_DIR/internal_/handlers/identifier_validator_mock.go" \
    "$MOCK_DIR/internal_/handlers/password_validator_mock.go" \
    "$MOCK_DIR/internal_/handlers/phone_validator_mock.go" \
    "$MOCK_DIR/internal_/handlers/profile_validator_mock.go" \
    "$MOCK_DIR/internal_/handlers/token_validator_mock.go"

process_group "audit" "../core/audit/mocks" \
    "$MOCK_DIR/internal_/handlers/audit_logger_mock.go"

process_group "handler_helpers" "../core/handlerhelpers/mocks" \
    "$MOCK_DIR/internal_/handlers/auth_helper_mock.go" \
    "$MOCK_DIR/internal_/handlers/http_helper_mock.go"

process_group "oauth" "../core/oauth/mocks" \
    "$MOCK_DIR/internal_/handlers/code_issuer_mock.go" \
    "$MOCK_DIR/internal_/handlers/token_issuer_mock.go" \
    "$MOCK_DIR/internal_/handlers/token_exchanger_mock.go" \
    "$MOCK_DIR/internal_/handlers/token_parser_mock.go"

process_group "communication" "../core/communication/mocks" \
    "$MOCK_DIR/internal_/handlers/email_sender_mock.go" \
    "$MOCK_DIR/internal_/handlers/sms_sender_mock.go"

process_group "inputsanitizer" "../core/inputsanitizer/mocks" \
    "$MOCK_DIR/internal_/handlers/input_sanitizer_mock.go"

process_group "otp" "../core/otp/mocks" \
    "$MOCK_DIR/internal_/handlers/otp_secret_generator_mock.go"

process_group "user" "../core/user/mocks" \
    "$MOCK_DIR/internal_/handlers/permission_checker_mock.go" \
    "$MOCK_DIR/internal_/handlers/user_creator_mock.go" \
    "$MOCK_DIR/internal_/handlers/user_session_manager_mock.go"

process_group "tcputils" "../adminconsole/internal/tcputils/mocks" \
    "$MOCK_DIR/internal_/handlers/tcpconnection_tester_mock.go"

echo "Cleaning up empty directories..."
rm -rf $MOCK_DIR

echo "Mock generation completed."