#!/bin/bash

GOIABADA_VERSION="1.0"
NEW_GO_VERSION="1.23.3" # https://go.dev/dl/
NEW_TAILWIND_VERSION="3.4.15" # https://github.com/tailwindlabs/tailwindcss
NEW_GOLANGCI_LINT_VERSION="1.62.0" # https://github.com/golangci/golangci-lint
NEW_MOCKERY_VERSION="2.48.0" # https://github.com/vektra/mockery
NEW_DAISYUI_VERSION="4.12.14" # https://daisyui.com/
NEW_HUMANIZE_DURATION_VERSION="3.32.1" # https://www.npmjs.com/package/humanize-duration

BASE_DIR="../../"

# Function to update version in files
update_version() {
    local file="$1"
    local old_pattern="$2"
    local new_pattern="$3"
    
    sed -i "s|${old_pattern}|${new_pattern}|g" "$file"
    echo "Updated $file: ${old_pattern} -> ${new_pattern}"
}

# Update GitHub Actions workflow Go version
GITHUB_WORKFLOW_FILE="$BASE_DIR/.github/workflows/build-binaries.yml"
if [ -f "$GITHUB_WORKFLOW_FILE" ]; then
    update_version "$GITHUB_WORKFLOW_FILE" "go-version: '[0-9.]\+'" "go-version: '${NEW_GO_VERSION}'"
fi

# Update build scripts with Goiabada version
BUILD_SCRIPTS=(
    "$BASE_DIR/src/build/build-binaries.sh"
    "$BASE_DIR/src/build/build-docker-images.sh"
    "$BASE_DIR/src/build/push-docker-images.sh"
)

for script in "${BUILD_SCRIPTS[@]}"; do
    if [ -f "$script" ]; then
        update_version "$script" 'VERSION="[0-9.]\+"' "VERSION=\"${GOIABADA_VERSION}\""
    fi
done

# Update .devcontainer/Dockerfile
DEVCONTAINER_DOCKERFILE="$BASE_DIR/.devcontainer/Dockerfile"
if [ -f "$DEVCONTAINER_DOCKERFILE" ]; then
    update_version "$DEVCONTAINER_DOCKERFILE" "go[0-9.]\+\.linux-amd64\.tar\.gz" "go${NEW_GO_VERSION}.linux-amd64.tar.gz"
    update_version "$DEVCONTAINER_DOCKERFILE" "tailwindcss/releases/download/v[0-9.]\+/tailwindcss-linux-x64" "tailwindcss/releases/download/v${NEW_TAILWIND_VERSION}/tailwindcss-linux-x64"
    update_version "$DEVCONTAINER_DOCKERFILE" "golangci-lint@v[0-9.]\+" "golangci-lint@v${NEW_GOLANGCI_LINT_VERSION}"
    update_version "$DEVCONTAINER_DOCKERFILE" "mockery/v2@v[0-9.]\+" "mockery/v2@v${NEW_MOCKERY_VERSION}"
fi

# Update Dockerfile's
for dockerfile in "$BASE_DIR/src/build/Dockerfile-adminconsole" "$BASE_DIR/src/build/Dockerfile-authserver" "$BASE_DIR/src/build/Dockerfile-test"; do
    if [ -f "$dockerfile" ]; then
        update_version "$dockerfile" "golang:[0-9.]\+-alpine" "golang:${NEW_GO_VERSION}-alpine"
        update_version "$dockerfile" "tailwindcss/releases/download/v[0-9.]\+/tailwindcss-linux-x64" "tailwindcss/releases/download/v${NEW_TAILWIND_VERSION}/tailwindcss-linux-x64"
    fi
done

# Update go.mod files
for gomod in "$BASE_DIR/src/adminconsole/go.mod" "$BASE_DIR/src/authserver/go.mod" "$BASE_DIR/src/core/go.mod"; do
    if [ -f "$gomod" ]; then
        update_version "$gomod" "go [0-9.]\+" "go ${NEW_GO_VERSION}"
    fi
done

# Update daisyUI version in HTML files
DAISYUI_FILES=(
    "$BASE_DIR/src/authserver/web/template/layouts/auth_layout.html"
    "$BASE_DIR/src/authserver/web/template/layouts/no_menu_layout.html"
    "$BASE_DIR/src/adminconsole/web/template/layouts/no_menu_layout.html"
    "$BASE_DIR/src/adminconsole/web/template/layouts/menu_layout.html"
)

for html_file in "${DAISYUI_FILES[@]}"; do
    if [ -f "$html_file" ]; then
        update_version "$html_file" "daisyui@[0-9.]\+/dist" "daisyui@${NEW_DAISYUI_VERSION}/dist"
    fi
done

# Update humanize-duration version
MENU_LAYOUT_HTML="$BASE_DIR/src/adminconsole/web/template/layouts/menu_layout.html"
if [ -f "$MENU_LAYOUT_HTML" ]; then
    update_version "$MENU_LAYOUT_HTML" "humanize-duration@[0-9.]\+/" "humanize-duration@${NEW_HUMANIZE_DURATION_VERSION}/"
fi

echo "Version update complete."