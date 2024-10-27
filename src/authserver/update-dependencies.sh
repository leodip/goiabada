#!/bin/bash

# Set the new versions here
NEW_GO_VERSION="1.23.2"  
NEW_TAILWIND_VERSION="3.4.14"
NEW_GOLANGCI_LINT_VERSION="1.61.0"
NEW_MOCKERY_VERSION="2.46.3" 
NEW_DAISYUI_VERSION="4.12.13"
NEW_HUMANIZE_DURATION_VERSION="3.32.1" 

BASE_DIR="../"

# Function to update version in files
update_version() {
    local file="$1"
    local old_pattern="$2"
    local new_pattern="$3"
    
    sed -i "s|${old_pattern}|${new_pattern}|g" "$file"
    echo "Updated $file: ${old_pattern} -> ${new_pattern}"
}

# Update .devcontainer/Dockerfile
DEVCONTAINER_DOCKERFILE="$BASE_DIR/.devcontainer/Dockerfile"
if [ -f "$DEVCONTAINER_DOCKERFILE" ]; then
    update_version "$DEVCONTAINER_DOCKERFILE" "go[0-9.]\+\.linux-amd64\.tar\.gz" "go${NEW_GO_VERSION}.linux-amd64.tar.gz"
    update_version "$DEVCONTAINER_DOCKERFILE" "tailwindcss/releases/download/v[0-9.]\+/tailwindcss-linux-x64" "tailwindcss/releases/download/v${NEW_TAILWIND_VERSION}/tailwindcss-linux-x64"
    update_version "$DEVCONTAINER_DOCKERFILE" "golangci-lint@v[0-9.]\+" "golangci-lint@v${NEW_GOLANGCI_LINT_VERSION}"
    update_version "$DEVCONTAINER_DOCKERFILE" "mockery/v2@v[0-9.]\+" "mockery/v2@v${NEW_MOCKERY_VERSION}"
fi

# Update docker/Dockerfile and docker/Dockerfile-test
for dockerfile in "$BASE_DIR/docker/Dockerfile" "$BASE_DIR/docker/Dockerfile-test"; do
    if [ -f "$dockerfile" ]; then
        update_version "$dockerfile" "golang:[0-9.]\+-alpine" "golang:${NEW_GO_VERSION}-alpine"
        update_version "$dockerfile" "tailwindcss/releases/download/v[0-9.]\+/tailwindcss-linux-x64" "tailwindcss/releases/download/v${NEW_TAILWIND_VERSION}/tailwindcss-linux-x64"
    fi
done

# Update go.mod files
for gomod in "$BASE_DIR/adminconsole/go.mod" "$BASE_DIR/authserver/go.mod" "$BASE_DIR/core/go.mod"; do
    if [ -f "$gomod" ]; then
        update_version "$gomod" "go [0-9.]\+" "go ${NEW_GO_VERSION}"
    fi
done

# Update daisyUI version in HTML files
DAISYUI_FILES=(
    "$BASE_DIR/authserver/web/template/layouts/auth_layout.html"
    "$BASE_DIR/authserver/web/template/layouts/no_menu_layout.html"
    "$BASE_DIR/adminconsole/web/template/layouts/no_menu_layout.html"
    "$BASE_DIR/adminconsole/web/template/layouts/menu_layout.html"
)

for html_file in "${DAISYUI_FILES[@]}"; do
    if [ -f "$html_file" ]; then
        update_version "$html_file" "daisyui@[0-9.]\+/dist" "daisyui@${NEW_DAISYUI_VERSION}/dist"
    fi
done

# Update humanize-duration version
MENU_LAYOUT_HTML="$BASE_DIR/adminconsole/web/template/layouts/menu_layout.html"
if [ -f "$MENU_LAYOUT_HTML" ]; then
    update_version "$MENU_LAYOUT_HTML" "humanize-duration@[0-9.]\+/" "humanize-duration@${NEW_HUMANIZE_DURATION_VERSION}/"
fi

echo "Version update complete."

cd ../core
go get -u ./...
go mod tidy

echo "Updated core dependencies"

cd ../authserver
go get -u ./...
go mod tidy

echo "Updated authserver dependencies"

cd ../adminconsole
go get -u ./...
go mod tidy

echo "Updated adminconsole dependencies"

cd ../authserver
