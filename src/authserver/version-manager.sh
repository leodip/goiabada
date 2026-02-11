#!/bin/bash

# =============================================================================
# Goiabada Version Manager
# =============================================================================
# A unified script for managing versions across the Goiabada project.
#
# Usage:
#   ./version-manager.sh <command>
#
# Commands:
#   show    - Display all versions from versions.yaml
#   check   - Check online for newer versions of dependencies
#   update  - Update version strings in all project files
#   deps    - Update Go modules and npm packages
#   all     - Run all commands in sequence (check → update → deps)
#
# Workflow:
#   1. Edit versions.yaml to set desired versions
#   2. Run: ./version-manager.sh update
#   3. Review changes: git diff
#   4. Run tests and build
#
# Requirements:
#   - yq (YAML parser) - installed in devcontainer
#   - curl (for online version checks)
#   - go, npm (for dependency updates)
# =============================================================================

# Note: We don't use 'set -e' because arithmetic expressions like ((count++))
# return non-zero when the value is 0, which would cause the script to exit.
# Instead, we handle errors explicitly where needed.

# =============================================================================
# Configuration
# =============================================================================

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BASE_DIR=$(cd "${SCRIPT_DIR}/../.." && pwd)
VERSIONS_FILE="${SCRIPT_DIR}/versions.yaml"

# =============================================================================
# Color Codes for Output
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'  # No Color

# =============================================================================
# Output Helper Functions
# =============================================================================

print_header() {
    echo ""
    echo -e "${BOLD}${CYAN}=== $1 ===${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${BLUE}$1${NC}"
}

# =============================================================================
# Prerequisites Check
# =============================================================================

# Verify yq is installed (required for YAML parsing)
require_yq() {
    if ! command -v yq &> /dev/null; then
        print_error "yq is required but not installed."
        echo "Install yq: https://github.com/mikefarah/yq#install"
        echo "Or rebuild the devcontainer which includes yq."
        exit 1
    fi
}

# Check if we have internet connectivity (for version checks)
check_internet() {
    if command -v curl &> /dev/null; then
        if curl -s --head --connect-timeout 5 https://api.github.com > /dev/null 2>&1; then
            return 0
        fi
    fi
    return 1
}

# =============================================================================
# Version Reading Functions
# =============================================================================

# Read a version from versions.yaml
# Usage: get_version "project.goiabada" -> "1.4.4"
get_version() {
    local key="$1"
    yq -r ".$key" "$VERSIONS_FILE"
}

# Get all versions as key=value pairs for display
get_all_versions() {
    yq -r '
        .project | to_entries | .[] | "project." + .key + "=" + .value,
        .tools | to_entries | .[] | "tools." + .key + "=" + .value,
        .cdn | to_entries | .[] | "cdn." + .key + "=" + .value
    ' "$VERSIONS_FILE" 2>/dev/null || {
        # Fallback: read each key individually
        echo "project.goiabada=$(get_version 'project.goiabada')"
        echo "project.goiabada-setup=$(get_version 'project.goiabada-setup')"
        echo "tools.go=$(get_version 'tools.go')"
        echo "tools.tailwind=$(get_version 'tools.tailwind')"
        echo "tools.golangci-lint=$(get_version 'tools.golangci-lint')"
        echo "tools.mockery=$(get_version 'tools.mockery')"
        echo "cdn.daisyui=$(get_version 'cdn.daisyui')"
        echo "cdn.humanize-duration=$(get_version 'cdn.humanize-duration')"
        echo "cdn.oauth4webapi=$(get_version 'cdn.oauth4webapi')"
        echo "cdn.jose=$(get_version 'cdn.jose')"
    }
}

# =============================================================================
# Online Version Check Functions
# =============================================================================

# Compare versions: returns 0 if v1 < v2
version_lt() {
    local v1="$1"
    local v2="$2"
    if [ "$(printf '%s\n' "$v1" "$v2" | sort -V | head -1)" = "$v1" ] && [ "$v1" != "$v2" ]; then
        return 0
    fi
    return 1
}

# Fetch latest version from GitHub releases API
# Usage: get_github_latest "tailwindlabs/tailwindcss"
get_github_latest() {
    local repo="$1"
    local response
    response=$(curl -s --connect-timeout 10 "https://api.github.com/repos/${repo}/releases/latest" 2>/dev/null)
    if [ $? -eq 0 ] && [ -n "$response" ]; then
        echo "$response" | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4 | sed 's/^v//'
    fi
}

# Fetch latest Go version from go.dev
get_go_latest() {
    local response
    response=$(curl -s --connect-timeout 10 "https://go.dev/dl/?mode=json" 2>/dev/null)
    if [ $? -eq 0 ] && [ -n "$response" ]; then
        echo "$response" | grep -o '"version"[[:space:]]*:[[:space:]]*"go[0-9.]*"' | head -1 | cut -d'"' -f4 | sed 's/^go//'
    fi
}

# Fetch latest version from npm registry
# Usage: get_npm_latest "daisyui"
get_npm_latest() {
    local package="$1"
    local response
    response=$(curl -s --connect-timeout 10 "https://registry.npmjs.org/${package}/latest" 2>/dev/null)
    if [ $? -eq 0 ] && [ -n "$response" ]; then
        echo "$response" | grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | cut -d'"' -f4
    fi
}

# =============================================================================
# File Update Functions
# =============================================================================

# Update a pattern in a file using sed
# Usage: update_file <file> <sed_pattern> <description>
# Returns: 0 on success, 1 on failure
update_file() {
    local file="$1"
    local sed_pattern="$2"
    local description="$3"

    if [ ! -f "$file" ]; then
        print_error "File not found: $file"
        return 1
    fi

    if sed -i "$sed_pattern" "$file"; then
        print_success "Updated: $(basename "$file") - $description"
        return 0
    else
        print_error "Failed: $(basename "$file")"
        return 1
    fi
}

# =============================================================================
# Command: show
# =============================================================================
# Display all versions defined in versions.yaml

cmd_show() {
    require_yq
    print_header "Current Versions (from versions.yaml)"

    printf "%-25s %s\n" "Key" "Version"
    printf "%-25s %s\n" "---" "-------"

    # Project versions
    echo -e "\n${BOLD}Project:${NC}"
    printf "  %-23s ${GREEN}%s${NC}\n" "goiabada" "$(get_version 'project.goiabada')"
    printf "  %-23s ${GREEN}%s${NC}\n" "goiabada-setup" "$(get_version 'project.goiabada-setup')"

    # Tool versions
    echo -e "\n${BOLD}Tools:${NC}"
    printf "  %-23s ${GREEN}%s${NC}\n" "go" "$(get_version 'tools.go')"
    printf "  %-23s ${GREEN}%s${NC}\n" "tailwind" "$(get_version 'tools.tailwind')"
    printf "  %-23s ${GREEN}%s${NC}\n" "golangci-lint" "$(get_version 'tools.golangci-lint')"
    printf "  %-23s ${GREEN}%s${NC}\n" "mockery" "$(get_version 'tools.mockery')"

    # CDN versions
    echo -e "\n${BOLD}CDN Dependencies:${NC}"
    printf "  %-23s ${GREEN}%s${NC}\n" "daisyui" "$(get_version 'cdn.daisyui')"
    printf "  %-23s ${GREEN}%s${NC}\n" "humanize-duration" "$(get_version 'cdn.humanize-duration')"
    printf "  %-23s ${GREEN}%s${NC}\n" "oauth4webapi" "$(get_version 'cdn.oauth4webapi')"
    printf "  %-23s ${GREEN}%s${NC}\n" "jose" "$(get_version 'cdn.jose')"

    echo ""
    print_info "Edit versions.yaml to change versions, then run: ./version-manager.sh update"
}

# =============================================================================
# Command: check
# =============================================================================
# Check online for newer versions of dependencies

cmd_check() {
    require_yq
    print_header "Checking for Newer Versions Online"

    if ! check_internet; then
        print_error "No internet connection. Cannot check for updates."
        return 1
    fi

    local updates_available=()

    # Define checks: name|current_key|fetch_function|url
    # We'll check each dependency and compare with our current version

    # --- Go ---
    echo -n "Checking Go... "
    local current_go=$(get_version 'tools.go')
    local latest_go=$(get_go_latest)
    if [ -n "$latest_go" ]; then
        if version_lt "$current_go" "$latest_go"; then
            echo -e "${YELLOW}UPDATE AVAILABLE${NC}"
            updates_available+=("Go|$current_go|$latest_go|https://go.dev/dl/")
        else
            print_success "Up to date ($current_go)"
        fi
    else
        print_warning "Check failed"
    fi

    # --- Tailwind CSS ---
    echo -n "Checking Tailwind CSS... "
    local current_tailwind=$(get_version 'tools.tailwind')
    local latest_tailwind=$(get_github_latest "tailwindlabs/tailwindcss")
    if [ -n "$latest_tailwind" ]; then
        if version_lt "$current_tailwind" "$latest_tailwind"; then
            echo -e "${YELLOW}UPDATE AVAILABLE${NC}"
            updates_available+=("Tailwind CSS|$current_tailwind|$latest_tailwind|https://github.com/tailwindlabs/tailwindcss/releases")
        else
            print_success "Up to date ($current_tailwind)"
        fi
    else
        print_warning "Check failed"
    fi

    # --- golangci-lint ---
    echo -n "Checking golangci-lint... "
    local current_lint=$(get_version 'tools.golangci-lint')
    local latest_lint=$(get_github_latest "golangci/golangci-lint")
    if [ -n "$latest_lint" ]; then
        if version_lt "$current_lint" "$latest_lint"; then
            echo -e "${YELLOW}UPDATE AVAILABLE${NC}"
            updates_available+=("golangci-lint|$current_lint|$latest_lint|https://github.com/golangci/golangci-lint/releases")
        else
            print_success "Up to date ($current_lint)"
        fi
    else
        print_warning "Check failed"
    fi

    # --- mockery ---
    echo -n "Checking mockery... "
    local current_mockery=$(get_version 'tools.mockery')
    local latest_mockery=$(get_github_latest "vektra/mockery")
    if [ -n "$latest_mockery" ]; then
        if version_lt "$current_mockery" "$latest_mockery"; then
            echo -e "${YELLOW}UPDATE AVAILABLE${NC}"
            updates_available+=("mockery|$current_mockery|$latest_mockery|https://github.com/vektra/mockery/releases")
        else
            print_success "Up to date ($current_mockery)"
        fi
    else
        print_warning "Check failed"
    fi

    # --- daisyUI ---
    echo -n "Checking daisyUI... "
    local current_daisyui=$(get_version 'cdn.daisyui')
    local latest_daisyui=$(get_npm_latest "daisyui")
    if [ -n "$latest_daisyui" ]; then
        if version_lt "$current_daisyui" "$latest_daisyui"; then
            echo -e "${YELLOW}UPDATE AVAILABLE${NC}"
            updates_available+=("daisyUI|$current_daisyui|$latest_daisyui|https://www.npmjs.com/package/daisyui")
        else
            print_success "Up to date ($current_daisyui)"
        fi
    else
        print_warning "Check failed"
    fi

    # --- humanize-duration ---
    echo -n "Checking humanize-duration... "
    local current_humanize=$(get_version 'cdn.humanize-duration')
    local latest_humanize=$(get_npm_latest "humanize-duration")
    if [ -n "$latest_humanize" ]; then
        if version_lt "$current_humanize" "$latest_humanize"; then
            echo -e "${YELLOW}UPDATE AVAILABLE${NC}"
            updates_available+=("humanize-duration|$current_humanize|$latest_humanize|https://www.npmjs.com/package/humanize-duration")
        else
            print_success "Up to date ($current_humanize)"
        fi
    else
        print_warning "Check failed"
    fi

    # --- oauth4webapi ---
    echo -n "Checking oauth4webapi... "
    local current_oauth=$(get_version 'cdn.oauth4webapi')
    local latest_oauth=$(get_npm_latest "oauth4webapi")
    if [ -n "$latest_oauth" ]; then
        if version_lt "$current_oauth" "$latest_oauth"; then
            echo -e "${YELLOW}UPDATE AVAILABLE${NC}"
            updates_available+=("oauth4webapi|$current_oauth|$latest_oauth|https://www.npmjs.com/package/oauth4webapi")
        else
            print_success "Up to date ($current_oauth)"
        fi
    else
        print_warning "Check failed"
    fi

    # --- jose ---
    echo -n "Checking jose... "
    local current_jose=$(get_version 'cdn.jose')
    local latest_jose=$(get_npm_latest "jose")
    if [ -n "$latest_jose" ]; then
        if version_lt "$current_jose" "$latest_jose"; then
            echo -e "${YELLOW}UPDATE AVAILABLE${NC}"
            updates_available+=("jose|$current_jose|$latest_jose|https://www.npmjs.com/package/jose")
        else
            print_success "Up to date ($current_jose)"
        fi
    else
        print_warning "Check failed"
    fi

    # --- Summary ---
    echo ""
    if [ ${#updates_available[@]} -gt 0 ]; then
        print_header "Updates Available"
        printf "%-20s %-12s %-12s %s\n" "Dependency" "Current" "Latest" "URL"
        printf "%-20s %-12s %-12s %s\n" "----------" "-------" "------" "---"
        for info in "${updates_available[@]}"; do
            IFS='|' read -r name current latest url <<< "$info"
            printf "${YELLOW}%-20s${NC} %-12s ${GREEN}%-12s${NC} ${BLUE}%s${NC}\n" "$name" "$current" "$latest" "$url"
        done
        echo ""
        print_info "To update: edit versions.yaml, then run ./version-manager.sh update"
    else
        print_success "All dependencies are up to date!"
    fi
}

# =============================================================================
# Command: update
# =============================================================================
# Update version strings in all project files based on versions.yaml

cmd_update() {
    require_yq
    print_header "Updating Version Strings in Project Files"

    # Load all versions from YAML
    local GOIABADA_VERSION=$(get_version 'project.goiabada')
    local SETUP_VERSION=$(get_version 'project.goiabada-setup')
    local GO_VERSION=$(get_version 'tools.go')
    local TAILWIND_VERSION=$(get_version 'tools.tailwind')
    local GOLANGCI_VERSION=$(get_version 'tools.golangci-lint')
    local MOCKERY_VERSION=$(get_version 'tools.mockery')
    local DAISYUI_VERSION=$(get_version 'cdn.daisyui')
    local HUMANIZE_VERSION=$(get_version 'cdn.humanize-duration')
    local OAUTH4WEBAPI_VERSION=$(get_version 'cdn.oauth4webapi')
    local JOSE_VERSION=$(get_version 'cdn.jose')

    local success_count=0
    local fail_count=0

    # -------------------------------------------------------------------------
    # GitHub Actions Workflows
    # -------------------------------------------------------------------------
    echo -e "\n${BOLD}GitHub Actions Workflows${NC}"

    for workflow in "$BASE_DIR/.github/workflows/build-binaries.yml" \
                    "$BASE_DIR/.github/workflows/build-setup-binaries.yml"; do
        if [ -f "$workflow" ]; then
            # Pattern: go-version: 'X.Y.Z' -> go-version: 'NEW_VERSION'
            if update_file "$workflow" \
                "s|go-version: '[0-9.]*'|go-version: '${GO_VERSION}'|g" \
                "Go version"; then
                ((success_count++))
            else
                ((fail_count++))
            fi
        fi
    done

    # -------------------------------------------------------------------------
    # Build Scripts (Goiabada Version)
    # -------------------------------------------------------------------------
    echo -e "\n${BOLD}Build Scripts${NC}"

    for script in "$BASE_DIR/src/build/build-binaries.sh" \
                  "$BASE_DIR/src/build/build-docker-images.sh"; do
        if [ -f "$script" ]; then
            # Pattern: VERSION="X.Y.Z" or VERSION="X.Y.Z-suffix"
            if update_file "$script" \
                "s|VERSION=\"[0-9.]*\(-[a-zA-Z0-9]*\)\?\"|VERSION=\"${GOIABADA_VERSION}\"|g" \
                "Goiabada version"; then
                ((success_count++))
            else
                ((fail_count++))
            fi
        fi
    done

    # -------------------------------------------------------------------------
    # goiabada-setup Tool
    # -------------------------------------------------------------------------
    echo -e "\n${BOLD}Goiabada Setup Tool${NC}"

    # Makefile: VERSION ?= X.Y.Z
    if [ -f "$BASE_DIR/src/cmd/goiabada-setup/Makefile" ]; then
        if update_file "$BASE_DIR/src/cmd/goiabada-setup/Makefile" \
            "s|VERSION ?= [0-9.]*|VERSION ?= ${SETUP_VERSION}|g" \
            "Makefile version"; then
            ((success_count++))
        else
            ((fail_count++))
        fi
    fi

    # main.go: const version = "X.Y.Z"
    if [ -f "$BASE_DIR/src/cmd/goiabada-setup/main.go" ]; then
        if update_file "$BASE_DIR/src/cmd/goiabada-setup/main.go" \
            "s|const version = \"[0-9.]*\"|const version = \"${SETUP_VERSION}\"|g" \
            "version constant"; then
            ((success_count++))
        else
            ((fail_count++))
        fi

        # Docker image references: leodip/goiabada:authserver-X.Y.Z(-suffix)
        if update_file "$BASE_DIR/src/cmd/goiabada-setup/main.go" \
            "s|leodip/goiabada:authserver-[0-9.]*\(-[a-zA-Z0-9]*\)\?|leodip/goiabada:authserver-${GOIABADA_VERSION}|g" \
            "authserver image"; then
            ((success_count++))
        else
            ((fail_count++))
        fi

        if update_file "$BASE_DIR/src/cmd/goiabada-setup/main.go" \
            "s|leodip/goiabada:adminconsole-[0-9.]*\(-[a-zA-Z0-9]*\)\?|leodip/goiabada:adminconsole-${GOIABADA_VERSION}|g" \
            "adminconsole image"; then
            ((success_count++))
        else
            ((fail_count++))
        fi
    fi

    # build-binaries.sh: VERSION="X.Y.Z"
    if [ -f "$BASE_DIR/src/cmd/goiabada-setup/build-binaries.sh" ]; then
        if update_file "$BASE_DIR/src/cmd/goiabada-setup/build-binaries.sh" \
            "s|VERSION=\"[0-9.]*\"|VERSION=\"${SETUP_VERSION}\"|g" \
            "build script version"; then
            ((success_count++))
        else
            ((fail_count++))
        fi
    fi

    # -------------------------------------------------------------------------
    # DevContainer Dockerfile
    # -------------------------------------------------------------------------
    echo -e "\n${BOLD}DevContainer${NC}"

    if [ -f "$BASE_DIR/src/.devcontainer/Dockerfile" ]; then
        # Go tarball: goX.Y.Z.linux-amd64.tar.gz
        if update_file "$BASE_DIR/src/.devcontainer/Dockerfile" \
            "s|go[0-9.]*\.linux-amd64\.tar\.gz|go${GO_VERSION}.linux-amd64.tar.gz|g" \
            "Go tarball"; then
            ((success_count++))
        else
            ((fail_count++))
        fi

        # Tailwind CSS: tailwindcss/releases/download/vX.Y.Z/tailwindcss-linux-x64
        if update_file "$BASE_DIR/src/.devcontainer/Dockerfile" \
            "s|tailwindcss/releases/download/v[0-9.]*/tailwindcss-linux-x64|tailwindcss/releases/download/v${TAILWIND_VERSION}/tailwindcss-linux-x64|g" \
            "Tailwind CSS"; then
            ((success_count++))
        else
            ((fail_count++))
        fi

        # golangci-lint: golangci-lint@vX.Y.Z
        if update_file "$BASE_DIR/src/.devcontainer/Dockerfile" \
            "s|golangci-lint@v[0-9.]*|golangci-lint@v${GOLANGCI_VERSION}|g" \
            "golangci-lint"; then
            ((success_count++))
        else
            ((fail_count++))
        fi

        # mockery: mockery/v3@vX.Y.Z
        if update_file "$BASE_DIR/src/.devcontainer/Dockerfile" \
            "s|mockery/v3@v[0-9.]*|mockery/v3@v${MOCKERY_VERSION}|g" \
            "mockery"; then
            ((success_count++))
        else
            ((fail_count++))
        fi
    fi

    # -------------------------------------------------------------------------
    # Production Dockerfiles
    # -------------------------------------------------------------------------
    echo -e "\n${BOLD}Production Dockerfiles${NC}"

    for dockerfile in "$BASE_DIR/src/build/Dockerfile-adminconsole" \
                      "$BASE_DIR/src/build/Dockerfile-authserver" \
                      "$BASE_DIR/src/build/Dockerfile-test"; do
        if [ -f "$dockerfile" ]; then
            # Go base image: golang:X.Y.Z-alpine
            if update_file "$dockerfile" \
                "s|golang:[0-9.]*-alpine|golang:${GO_VERSION}-alpine|g" \
                "Go base image"; then
                ((success_count++))
            else
                ((fail_count++))
            fi

            # Tailwind in Dockerfile-test (musl variant)
            if [[ "$dockerfile" == *"Dockerfile-test"* ]]; then
                if update_file "$dockerfile" \
                    "s|tailwindcss/releases/download/v[0-9.]*/tailwindcss-linux-x64-musl|tailwindcss/releases/download/v${TAILWIND_VERSION}/tailwindcss-linux-x64-musl|g" \
                    "Tailwind CSS (musl)"; then
                    ((success_count++))
                else
                    ((fail_count++))
                fi
            fi
        fi
    done

    # -------------------------------------------------------------------------
    # Go Module Files
    # -------------------------------------------------------------------------
    echo -e "\n${BOLD}Go Module Files${NC}"

    for gomod in "$BASE_DIR/src/core/go.mod" \
                 "$BASE_DIR/src/authserver/go.mod" \
                 "$BASE_DIR/src/adminconsole/go.mod" \
                 "$BASE_DIR/src/cmd/goiabada-setup/go.mod" \
                 "$BASE_DIR/test-integrations/go-webapp/go.mod"; do
        if [ -f "$gomod" ]; then
            # Go version directive: go X.Y.Z
            if update_file "$gomod" \
                "s|^go [0-9.]*|go ${GO_VERSION}|g" \
                "Go version directive"; then
                ((success_count++))
            else
                ((fail_count++))
            fi
        fi
    done

    # -------------------------------------------------------------------------
    # HTML Templates (daisyUI CDN)
    # -------------------------------------------------------------------------
    echo -e "\n${BOLD}HTML Templates${NC}"

    for html in "$BASE_DIR/src/authserver/web/template/layouts/auth_layout.html" \
                "$BASE_DIR/src/authserver/web/template/layouts/no_menu_layout.html" \
                "$BASE_DIR/src/adminconsole/web/template/layouts/no_menu_layout.html" \
                "$BASE_DIR/src/adminconsole/web/template/layouts/menu_layout.html"; do
        if [ -f "$html" ]; then
            # daisyUI CDN: daisyui@X.Y.Z
            if update_file "$html" \
                "s|daisyui@[0-9.]*|daisyui@${DAISYUI_VERSION}|g" \
                "daisyUI CDN"; then
                ((success_count++))
            else
                ((fail_count++))
            fi
        fi
    done

    # humanize-duration (only in admin console menu_layout)
    if [ -f "$BASE_DIR/src/adminconsole/web/template/layouts/menu_layout.html" ]; then
        if update_file "$BASE_DIR/src/adminconsole/web/template/layouts/menu_layout.html" \
            "s|humanize-duration@[0-9.]*/|humanize-duration@${HUMANIZE_VERSION}/|g" \
            "humanize-duration CDN"; then
            ((success_count++))
        else
            ((fail_count++))
        fi
    fi

    # -------------------------------------------------------------------------
    # Test Integrations (js-only)
    # -------------------------------------------------------------------------
    echo -e "\n${BOLD}Test Integrations (js-only)${NC}"

    for jsfile in "$BASE_DIR/test-integrations/js-only/index.html" \
                  "$BASE_DIR/test-integrations/js-only/callback.html"; do
        if [ -f "$jsfile" ]; then
            # oauth4webapi CDN: oauth4webapi@X.Y.Z/
            if update_file "$jsfile" \
                "s|oauth4webapi@[0-9.]*/|oauth4webapi@${OAUTH4WEBAPI_VERSION}/|g" \
                "oauth4webapi CDN"; then
                ((success_count++))
            else
                ((fail_count++))
            fi
        fi
    done

    # jose (only in callback.html)
    if [ -f "$BASE_DIR/test-integrations/js-only/callback.html" ]; then
        if update_file "$BASE_DIR/test-integrations/js-only/callback.html" \
            "s|jose@[0-9.]*/|jose@${JOSE_VERSION}/|g" \
            "jose CDN"; then
            ((success_count++))
        else
            ((fail_count++))
        fi
    fi

    # -------------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------------
    echo ""
    print_header "Summary"
    print_success "Successful updates: $success_count"
    if [ $fail_count -gt 0 ]; then
        print_error "Failed updates: $fail_count"
    fi

    echo ""
    print_info "Next steps:"
    echo "  1. Review changes: git diff"
    echo "  2. Run tests: make test-ci"
    echo "  3. Commit changes"
}

# =============================================================================
# Command: deps
# =============================================================================
# Update Go modules and npm packages

cmd_deps() {
    print_header "Updating Dependencies"

    # -------------------------------------------------------------------------
    # Go Modules
    # -------------------------------------------------------------------------
    echo -e "\n${BOLD}Go Modules${NC}"

    # Modules that depend on core (need special handling to preserve local reference)
    local modules_with_core=(
        "$BASE_DIR/src/core"
        "$BASE_DIR/src/authserver"
        "$BASE_DIR/src/adminconsole"
    )

    # Standalone modules
    local modules_standalone=(
        "$BASE_DIR/src/cmd/goiabada-setup"
        "$BASE_DIR/test-integrations/go-webapp"
    )

    # Update modules with core dependency
    for module_dir in "${modules_with_core[@]}"; do
        if [ -d "$module_dir" ]; then
            echo -e "\n${BOLD}Updating ${module_dir}${NC}"
            pushd "$module_dir" > /dev/null 2>&1

            if go get -u ./... 2>&1; then
                # Reset core module back to v0.0.0 (local pseudo-version)
                # This is needed because go get -u tries to fetch from remote
                go mod edit -require=github.com/leodip/goiabada/core@v0.0.0 2>/dev/null || true
                print_success "go get -u ./..."
            else
                print_error "go get -u ./... failed"
            fi

            if go mod tidy 2>&1; then
                print_success "go mod tidy"
            else
                print_error "go mod tidy failed"
            fi

            popd > /dev/null 2>&1
        fi
    done

    # Update standalone modules
    for module_dir in "${modules_standalone[@]}"; do
        if [ -d "$module_dir" ]; then
            echo -e "\n${BOLD}Updating ${module_dir}${NC}"
            pushd "$module_dir" > /dev/null 2>&1

            if go get -u ./... 2>&1; then
                print_success "go get -u ./..."
            else
                print_error "go get -u ./... failed"
            fi

            if go mod tidy 2>&1; then
                print_success "go mod tidy"
            else
                print_error "go mod tidy failed"
            fi

            popd > /dev/null 2>&1
        fi
    done

    # -------------------------------------------------------------------------
    # npm Packages
    # -------------------------------------------------------------------------
    echo -e "\n${BOLD}npm Packages${NC}"

    if ! command -v ncu &> /dev/null; then
        print_warning "ncu (npm-check-updates) is not installed. Skipping npm updates."
        echo "Install: npm install -g npm-check-updates"
    else
        local npm_dirs=(
            "$BASE_DIR/test-integrations/react-vite/client"
            "$BASE_DIR/test-integrations/react-vite/server"
        )

        for npm_dir in "${npm_dirs[@]}"; do
            if [ -d "$npm_dir" ]; then
                echo -e "\n${BOLD}Updating ${npm_dir}${NC}"
                pushd "$npm_dir" > /dev/null 2>&1

                if ncu -u 2>&1; then
                    print_success "ncu -u"
                else
                    print_error "ncu -u failed"
                fi

                if npm install 2>&1; then
                    print_success "npm install"
                else
                    print_error "npm install failed"
                fi

                popd > /dev/null 2>&1
            else
                print_warning "Directory not found: $npm_dir"
            fi
        done
    fi

    echo ""
    print_success "Dependency update complete"
}

# =============================================================================
# Command: all
# =============================================================================
# Run all commands in sequence

cmd_all() {
    print_header "Running Full Update"

    cmd_check
    echo ""
    read -p "Press Enter to continue with file updates..."

    cmd_update
    echo ""
    read -p "Press Enter to continue with dependency updates..."

    cmd_deps

    print_header "Full Update Complete"
    echo "Next steps:"
    echo "  1. Review the changes: git diff"
    echo "  2. Run tests: make test-ci"
    echo "  3. Build: make build"
}

# =============================================================================
# Help
# =============================================================================

show_help() {
    echo ""
    echo -e "${BOLD}${CYAN}Goiabada Version Manager${NC}"
    echo ""
    echo "Usage: $0 <command>"
    echo ""
    echo "Commands:"
    echo "  show    Display all versions from versions.yaml"
    echo "  check   Check online for newer versions"
    echo "  update  Update version strings in all project files"
    echo "  deps    Update Go modules and npm packages"
    echo "  all     Run all commands in sequence"
    echo ""
    echo "Workflow:"
    echo "  1. Edit versions.yaml to set desired versions"
    echo "  2. Run: $0 update"
    echo "  3. Review changes: git diff"
    echo "  4. Run tests and build"
    echo ""
    echo "Examples:"
    echo "  $0 show          # See current versions"
    echo "  $0 check         # Check for newer versions online"
    echo "  $0 update        # Apply versions from yaml to files"
    echo ""
}

# =============================================================================
# Main Entry Point
# =============================================================================

# Check that versions.yaml exists
if [ ! -f "$VERSIONS_FILE" ]; then
    print_error "versions.yaml not found at: $VERSIONS_FILE"
    exit 1
fi

# Parse command
case "${1:-}" in
    show)
        cmd_show
        ;;
    check)
        cmd_check
        ;;
    update)
        cmd_update
        ;;
    deps)
        cmd_deps
        ;;
    all)
        cmd_all
        ;;
    -h|--help|help)
        show_help
        ;;
    "")
        show_help
        ;;
    *)
        print_error "Unknown command: $1"
        echo "Use '$0 --help' for usage information."
        exit 1
        ;;
esac
