#!/bin/bash

# =============================================================================
# Goiabada Version Management Script
# =============================================================================

# Target versions (edit these to update)
GOIABADA_VERSION="1.4.3"
GOIABADA_SETUP_VERSION="1.0.0"
NEW_GO_VERSION="1.25.6"
NEW_TAILWIND_VERSION="4.1.18"
NEW_GOLANGCI_LINT_VERSION="2.8.0"
NEW_MOCKERY_VERSION="3.6.3"
NEW_DAISYUI_VERSION="5.5.14"
NEW_HUMANIZE_DURATION_VERSION="3.33.2"
NEW_OAUTH4WEBAPI_VERSION="3.8.3"
NEW_JOSE_VERSION="6.1.3"

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BASE_DIR=$(cd "${SCRIPT_DIR}/../.." && pwd)

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# =============================================================================
# Helper Functions
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

check_internet() {
    if command -v curl &> /dev/null; then
        if curl -s --head --connect-timeout 5 https://api.github.com > /dev/null 2>&1; then
            return 0
        fi
    fi
    return 1
}

# Compare versions: returns 0 if v1 < v2
version_lt() {
    local v1="$1"
    local v2="$2"
    if [ "$(printf '%s\n' "$v1" "$v2" | sort -V | head -1)" = "$v1" ] && [ "$v1" != "$v2" ]; then
        return 0
    fi
    return 1
}

get_github_latest_version() {
    local repo="$1"
    if ! command -v curl &> /dev/null; then
        return 1
    fi
    local response
    response=$(curl -s --connect-timeout 10 "https://api.github.com/repos/${repo}/releases/latest" 2>/dev/null)
    if [ $? -eq 0 ] && [ -n "$response" ]; then
        local version
        version=$(echo "$response" | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4 | sed 's/^v//')
        if [ -n "$version" ]; then
            echo "$version"
            return 0
        fi
    fi
    return 1
}

get_go_latest_version() {
    if ! command -v curl &> /dev/null; then
        return 1
    fi
    local response
    response=$(curl -s --connect-timeout 10 "https://go.dev/dl/?mode=json" 2>/dev/null)
    if [ $? -eq 0 ] && [ -n "$response" ]; then
        local version
        version=$(echo "$response" | grep -o '"version"[[:space:]]*:[[:space:]]*"go[0-9.]*"' | head -1 | cut -d'"' -f4 | sed 's/^go//')
        if [ -n "$version" ]; then
            echo "$version"
            return 0
        fi
    fi
    return 1
}

get_npm_latest_version() {
    local package="$1"
    if ! command -v curl &> /dev/null; then
        return 1
    fi
    local response
    response=$(curl -s --connect-timeout 10 "https://registry.npmjs.org/${package}/latest" 2>/dev/null)
    if [ $? -eq 0 ] && [ -n "$response" ]; then
        local version
        version=$(echo "$response" | grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | cut -d'"' -f4)
        if [ -n "$version" ]; then
            echo "$version"
            return 0
        fi
    fi
    return 1
}

update_version() {
    local file="$1"
    local old_pattern="$2"
    local new_pattern="$3"
    local description="$4"

    if [ ! -f "$file" ]; then
        print_error "File not found: $file"
        return 1
    fi

    if ! grep -q "${old_pattern}" "$file" 2>/dev/null; then
        print_error "Pattern not found in $file"
        return 1
    fi

    if sed -i "s|${old_pattern}|${new_pattern}|g" "$file"; then
        print_success "Updated $file - $description"
        return 0
    else
        print_error "Failed to update $file"
        return 1
    fi
}

# =============================================================================
# Menu Option 1: Check for Updates
# =============================================================================

check_for_updates() {
    print_header "Checking for Newer Versions Online"

    if ! check_internet; then
        print_error "No internet connection. Cannot check for updates."
        return 1
    fi

    local updates_available=()

    # Check Go
    echo -n "Checking Go... "
    local latest_go
    latest_go=$(get_go_latest_version)
    if [ $? -eq 0 ] && [ -n "$latest_go" ]; then
        if version_lt "$NEW_GO_VERSION" "$latest_go"; then
            echo -e "${YELLOW}UPDATE AVAILABLE${NC}"
            updates_available+=("Go|$NEW_GO_VERSION|$latest_go|https://go.dev/dl/")
        else
            print_success "Up to date ($NEW_GO_VERSION)"
        fi
    else
        print_warning "Check failed"
    fi

    # Check Tailwind CSS
    echo -n "Checking Tailwind CSS... "
    local latest_tailwind
    latest_tailwind=$(get_github_latest_version "tailwindlabs/tailwindcss")
    if [ $? -eq 0 ] && [ -n "$latest_tailwind" ]; then
        if version_lt "$NEW_TAILWIND_VERSION" "$latest_tailwind"; then
            echo -e "${YELLOW}UPDATE AVAILABLE${NC}"
            updates_available+=("Tailwind CSS|$NEW_TAILWIND_VERSION|$latest_tailwind|https://github.com/tailwindlabs/tailwindcss/releases")
        else
            print_success "Up to date ($NEW_TAILWIND_VERSION)"
        fi
    else
        print_warning "Check failed"
    fi

    # Check golangci-lint
    echo -n "Checking golangci-lint... "
    local latest_golangci
    latest_golangci=$(get_github_latest_version "golangci/golangci-lint")
    if [ $? -eq 0 ] && [ -n "$latest_golangci" ]; then
        if version_lt "$NEW_GOLANGCI_LINT_VERSION" "$latest_golangci"; then
            echo -e "${YELLOW}UPDATE AVAILABLE${NC}"
            updates_available+=("golangci-lint|$NEW_GOLANGCI_LINT_VERSION|$latest_golangci|https://github.com/golangci/golangci-lint/releases")
        else
            print_success "Up to date ($NEW_GOLANGCI_LINT_VERSION)"
        fi
    else
        print_warning "Check failed"
    fi

    # Check mockery
    echo -n "Checking mockery... "
    local latest_mockery
    latest_mockery=$(get_github_latest_version "vektra/mockery")
    if [ $? -eq 0 ] && [ -n "$latest_mockery" ]; then
        if version_lt "$NEW_MOCKERY_VERSION" "$latest_mockery"; then
            echo -e "${YELLOW}UPDATE AVAILABLE${NC}"
            updates_available+=("mockery|$NEW_MOCKERY_VERSION|$latest_mockery|https://github.com/vektra/mockery/releases")
        else
            print_success "Up to date ($NEW_MOCKERY_VERSION)"
        fi
    else
        print_warning "Check failed"
    fi

    # Check daisyUI
    echo -n "Checking daisyUI... "
    local latest_daisyui
    latest_daisyui=$(get_npm_latest_version "daisyui")
    if [ $? -eq 0 ] && [ -n "$latest_daisyui" ]; then
        if version_lt "$NEW_DAISYUI_VERSION" "$latest_daisyui"; then
            echo -e "${YELLOW}UPDATE AVAILABLE${NC}"
            updates_available+=("daisyUI|$NEW_DAISYUI_VERSION|$latest_daisyui|https://www.npmjs.com/package/daisyui")
        else
            print_success "Up to date ($NEW_DAISYUI_VERSION)"
        fi
    else
        print_warning "Check failed"
    fi

    # Check humanize-duration
    echo -n "Checking humanize-duration... "
    local latest_humanize
    latest_humanize=$(get_npm_latest_version "humanize-duration")
    if [ $? -eq 0 ] && [ -n "$latest_humanize" ]; then
        if version_lt "$NEW_HUMANIZE_DURATION_VERSION" "$latest_humanize"; then
            echo -e "${YELLOW}UPDATE AVAILABLE${NC}"
            updates_available+=("humanize-duration|$NEW_HUMANIZE_DURATION_VERSION|$latest_humanize|https://www.npmjs.com/package/humanize-duration")
        else
            print_success "Up to date ($NEW_HUMANIZE_DURATION_VERSION)"
        fi
    else
        print_warning "Check failed"
    fi

    # Check oauth4webapi
    echo -n "Checking oauth4webapi... "
    local latest_oauth4webapi
    latest_oauth4webapi=$(get_npm_latest_version "oauth4webapi")
    if [ $? -eq 0 ] && [ -n "$latest_oauth4webapi" ]; then
        if version_lt "$NEW_OAUTH4WEBAPI_VERSION" "$latest_oauth4webapi"; then
            echo -e "${YELLOW}UPDATE AVAILABLE${NC}"
            updates_available+=("oauth4webapi|$NEW_OAUTH4WEBAPI_VERSION|$latest_oauth4webapi|https://www.npmjs.com/package/oauth4webapi")
        else
            print_success "Up to date ($NEW_OAUTH4WEBAPI_VERSION)"
        fi
    else
        print_warning "Check failed"
    fi

    # Check jose
    echo -n "Checking jose... "
    local latest_jose
    latest_jose=$(get_npm_latest_version "jose")
    if [ $? -eq 0 ] && [ -n "$latest_jose" ]; then
        if version_lt "$NEW_JOSE_VERSION" "$latest_jose"; then
            echo -e "${YELLOW}UPDATE AVAILABLE${NC}"
            updates_available+=("jose|$NEW_JOSE_VERSION|$latest_jose|https://www.npmjs.com/package/jose")
        else
            print_success "Up to date ($NEW_JOSE_VERSION)"
        fi
    else
        print_warning "Check failed"
    fi

    # Summary
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
        print_info "To update, edit the version variables at the top of this script."
    else
        print_success "All dependencies are up to date!"
    fi
}

# =============================================================================
# Menu Option 2: Update Version Files
# =============================================================================

update_version_files() {
    print_header "Updating Version Strings in Project Files"

    local success_count=0
    local fail_count=0

    # GitHub Actions workflows
    echo -e "${BOLD}GitHub Actions Workflows${NC}"
    for workflow_file in "$BASE_DIR/.github/workflows/build-binaries.yml" "$BASE_DIR/.github/workflows/build-setup-binaries.yml"; do
        if [ -f "$workflow_file" ]; then
            if update_version "$workflow_file" "go-version: '[0-9.]\+'" "go-version: '${NEW_GO_VERSION}'" "Go version"; then
                ((success_count++))
            else
                ((fail_count++))
            fi
        fi
    done

    # Build scripts (Goiabada version)
    echo ""
    echo -e "${BOLD}Build Scripts${NC}"
    for script in "$BASE_DIR/src/build/build-binaries.sh" "$BASE_DIR/src/build/build-docker-images.sh"; do
        if [ -f "$script" ]; then
            if update_version "$script" 'VERSION="[0-9.]\+\(-[a-zA-Z0-9]\+\)\?"' "VERSION=\"${GOIABADA_VERSION}\"" "Goiabada version"; then
                ((success_count++))
            else
                ((fail_count++))
            fi
        fi
    done

    # goiabada-setup files
    echo ""
    echo -e "${BOLD}Goiabada Setup Tool${NC}"

    if [ -f "$BASE_DIR/src/cmd/goiabada-setup/Makefile" ]; then
        if update_version "$BASE_DIR/src/cmd/goiabada-setup/Makefile" 'VERSION ?= [0-9.]\+' "VERSION ?= ${GOIABADA_SETUP_VERSION}" "Makefile version"; then
            ((success_count++))
        else
            ((fail_count++))
        fi
    fi

    if [ -f "$BASE_DIR/src/cmd/goiabada-setup/main.go" ]; then
        if update_version "$BASE_DIR/src/cmd/goiabada-setup/main.go" 'const version = "[0-9.]\+"' "const version = \"${GOIABADA_SETUP_VERSION}\"" "version constant"; then
            ((success_count++))
        else
            ((fail_count++))
        fi
        if update_version "$BASE_DIR/src/cmd/goiabada-setup/main.go" 'leodip/goiabada:authserver-[0-9.]\+\(-[a-zA-Z0-9]\+\)\?' "leodip/goiabada:authserver-${GOIABADA_VERSION}" "authserver image"; then
            ((success_count++))
        else
            ((fail_count++))
        fi
        if update_version "$BASE_DIR/src/cmd/goiabada-setup/main.go" 'leodip/goiabada:adminconsole-[0-9.]\+\(-[a-zA-Z0-9]\+\)\?' "leodip/goiabada:adminconsole-${GOIABADA_VERSION}" "adminconsole image"; then
            ((success_count++))
        else
            ((fail_count++))
        fi
    fi

    if [ -f "$BASE_DIR/src/cmd/goiabada-setup/build-binaries.sh" ]; then
        if update_version "$BASE_DIR/src/cmd/goiabada-setup/build-binaries.sh" 'VERSION="[0-9.]\+"' "VERSION=\"${GOIABADA_SETUP_VERSION}\"" "build script version"; then
            ((success_count++))
        else
            ((fail_count++))
        fi
    fi

    # DevContainer
    echo ""
    echo -e "${BOLD}DevContainer${NC}"
    if [ -f "$BASE_DIR/src/.devcontainer/Dockerfile" ]; then
        if update_version "$BASE_DIR/src/.devcontainer/Dockerfile" "go[0-9.]\+\.linux-amd64\.tar\.gz" "go${NEW_GO_VERSION}.linux-amd64.tar.gz" "Go tarball"; then
            ((success_count++))
        else
            ((fail_count++))
        fi
        if update_version "$BASE_DIR/src/.devcontainer/Dockerfile" "tailwindcss/releases/download/v[0-9.]\+/tailwindcss-linux-x64" "tailwindcss/releases/download/v${NEW_TAILWIND_VERSION}/tailwindcss-linux-x64" "Tailwind CSS"; then
            ((success_count++))
        else
            ((fail_count++))
        fi
        if update_version "$BASE_DIR/src/.devcontainer/Dockerfile" "golangci-lint@v[0-9.]\+" "golangci-lint@v${NEW_GOLANGCI_LINT_VERSION}" "golangci-lint"; then
            ((success_count++))
        else
            ((fail_count++))
        fi
        if update_version "$BASE_DIR/src/.devcontainer/Dockerfile" "mockery/v3@v[0-9.]\+" "mockery/v3@v${NEW_MOCKERY_VERSION}" "mockery"; then
            ((success_count++))
        else
            ((fail_count++))
        fi
    fi

    # Production Dockerfiles
    echo ""
    echo -e "${BOLD}Production Dockerfiles${NC}"
    for dockerfile in "$BASE_DIR/src/build/Dockerfile-adminconsole" "$BASE_DIR/src/build/Dockerfile-authserver" "$BASE_DIR/src/build/Dockerfile-test"; do
        if [ -f "$dockerfile" ]; then
            if update_version "$dockerfile" "golang:[0-9.]\+-alpine" "golang:${NEW_GO_VERSION}-alpine" "Go base image"; then
                ((success_count++))
            else
                ((fail_count++))
            fi
            if [[ "$dockerfile" == *"Dockerfile-test"* ]]; then
                if update_version "$dockerfile" "tailwindcss/releases/download/v[0-9.]\+/tailwindcss-linux-x64-musl" "tailwindcss/releases/download/v${NEW_TAILWIND_VERSION}/tailwindcss-linux-x64-musl" "Tailwind CSS (musl)"; then
                    ((success_count++))
                else
                    ((fail_count++))
                fi
            fi
        fi
    done

    # Go module files
    echo ""
    echo -e "${BOLD}Go Module Files${NC}"
    for gomod in "$BASE_DIR/src/adminconsole/go.mod" "$BASE_DIR/src/authserver/go.mod" "$BASE_DIR/src/core/go.mod" "$BASE_DIR/src/cmd/goiabada-setup/go.mod" "$BASE_DIR/test-integrations/go-webapp/go.mod"; do
        if [ -f "$gomod" ]; then
            if update_version "$gomod" "^go [0-9.]\+" "go ${NEW_GO_VERSION}" "Go version directive"; then
                ((success_count++))
            else
                ((fail_count++))
            fi
        fi
    done

    # HTML templates (daisyUI and humanize-duration)
    echo ""
    echo -e "${BOLD}HTML Templates${NC}"
    for html_file in "$BASE_DIR/src/authserver/web/template/layouts/auth_layout.html" "$BASE_DIR/src/authserver/web/template/layouts/no_menu_layout.html" "$BASE_DIR/src/adminconsole/web/template/layouts/no_menu_layout.html" "$BASE_DIR/src/adminconsole/web/template/layouts/menu_layout.html"; do
        if [ -f "$html_file" ]; then
            if update_version "$html_file" "daisyui@[0-9.]\+" "daisyui@${NEW_DAISYUI_VERSION}" "daisyUI CDN"; then
                ((success_count++))
            else
                ((fail_count++))
            fi
        fi
    done

    if [ -f "$BASE_DIR/src/adminconsole/web/template/layouts/menu_layout.html" ]; then
        if update_version "$BASE_DIR/src/adminconsole/web/template/layouts/menu_layout.html" "humanize-duration@[0-9.]\+/" "humanize-duration@${NEW_HUMANIZE_DURATION_VERSION}/" "humanize-duration CDN"; then
            ((success_count++))
        else
            ((fail_count++))
        fi
    fi

    # Test integrations - js-only
    echo ""
    echo -e "${BOLD}Test Integrations (js-only)${NC}"
    for js_file in "$BASE_DIR/test-integrations/js-only/index.html" "$BASE_DIR/test-integrations/js-only/callback.html"; do
        if [ -f "$js_file" ]; then
            if update_version "$js_file" "oauth4webapi@[0-9.]\+/" "oauth4webapi@${NEW_OAUTH4WEBAPI_VERSION}/" "oauth4webapi CDN"; then
                ((success_count++))
            else
                ((fail_count++))
            fi
        fi
    done

    if [ -f "$BASE_DIR/test-integrations/js-only/callback.html" ]; then
        if update_version "$BASE_DIR/test-integrations/js-only/callback.html" "jose@[0-9.]\+/" "jose@${NEW_JOSE_VERSION}/" "jose CDN"; then
            ((success_count++))
        else
            ((fail_count++))
        fi
    fi

    # Summary
    echo ""
    print_header "Summary"
    print_success "Successful updates: $success_count"
    if [ $fail_count -gt 0 ]; then
        print_error "Failed updates: $fail_count"
    fi
}

# =============================================================================
# Menu Option 3: Update Go Modules
# =============================================================================

update_go_modules() {
    print_header "Updating Go Module Dependencies"

    local modules_with_core=(
        "$BASE_DIR/src/core"
        "$BASE_DIR/src/authserver"
        "$BASE_DIR/src/adminconsole"
    )

    local modules_standalone=(
        "$BASE_DIR/src/cmd/goiabada-setup"
        "$BASE_DIR/test-integrations/go-webapp"
    )

    # Modules with core dependency
    for module_dir in "${modules_with_core[@]}"; do
        if [ -d "$module_dir" ]; then
            echo -e "${BOLD}Updating ${module_dir}${NC}"
            pushd "$module_dir" > /dev/null 2>&1

            if go get -u ./... 2>&1; then
                # Reset core module back to v0.0.0 (local pseudo-version)
                go mod edit -require=github.com/leodip/goiabada/core@v0.0.0 2>/dev/null
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
            echo ""
        fi
    done

    # Standalone modules
    for module_dir in "${modules_standalone[@]}"; do
        if [ -d "$module_dir" ]; then
            echo -e "${BOLD}Updating ${module_dir}${NC}"
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
            echo ""
        fi
    done

    print_success "Go modules update complete"
}

# =============================================================================
# Menu Option 4: Update npm Packages
# =============================================================================

update_npm_packages() {
    print_header "Updating npm Packages"

    if ! command -v npm &> /dev/null; then
        print_error "npm is not installed. Cannot update npm packages."
        return 1
    fi

    local npm_dirs=(
        "$BASE_DIR/test-integrations/react-vite/client"
        "$BASE_DIR/test-integrations/react-vite/server"
    )

    for npm_dir in "${npm_dirs[@]}"; do
        if [ -d "$npm_dir" ]; then
            echo -e "${BOLD}Updating ${npm_dir}${NC}"
            pushd "$npm_dir" > /dev/null 2>&1

            if npm update 2>&1; then
                print_success "npm update"
            else
                print_error "npm update failed"
            fi

            popd > /dev/null 2>&1
            echo ""
        else
            print_warning "Directory not found: $npm_dir"
        fi
    done

    print_success "npm packages update complete"
}

# =============================================================================
# Menu Option 5: Full Update
# =============================================================================

full_update() {
    print_header "Running Full Update"

    check_for_updates
    echo ""
    read -p "Press Enter to continue with file updates..."

    update_version_files
    echo ""
    read -p "Press Enter to continue with Go module updates..."

    update_go_modules
    echo ""
    read -p "Press Enter to continue with npm package updates..."

    update_npm_packages

    print_header "Full Update Complete"
    echo "Next steps:"
    echo "  1. Review the changes: git diff"
    echo "  2. Run tests to verify: make test-ci"
    echo "  3. Build binaries: make build"
}

# =============================================================================
# Menu Option 6: Show Current Versions
# =============================================================================

show_current_versions() {
    print_header "Current Target Versions"

    printf "%-25s %s\n" "Dependency" "Version"
    printf "%-25s %s\n" "----------" "-------"
    printf "%-25s ${GREEN}%s${NC}\n" "Goiabada" "$GOIABADA_VERSION"
    printf "%-25s ${GREEN}%s${NC}\n" "goiabada-setup" "$GOIABADA_SETUP_VERSION"
    printf "%-25s ${GREEN}%s${NC}\n" "Go" "$NEW_GO_VERSION"
    printf "%-25s ${GREEN}%s${NC}\n" "Tailwind CSS" "$NEW_TAILWIND_VERSION"
    printf "%-25s ${GREEN}%s${NC}\n" "golangci-lint" "$NEW_GOLANGCI_LINT_VERSION"
    printf "%-25s ${GREEN}%s${NC}\n" "mockery" "$NEW_MOCKERY_VERSION"
    printf "%-25s ${GREEN}%s${NC}\n" "daisyUI" "$NEW_DAISYUI_VERSION"
    printf "%-25s ${GREEN}%s${NC}\n" "humanize-duration" "$NEW_HUMANIZE_DURATION_VERSION"
    printf "%-25s ${GREEN}%s${NC}\n" "oauth4webapi" "$NEW_OAUTH4WEBAPI_VERSION"
    printf "%-25s ${GREEN}%s${NC}\n" "jose" "$NEW_JOSE_VERSION"
    echo ""
    print_info "Edit the variables at the top of this script to change versions."
}

# =============================================================================
# Main Menu
# =============================================================================

show_menu() {
    echo ""
    echo -e "${BOLD}${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║           Goiabada Version Management                         ║${NC}"
    echo -e "${BOLD}${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BOLD}1)${NC} Check for updates        Check online for newer versions"
    echo -e "  ${BOLD}2)${NC} Update version files     Update version strings in project files"
    echo -e "  ${BOLD}3)${NC} Update Go modules        Run go get -u and go mod tidy"
    echo -e "  ${BOLD}4)${NC} Update npm packages      Run npm update on react-vite apps"
    echo -e "  ${BOLD}5)${NC} Full update              Run all of the above"
    echo -e "  ${BOLD}6)${NC} Show current versions    Display target versions in this script"
    echo ""
    echo -e "  ${BOLD}q)${NC} Quit"
    echo ""
}

run_menu() {
    while true; do
        show_menu
        read -p "Select an option: " choice

        case $choice in
            1)
                check_for_updates
                ;;
            2)
                update_version_files
                ;;
            3)
                update_go_modules
                ;;
            4)
                update_npm_packages
                ;;
            5)
                full_update
                ;;
            6)
                show_current_versions
                ;;
            q|Q)
                echo ""
                echo "Goodbye!"
                exit 0
                ;;
            *)
                print_error "Invalid option. Please try again."
                ;;
        esac

        echo ""
        read -p "Press Enter to continue..."
    done
}

# =============================================================================
# Entry Point
# =============================================================================

# Allow direct execution with option number
if [ -n "$1" ]; then
    case $1 in
        1) check_for_updates ;;
        2) update_version_files ;;
        3) update_go_modules ;;
        4) update_npm_packages ;;
        5) full_update ;;
        6) show_current_versions ;;
        --help|-h)
            echo "Usage: $0 [OPTION]"
            echo ""
            echo "Options:"
            echo "  1    Check for updates"
            echo "  2    Update version files"
            echo "  3    Update Go modules"
            echo "  4    Update npm packages"
            echo "  5    Full update (all of the above)"
            echo "  6    Show current versions"
            echo ""
            echo "Run without arguments for interactive menu."
            exit 0
            ;;
        *)
            print_error "Invalid option: $1"
            echo "Use --help for usage information."
            exit 1
            ;;
    esac
    exit 0
fi

# Run interactive menu
run_menu
