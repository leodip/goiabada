#!/bin/bash

GOIABADA_VERSION="1.2.1"
GOIABADA_SETUP_VERSION="1.0.0" # goiabada-setup CLI tool version
NEW_GO_VERSION="1.25.4" # https://go.dev/dl/
NEW_TAILWIND_VERSION="4.1.17" # https://github.com/tailwindlabs/tailwindcss
NEW_GOLANGCI_LINT_VERSION="2.6.2" # https://github.com/golangci/golangci-lint
NEW_MOCKERY_VERSION="3.6.1" # https://github.com/vektra/mockery
NEW_DAISYUI_VERSION="5.5.5" # https://daisyui.com/
NEW_HUMANIZE_DURATION_VERSION="3.33.1" # https://www.npmjs.com/package/humanize-duration

BASE_DIR="../../"

# Version check results
LATEST_VERSIONS=()
VERSION_CHECK_FAILED=false

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Flags
DRY_RUN=false
VERBOSE=false
BACKUP=false
CHECK_VERSIONS=true

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --backup)
            BACKUP=true
            shift
            ;;
        --no-version-check)
            CHECK_VERSIONS=false
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --dry-run           Show what would be changed without making changes"
            echo "  --verbose           Show detailed output"
            echo "  --backup            Create .bak files before modifying"
            echo "  --no-version-check  Skip checking for newer versions online"
            echo "  --help              Show this help message"
            echo ""
            echo "Current version targets:"
            echo "  Goiabada:          $GOIABADA_VERSION"
            echo "  goiabada-setup:    $GOIABADA_SETUP_VERSION"
            echo "  Go:                $NEW_GO_VERSION"
            echo "  Tailwind CSS:      $NEW_TAILWIND_VERSION"
            echo "  golangci-lint:     $NEW_GOLANGCI_LINT_VERSION"
            echo "  mockery:           $NEW_MOCKERY_VERSION"
            echo "  daisyUI:           $NEW_DAISYUI_VERSION"
            echo "  humanize-duration: $NEW_HUMANIZE_DURATION_VERSION"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

if [ "$DRY_RUN" = true ]; then
    echo -e "${YELLOW}=== DRY RUN MODE - No files will be modified ===${NC}"
    echo ""
fi

# Counter for tracking changes
TOTAL_FILES=0
TOTAL_CHANGES=0
FAILED_UPDATES=0

# Function to check internet connectivity
check_internet() {
    if command -v curl &> /dev/null; then
        if curl -s --head --connect-timeout 5 https://api.github.com > /dev/null 2>&1; then
            return 0
        fi
    elif command -v wget &> /dev/null; then
        if wget -q --spider --timeout=5 https://api.github.com 2>&1; then
            return 0
        fi
    fi
    return 1
}

# Function to get latest GitHub release version
get_github_latest_version() {
    local repo="$1"
    local current_version="$2"

    if ! command -v curl &> /dev/null; then
        return 1
    fi

    # Try GitHub API (works without authentication, but has rate limits)
    local api_url="https://api.github.com/repos/${repo}/releases/latest"
    local response
    response=$(curl -s --connect-timeout 10 "$api_url" 2>/dev/null)

    if [ $? -eq 0 ] && [ -n "$response" ]; then
        # Extract tag_name and remove 'v' prefix if present
        local version
        version=$(echo "$response" | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4 | sed 's/^v//')

        if [ -n "$version" ]; then
            echo "$version"
            return 0
        fi
    fi

    return 1
}

# Function to get latest Go version
get_go_latest_version() {
    if ! command -v curl &> /dev/null; then
        return 1
    fi

    # Fetch Go downloads page and extract latest stable version
    local response
    response=$(curl -s --connect-timeout 10 "https://go.dev/dl/?mode=json" 2>/dev/null)

    if [ $? -eq 0 ] && [ -n "$response" ]; then
        # Extract the first stable version (format: "go1.25.4")
        local version
        version=$(echo "$response" | grep -o '"version"[[:space:]]*:[[:space:]]*"go[0-9.]*"' | head -1 | cut -d'"' -f4 | sed 's/^go//')

        if [ -n "$version" ]; then
            echo "$version"
            return 0
        fi
    fi

    return 1
}

# Function to get latest npm package version
get_npm_latest_version() {
    local package="$1"

    if ! command -v curl &> /dev/null; then
        return 1
    fi

    # Use npm registry API
    local api_url="https://registry.npmjs.org/${package}/latest"
    local response
    response=$(curl -s --connect-timeout 10 "$api_url" 2>/dev/null)

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

# Function to compare versions (returns 0 if v1 < v2, 1 if v1 >= v2)
version_lt() {
    local v1="$1"
    local v2="$2"

    # Simple version comparison using sort -V
    if [ "$(printf '%s\n' "$v1" "$v2" | sort -V | head -1)" = "$v1" ] && [ "$v1" != "$v2" ]; then
        return 0
    fi
    return 1
}

# Function to check for version updates
check_version_updates() {
    if [ "$CHECK_VERSIONS" = false ]; then
        return
    fi

    echo "=== Checking for Newer Versions ==="

    if ! check_internet; then
        echo -e "${YELLOW}⚠ No internet connection detected. Skipping version checks.${NC}"
        VERSION_CHECK_FAILED=true
        echo ""
        return
    fi

    # Check Go version
    echo -n "Checking Go version... "
    local latest_go
    latest_go=$(get_go_latest_version)
    if [ $? -eq 0 ] && [ -n "$latest_go" ]; then
        if version_lt "$NEW_GO_VERSION" "$latest_go"; then
            echo -e "${YELLOW}UPDATE AVAILABLE${NC}"
            LATEST_VERSIONS+=("Go|$NEW_GO_VERSION|$latest_go|https://go.dev/dl/")
        else
            echo -e "${GREEN}✓ Up to date${NC}"
        fi
    else
        echo -e "${YELLOW}⚠ Check failed${NC}"
        VERSION_CHECK_FAILED=true
    fi

    # Check Tailwind CSS version
    echo -n "Checking Tailwind CSS version... "
    local latest_tailwind
    latest_tailwind=$(get_github_latest_version "tailwindlabs/tailwindcss" "$NEW_TAILWIND_VERSION")
    if [ $? -eq 0 ] && [ -n "$latest_tailwind" ]; then
        if version_lt "$NEW_TAILWIND_VERSION" "$latest_tailwind"; then
            echo -e "${YELLOW}UPDATE AVAILABLE${NC}"
            LATEST_VERSIONS+=("Tailwind CSS|$NEW_TAILWIND_VERSION|$latest_tailwind|https://github.com/tailwindlabs/tailwindcss/releases")
        else
            echo -e "${GREEN}✓ Up to date${NC}"
        fi
    else
        echo -e "${YELLOW}⚠ Check failed${NC}"
        VERSION_CHECK_FAILED=true
    fi

    # Check golangci-lint version
    echo -n "Checking golangci-lint version... "
    local latest_golangci
    latest_golangci=$(get_github_latest_version "golangci/golangci-lint" "$NEW_GOLANGCI_LINT_VERSION")
    if [ $? -eq 0 ] && [ -n "$latest_golangci" ]; then
        if version_lt "$NEW_GOLANGCI_LINT_VERSION" "$latest_golangci"; then
            echo -e "${YELLOW}UPDATE AVAILABLE${NC}"
            LATEST_VERSIONS+=("golangci-lint|$NEW_GOLANGCI_LINT_VERSION|$latest_golangci|https://github.com/golangci/golangci-lint/releases")
        else
            echo -e "${GREEN}✓ Up to date${NC}"
        fi
    else
        echo -e "${YELLOW}⚠ Check failed${NC}"
        VERSION_CHECK_FAILED=true
    fi

    # Check mockery version
    echo -n "Checking mockery version... "
    local latest_mockery
    latest_mockery=$(get_github_latest_version "vektra/mockery" "$NEW_MOCKERY_VERSION")
    if [ $? -eq 0 ] && [ -n "$latest_mockery" ]; then
        if version_lt "$NEW_MOCKERY_VERSION" "$latest_mockery"; then
            echo -e "${YELLOW}UPDATE AVAILABLE${NC}"
            LATEST_VERSIONS+=("mockery|$NEW_MOCKERY_VERSION|$latest_mockery|https://github.com/vektra/mockery/releases")
        else
            echo -e "${GREEN}✓ Up to date${NC}"
        fi
    else
        echo -e "${YELLOW}⚠ Check failed${NC}"
        VERSION_CHECK_FAILED=true
    fi

    # Check daisyUI version
    echo -n "Checking daisyUI version... "
    local latest_daisyui
    latest_daisyui=$(get_npm_latest_version "daisyui")
    if [ $? -eq 0 ] && [ -n "$latest_daisyui" ]; then
        if version_lt "$NEW_DAISYUI_VERSION" "$latest_daisyui"; then
            echo -e "${YELLOW}UPDATE AVAILABLE${NC}"
            LATEST_VERSIONS+=("daisyUI|$NEW_DAISYUI_VERSION|$latest_daisyui|https://www.npmjs.com/package/daisyui")
        else
            echo -e "${GREEN}✓ Up to date${NC}"
        fi
    else
        echo -e "${YELLOW}⚠ Check failed${NC}"
        VERSION_CHECK_FAILED=true
    fi

    # Check humanize-duration version
    echo -n "Checking humanize-duration version... "
    local latest_humanize
    latest_humanize=$(get_npm_latest_version "humanize-duration")
    if [ $? -eq 0 ] && [ -n "$latest_humanize" ]; then
        if version_lt "$NEW_HUMANIZE_DURATION_VERSION" "$latest_humanize"; then
            echo -e "${YELLOW}UPDATE AVAILABLE${NC}"
            LATEST_VERSIONS+=("humanize-duration|$NEW_HUMANIZE_DURATION_VERSION|$latest_humanize|https://www.npmjs.com/package/humanize-duration")
        else
            echo -e "${GREEN}✓ Up to date${NC}"
        fi
    else
        echo -e "${YELLOW}⚠ Check failed${NC}"
        VERSION_CHECK_FAILED=true
    fi

    echo ""
}

# Function to update version in files with better error handling
update_version() {
    local file="$1"
    local old_pattern="$2"
    local new_pattern="$3"
    local description="$4"

    if [ ! -f "$file" ]; then
        echo -e "${RED}✗ File not found: $file${NC}"
        ((FAILED_UPDATES++))
        return 1
    fi

    # Check if pattern exists in file
    if ! grep -q "${old_pattern}" "$file" 2>/dev/null; then
        echo -e "${RED}✗ Pattern not found in $file${NC}"
        if [ "$VERBOSE" = true ]; then
            echo -e "${RED}  Pattern: ${old_pattern}${NC}"
        fi
        ((FAILED_UPDATES++))
        return 1
    fi

    if [ "$DRY_RUN" = true ]; then
        echo -e "${BLUE}[DRY RUN]${NC} Would update $file"
        if [ "$VERBOSE" = true ]; then
            echo -e "  ${BLUE}Description: $description${NC}"
            echo -e "  ${BLUE}Pattern: ${old_pattern}${NC}"
            echo -e "  ${BLUE}Replacement: ${new_pattern}${NC}"
            echo -e "  ${BLUE}Preview:${NC}"
            grep --color=always "${old_pattern}" "$file" | head -3
        fi
        ((TOTAL_CHANGES++))
    else
        # Create backup if requested
        if [ "$BACKUP" = true ]; then
            cp "$file" "$file.bak"
        fi

        # Perform the update
        if sed -i "s|${old_pattern}|${new_pattern}|g" "$file"; then
            echo -e "${GREEN}✓ Updated $file${NC}"
            if [ "$VERBOSE" = true ]; then
                echo -e "  ${GREEN}Description: $description${NC}"
                echo -e "  ${GREEN}${old_pattern} → ${new_pattern}${NC}"
            fi
            ((TOTAL_CHANGES++))
        else
            echo -e "${RED}✗ Failed to update $file${NC}"
            ((FAILED_UPDATES++))
            return 1
        fi
    fi

    ((TOTAL_FILES++))
    return 0
}

echo "=== Goiabada Version Update Script ==="
echo ""
echo "Target versions:"
echo "  Goiabada:          $GOIABADA_VERSION"
echo "  goiabada-setup:    $GOIABADA_SETUP_VERSION"
echo "  Go:                $NEW_GO_VERSION"
echo "  Tailwind CSS:      $NEW_TAILWIND_VERSION"
echo "  golangci-lint:     $NEW_GOLANGCI_LINT_VERSION"
echo "  mockery:           $NEW_MOCKERY_VERSION"
echo "  daisyUI:           $NEW_DAISYUI_VERSION"
echo "  humanize-duration: $NEW_HUMANIZE_DURATION_VERSION"
echo ""

# Check for version updates before proceeding
check_version_updates

# Update GitHub Actions workflow Go version
echo "=== GitHub Actions Workflows ==="
GITHUB_WORKFLOW_FILE="$BASE_DIR/.github/workflows/build-binaries.yml"
if [ -f "$GITHUB_WORKFLOW_FILE" ]; then
    update_version "$GITHUB_WORKFLOW_FILE" \
        "go-version: '[0-9.]\+'" \
        "go-version: '${NEW_GO_VERSION}'" \
        "Go version in GitHub Actions"
fi
echo ""

# Update build scripts with Goiabada version
echo "=== Build Scripts (Goiabada Version) ==="
BUILD_SCRIPTS=(
    "$BASE_DIR/src/build/build-binaries.sh"
    "$BASE_DIR/src/build/build-docker-images.sh"
    "$BASE_DIR/src/build/push-docker-images.sh"
)

for script in "${BUILD_SCRIPTS[@]}"; do
    if [ -f "$script" ]; then
        update_version "$script" \
            'VERSION="[0-9.]\+"' \
            "VERSION=\"${GOIABADA_VERSION}\"" \
            "Goiabada version"
    fi
done

# Update goiabada-setup Makefile version
SETUP_MAKEFILE="$BASE_DIR/src/cmd/goiabada-setup/Makefile"
if [ -f "$SETUP_MAKEFILE" ]; then
    update_version "$SETUP_MAKEFILE" \
        'VERSION ?= [0-9.]\+' \
        "VERSION ?= ${GOIABADA_SETUP_VERSION}" \
        "Goiabada setup tool Makefile version"
fi

# Update goiabada-setup main.go versions
SETUP_MAIN_GO="$BASE_DIR/src/cmd/goiabada-setup/main.go"
if [ -f "$SETUP_MAIN_GO" ]; then
    # Update version constant
    update_version "$SETUP_MAIN_GO" \
        'const version = "[0-9.]\+"' \
        "const version = \"${GOIABADA_SETUP_VERSION}\"" \
        "goiabada-setup version constant"

    # Update Docker image versions
    update_version "$SETUP_MAIN_GO" \
        'leodip/goiabada:authserver-[0-9.]\+' \
        "leodip/goiabada:authserver-${GOIABADA_VERSION}" \
        "Auth server Docker image version in setup wizard"

    update_version "$SETUP_MAIN_GO" \
        'leodip/goiabada:adminconsole-[0-9.]\+' \
        "leodip/goiabada:adminconsole-${GOIABADA_VERSION}" \
        "Admin console Docker image version in setup wizard"
fi
echo ""

# Update .devcontainer/Dockerfile
echo "=== DevContainer Configuration ==="
DEVCONTAINER_DOCKERFILE="$BASE_DIR/src/.devcontainer/Dockerfile"
if [ -f "$DEVCONTAINER_DOCKERFILE" ]; then
    update_version "$DEVCONTAINER_DOCKERFILE" \
        "go[0-9.]\+\.linux-amd64\.tar\.gz" \
        "go${NEW_GO_VERSION}.linux-amd64.tar.gz" \
        "Go tarball download URL"

    update_version "$DEVCONTAINER_DOCKERFILE" \
        "tailwindcss/releases/download/v[0-9.]\+/tailwindcss-linux-x64" \
        "tailwindcss/releases/download/v${NEW_TAILWIND_VERSION}/tailwindcss-linux-x64" \
        "Tailwind CSS download URL"

    update_version "$DEVCONTAINER_DOCKERFILE" \
        "golangci-lint@v[0-9.]\+" \
        "golangci-lint@v${NEW_GOLANGCI_LINT_VERSION}" \
        "golangci-lint version"

    update_version "$DEVCONTAINER_DOCKERFILE" \
        "mockery/v3@v[0-9.]\+" \
        "mockery/v3@v${NEW_MOCKERY_VERSION}" \
        "mockery version"
fi
echo ""

# Update production Dockerfiles
echo "=== Production Dockerfiles ==="
PRODUCTION_DOCKERFILES=(
    "$BASE_DIR/src/build/Dockerfile-adminconsole"
    "$BASE_DIR/src/build/Dockerfile-authserver"
    "$BASE_DIR/src/build/Dockerfile-test"
)

for dockerfile in "${PRODUCTION_DOCKERFILES[@]}"; do
    if [ -f "$dockerfile" ]; then
        update_version "$dockerfile" \
            "golang:[0-9.]\+-alpine" \
            "golang:${NEW_GO_VERSION}-alpine" \
            "Go base image version"

        # Only Dockerfile-test has Tailwind (uses musl for Alpine)
        if [[ "$dockerfile" == *"Dockerfile-test"* ]]; then
            update_version "$dockerfile" \
                "tailwindcss/releases/download/v[0-9.]\+/tailwindcss-linux-x64-musl" \
                "tailwindcss/releases/download/v${NEW_TAILWIND_VERSION}/tailwindcss-linux-x64-musl" \
                "Tailwind CSS download URL (musl for Alpine)"
        fi
    fi
done
echo ""

# Update go.mod files (main modules)
echo "=== Go Module Files (Main) ==="
MAIN_GO_MODS=(
    "$BASE_DIR/src/adminconsole/go.mod"
    "$BASE_DIR/src/authserver/go.mod"
    "$BASE_DIR/src/core/go.mod"
    "$BASE_DIR/src/cmd/goiabada-setup/go.mod"
)

for gomod in "${MAIN_GO_MODS[@]}"; do
    if [ -f "$gomod" ]; then
        update_version "$gomod" \
            "^go [0-9.]\+" \
            "go ${NEW_GO_VERSION}" \
            "Go version directive"
    fi
done
echo ""

# Note: Skipping test-integrations/go-webapp/go.mod (uses different Go version for testing)
echo ""

# Update daisyUI version in HTML files
# NOTE: HTML files use unpinned major version (@5) for CDN links
# We keep this pattern for auto-updates, but document the specific version in comments
echo "=== HTML Templates (Frontend Dependencies) ==="
DAISYUI_FILES=(
    "$BASE_DIR/src/authserver/web/template/layouts/auth_layout.html"
    "$BASE_DIR/src/authserver/web/template/layouts/no_menu_layout.html"
    "$BASE_DIR/src/adminconsole/web/template/layouts/no_menu_layout.html"
    "$BASE_DIR/src/adminconsole/web/template/layouts/menu_layout.html"
)

for html_file in "${DAISYUI_FILES[@]}"; do
    if [ -f "$html_file" ]; then
        update_version "$html_file" \
            "daisyui@[0-9.]\+" \
            "daisyui@${NEW_DAISYUI_VERSION}" \
            "daisyUI CDN version"
    fi
done
echo ""

# Update humanize-duration version
MENU_LAYOUT_HTML="$BASE_DIR/src/adminconsole/web/template/layouts/menu_layout.html"
if [ -f "$MENU_LAYOUT_HTML" ]; then
    update_version "$MENU_LAYOUT_HTML" \
        "humanize-duration@[0-9.]\+/" \
        "humanize-duration@${NEW_HUMANIZE_DURATION_VERSION}/" \
        "humanize-duration CDN version"
fi
echo ""

# Update Go module dependencies
if [ "$DRY_RUN" = false ]; then
    echo "=== Updating Go Module Dependencies ==="

    # Main modules that depend on core (need special handling)
    GO_MODULES_WITH_CORE=(
        "$BASE_DIR/src/core"
        "$BASE_DIR/src/authserver"
        "$BASE_DIR/src/adminconsole"
    )

    for module_dir in "${GO_MODULES_WITH_CORE[@]}"; do
        if [ -d "$module_dir" ]; then
            echo -e "${BLUE}Updating dependencies in ${module_dir}...${NC}"

            # Change to module directory
            pushd "$module_dir" > /dev/null 2>&1

            # Update dependencies
            # Note: go get -u ./... will try to update the core module from GitHub
            # The replace directive ensures we use the local version, but we reset it after
            if go get -u ./... > /tmp/go-get-output-$$.log 2>&1; then
                # Reset core module back to v0.0.0 (local pseudo-version)
                go mod edit -require=github.com/leodip/goiabada/core@v0.0.0
                echo -e "${GREEN}✓ go get -u ./... succeeded${NC}"
            else
                echo -e "${RED}✗ go get -u ./... failed${NC}"
                cat /tmp/go-get-output-$$.log
                ((FAILED_UPDATES++))
            fi
            rm -f /tmp/go-get-output-$$.log

            # Tidy up (this will respect the replace directive)
            if go mod tidy > /tmp/go-mod-tidy-output-$$.log 2>&1; then
                echo -e "${GREEN}✓ go mod tidy succeeded${NC}"
            else
                echo -e "${RED}✗ go mod tidy failed${NC}"
                cat /tmp/go-mod-tidy-output-$$.log
                ((FAILED_UPDATES++))
            fi
            rm -f /tmp/go-mod-tidy-output-$$.log

            # Return to original directory
            popd > /dev/null 2>&1
            echo ""
        fi
    done

    # Standalone modules (no core dependency)
    GO_MODULES_STANDALONE=(
        "$BASE_DIR/src/cmd/goiabada-setup"
    )

    for module_dir in "${GO_MODULES_STANDALONE[@]}"; do
        if [ -d "$module_dir" ]; then
            echo -e "${BLUE}Updating dependencies in ${module_dir}...${NC}"

            # Change to module directory
            pushd "$module_dir" > /dev/null 2>&1

            # Update dependencies
            if go get -u ./... > /tmp/go-get-output-$$.log 2>&1; then
                echo -e "${GREEN}✓ go get -u ./... succeeded${NC}"
            else
                echo -e "${RED}✗ go get -u ./... failed${NC}"
                cat /tmp/go-get-output-$$.log
                ((FAILED_UPDATES++))
            fi
            rm -f /tmp/go-get-output-$$.log

            # Tidy up
            if go mod tidy > /tmp/go-mod-tidy-output-$$.log 2>&1; then
                echo -e "${GREEN}✓ go mod tidy succeeded${NC}"
            else
                echo -e "${RED}✗ go mod tidy failed${NC}"
                cat /tmp/go-mod-tidy-output-$$.log
                ((FAILED_UPDATES++))
            fi
            rm -f /tmp/go-mod-tidy-output-$$.log

            # Return to original directory
            popd > /dev/null 2>&1
            echo ""
        fi
    done
else
    echo "=== Updating Go Module Dependencies ==="
    echo -e "${BLUE}[DRY RUN] Would run 'go get -u ./...' and 'go mod tidy' in:${NC}"
    echo -e "${BLUE}  - src/core${NC}"
    echo -e "${BLUE}  - src/authserver${NC}"
    echo -e "${BLUE}  - src/adminconsole${NC}"
    echo -e "${BLUE}  - src/cmd/goiabada-setup${NC}"
    echo ""
fi

# Summary
echo "=== Update Summary ==="
echo -e "Files processed:  ${TOTAL_FILES}"
echo -e "${GREEN}Successful updates: ${TOTAL_CHANGES}${NC}"
if [ $FAILED_UPDATES -gt 0 ]; then
    echo -e "${RED}Failed updates:     ${FAILED_UPDATES}${NC}"
fi
echo ""

# Report version check results
if [ "$CHECK_VERSIONS" = true ]; then
    if [ ${#LATEST_VERSIONS[@]} -gt 0 ]; then
        echo "=== Available Version Updates ==="
        echo -e "${YELLOW}The following dependencies have newer versions available:${NC}"
        echo ""

        printf "%-20s %-12s %-12s %s\n" "Dependency" "Current" "Latest" "URL"
        printf "%-20s %-12s %-12s %s\n" "----------" "-------" "------" "---"

        for version_info in "${LATEST_VERSIONS[@]}"; do
            IFS='|' read -r name current latest url <<< "$version_info"
            printf "${YELLOW}%-20s${NC} %-12s ${GREEN}%-12s${NC} ${BLUE}%s${NC}\n" "$name" "$current" "$latest" "$url"
        done

        echo ""
        echo -e "${YELLOW}To update, modify the NEW_*_VERSION variables at the top of this script.${NC}"
        echo ""
    elif [ "$VERSION_CHECK_FAILED" = false ]; then
        echo "=== Version Check Results ==="
        echo -e "${GREEN}✓ All dependencies are up to date!${NC}"
        echo ""
    fi
fi

if [ "$DRY_RUN" = true ]; then
    echo -e "${YELLOW}This was a dry run. No files were modified.${NC}"
    echo -e "${YELLOW}Run without --dry-run to apply changes.${NC}"
else
    echo -e "${GREEN}Version update complete.${NC}"
    if [ "$BACKUP" = true ]; then
        echo -e "${GREEN}Backup files created with .bak extension.${NC}"
    fi
    echo ""
    echo "Next steps:"
    echo "  1. Review the changes: git diff"
    echo "  2. Run tests to verify: make test-ci"
    echo "  3. Build binaries: make build"
fi

exit $FAILED_UPDATES
