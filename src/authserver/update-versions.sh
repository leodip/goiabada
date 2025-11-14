#!/bin/bash

GOIABADA_VERSION="1.2"
NEW_GO_VERSION="1.25.4" # https://go.dev/dl/
NEW_TAILWIND_VERSION="4.1.17" # https://github.com/tailwindlabs/tailwindcss
NEW_GOLANGCI_LINT_VERSION="2.6.2" # https://github.com/golangci/golangci-lint
NEW_MOCKERY_VERSION="3.6.0" # https://github.com/vektra/mockery
NEW_DAISYUI_VERSION="5.5.3" # https://daisyui.com/
NEW_HUMANIZE_DURATION_VERSION="3.33.1" # https://www.npmjs.com/package/humanize-duration

BASE_DIR="../../"

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
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --dry-run    Show what would be changed without making changes"
            echo "  --verbose    Show detailed output"
            echo "  --backup     Create .bak files before modifying"
            echo "  --help       Show this help message"
            echo ""
            echo "Current version targets:"
            echo "  Goiabada:         $GOIABADA_VERSION"
            echo "  Go:               $NEW_GO_VERSION"
            echo "  Tailwind CSS:     $NEW_TAILWIND_VERSION"
            echo "  golangci-lint:    $NEW_GOLANGCI_LINT_VERSION"
            echo "  mockery:          $NEW_MOCKERY_VERSION"
            echo "  daisyUI:          $NEW_DAISYUI_VERSION"
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
echo "  Go:                $NEW_GO_VERSION"
echo "  Tailwind CSS:      $NEW_TAILWIND_VERSION"
echo "  golangci-lint:     $NEW_GOLANGCI_LINT_VERSION"
echo "  mockery:           $NEW_MOCKERY_VERSION"
echo "  daisyUI:           $NEW_DAISYUI_VERSION"
echo "  humanize-duration: $NEW_HUMANIZE_DURATION_VERSION"
echo ""

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

        # Only Dockerfile-test has Tailwind
        if [[ "$dockerfile" == *"Dockerfile-test"* ]]; then
            update_version "$dockerfile" \
                "tailwindcss/releases/download/v[0-9.]\+/tailwindcss-linux-x64" \
                "tailwindcss/releases/download/v${NEW_TAILWIND_VERSION}/tailwindcss-linux-x64" \
                "Tailwind CSS download URL"
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
        # Update daisyUI CDN links (these use @5 for auto-updates within v5)
        # We keep the major version pattern as intended by the design
        echo -e "${BLUE}ℹ ${html_file}${NC}"
        echo -e "${BLUE}  Note: daisyUI uses @5 pattern for automatic minor updates${NC}"
        echo -e "${BLUE}  Current pinned version for reference: ${NEW_DAISYUI_VERSION}${NC}"

        # If you want to pin to exact version, uncomment this:
        # update_version "$html_file" \
        #     "daisyui@[0-9]\+" \
        #     "daisyui@${NEW_DAISYUI_VERSION}" \
        #     "daisyUI exact version"
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

    GO_MODULES=(
        "$BASE_DIR/src/core"
        "$BASE_DIR/src/authserver"
        "$BASE_DIR/src/adminconsole"
    )

    for module_dir in "${GO_MODULES[@]}"; do
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
else
    echo "=== Updating Go Module Dependencies ==="
    echo -e "${BLUE}[DRY RUN] Would run 'go get -u ./...' and 'go mod tidy' in:${NC}"
    echo -e "${BLUE}  - src/core${NC}"
    echo -e "${BLUE}  - src/authserver${NC}"
    echo -e "${BLUE}  - src/adminconsole${NC}"
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
