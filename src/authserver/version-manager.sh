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
#   generate - Regenerate committed data files (timezones, countries)
#   override-status - Report whether unparam and mockery still need tools.x-tools-override
#   all     - Run all commands in sequence (check → update → deps)
#
# Scope: this script manages TOOLCHAIN and CDN pins (Go, Tailwind,
# golangci-lint, mockery, staticcheck, unparam, govulncheck, the release
# images' Alpine base, daisyUI, humanize-duration). It does NOT manage the product version.
#
# Workflow, for bumping a tool or CDN pin:
#   1. Edit versions.yaml to set desired versions
#   2. Run: ./version-manager.sh update
#   3. Review changes: git diff
#   4. Run tests and build
#
# Releasing the product is a separate activity and needs none of this:
#   git tag vX.Y.Z && git push origin vX.Y.Z
#
# The version compiled into the binaries, the Docker image tags and the image
# tags written into the setup wizard's generated manifests all derive from that
# one tag via ldflags, so they cannot disagree with each other.
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
# Usage: get_version "tools.go" -> "1.26.5"
get_version() {
    local key="$1"
    yq -r ".$key" "$VERSIONS_FILE"
}

# vendor_fetch downloads one pinned web dependency into the repository, and with a digest key
# writes the file's SHA-256 beside its pin in versions.yaml, which the web packages' tests hold
# the committed file to (#542). The digest line is rewritten with sed, as update_file does,
# since only one yq flavour keeps the file's comments.
# Usage: vendor_fetch URL DEST [DIGEST_KEY]
vendor_fetch() {
    local url="$1" dest="$2" digest_key="${3:-}"
    local tmp
    tmp=$(mktemp) || return 1
    if ! curl -sSfL --max-time 120 "$url" -o "$tmp"; then
        print_error "Unable to download $url"
        rm -f "$tmp"
        return 1
    fi
    mkdir -p "$(dirname "$dest")"
    mv "$tmp" "$dest"
    chmod 0644 "$dest"
    if [ -n "$digest_key" ]; then
        local digest
        if command -v sha256sum >/dev/null 2>&1; then
            digest=$(sha256sum "$dest" | cut -d' ' -f1)
        else
            digest=$(shasum -a 256 "$dest" | cut -d' ' -f1)
        fi
        if ! grep -q "^  ${digest_key}: " "$VERSIONS_FILE"; then
            print_error "versions.yaml has no vendored.${digest_key} to record the digest under"
            return 1
        fi
        sed -i "s|^  ${digest_key}: .*|  ${digest_key}: \"${digest}\"|" "$VERSIONS_FILE"
    fi
    print_success "$(basename "$dest") from $url"
}

# Get all versions as key=value pairs for display
get_all_versions() {
    yq -r '
        .tools | to_entries | .[] | "tools." + .key + "=" + .value,
        .vendored | to_entries | .[] | "vendored." + .key + "=" + .value
    ' "$VERSIONS_FILE" 2>/dev/null || {
        # Fallback: read each key individually
        echo "tools.go=$(get_version 'tools.go')"
        echo "tools.tailwind=$(get_version 'tools.tailwind')"
        echo "tools.golangci-lint=$(get_version 'tools.golangci-lint')"
        echo "tools.mockery=$(get_version 'tools.mockery')"
        echo "tools.staticcheck=$(get_version 'tools.staticcheck')"
        echo "tools.unparam=$(get_version 'tools.unparam')"
        echo "tools.govulncheck=$(get_version 'tools.govulncheck')"
        echo "tools.x-tools-override=$(get_version 'tools."x-tools-override"')"
        echo "tools.alpine=$(get_version 'tools.alpine')"
        echo "vendored.daisyui=$(get_version 'vendored.daisyui')"
        echo "vendored.humanize-duration=$(get_version 'vendored.humanize-duration')"
        echo "vendored.cropperjs=$(get_version 'vendored.cropperjs')"
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

# Fetch latest version from the Go module proxy
# Usage: get_goproxy_latest "honnef.co/go/tools"
#
# Used instead of get_github_latest for Go tools whose module version does not
# match their GitHub release tag. dominikh/go-tools tags releases as "2026.1"
# while the module is v0.7.0, so comparing against the release tag would report
# an update forever; golang/vuln's releases page trails its module tags by
# several minors, so it would never report one. The proxy is authoritative for
# what `go install` will actually fetch, which is what we pin.
get_goproxy_latest() {
    local module="$1"
    local response
    response=$(curl -s --connect-timeout 10 "https://proxy.golang.org/${module}/@latest" 2>/dev/null)
    if [ $? -eq 0 ] && [ -n "$response" ]; then
        echo "$response" | grep -o '"Version"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4 | sed 's/^v//'
    fi
}

# The version of one requirement in a module version's go.mod, read from the Go module proxy, without
# its leading v. Usage: get_goproxy_requirement "mvdan.cc/unparam" "0.0.0-2026..." "golang.org/x/tools"
get_goproxy_requirement() {
    local module="$1"
    local version="$2"
    local requirement="$3"
    local response
    response=$(curl -s --connect-timeout 10 "https://proxy.golang.org/${module}/@v/v${version}.mod" 2>/dev/null)
    if [ $? -eq 0 ] && [ -n "$response" ]; then
        echo "$response" | awk -v r="$requirement" '$1 == r { print $2; exit } $1 == "require" && $2 == r { print $3; exit }' | sed 's/^v//'
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

# Reduce Alpine's releases.json, read on stdin, to its newest stable release as
# major.minor, the form tools.alpine pins.
#
# Only an X.Y.Z version counts: edge publishes no release, and a release
# candidate's version carries a suffix (3.25.0_rc1). A patch release does not
# make the minor newer, so 3.24.2 reads as 3.24 (#396).
alpine_latest_minor() {
    grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' \
        | cut -d'"' -f4 \
        | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' \
        | cut -d. -f1,2 \
        | sort -V \
        | tail -1
}

# Fetch the newest stable Alpine minor from alpinelinux.org
get_alpine_latest() {
    local response
    response=$(curl -s --connect-timeout 10 "https://alpinelinux.org/releases.json" 2>/dev/null)
    if [ $? -eq 0 ] && [ -n "$response" ]; then
        echo "$response" | alpine_latest_minor
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

    # Product version, which this file does not own. Reported from git so that
    # `show` remains the one place that answers "what versions is this project
    # on", even though the answer now comes from two different sources.
    echo -e "\n${BOLD}Product (from git tags, not this file):${NC}"
    printf "  %-23s ${GREEN}%s${NC}\n" "latest tag" "$(git describe --tags --abbrev=0 2>/dev/null || echo 'none')"
    printf "  %-23s ${GREEN}%s${NC}\n" "working tree" "$(git describe --tags --dirty 2>/dev/null || echo 'unknown')"

    # Tool versions
    echo -e "\n${BOLD}Tools:${NC}"
    printf "  %-23s ${GREEN}%s${NC}\n" "go" "$(get_version 'tools.go')"
    printf "  %-23s ${GREEN}%s${NC}\n" "tailwind" "$(get_version 'tools.tailwind')"
    printf "  %-23s ${GREEN}%s${NC}\n" "golangci-lint" "$(get_version 'tools.golangci-lint')"
    printf "  %-23s ${GREEN}%s${NC}\n" "mockery" "$(get_version 'tools.mockery')"
    printf "  %-23s ${GREEN}%s${NC}\n" "staticcheck" "$(get_version 'tools.staticcheck')"
    printf "  %-23s ${GREEN}%s${NC}\n" "unparam" "$(get_version 'tools.unparam')"
    printf "  %-23s ${GREEN}%s${NC}\n" "govulncheck" "$(get_version 'tools.govulncheck')"
    printf "  %-23s ${GREEN}%s${NC}\n" "x-tools-override" "$(get_version 'tools."x-tools-override"')"
    printf "  %-23s ${GREEN}%s${NC}\n" "alpine" "$(get_version 'tools.alpine')"

    # Vendored web dependencies
    echo -e "\n${BOLD}Vendored web dependencies:${NC}"
    printf "  %-23s ${GREEN}%s${NC}\n" "daisyui" "$(get_version 'vendored.daisyui')"
    printf "  %-23s ${GREEN}%s${NC}\n" "humanize-duration" "$(get_version 'vendored.humanize-duration')"
    printf "  %-23s ${GREEN}%s${NC}\n" "cropperjs" "$(get_version 'vendored.cropperjs')"

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

    # --- staticcheck ---
    # Queried via the Go module proxy, not GitHub releases: the release tag is
    # "2026.1" while the module version is 0.7.0, and comparing those two
    # schemes would report an update on every run.
    echo -n "Checking staticcheck... "
    local current_staticcheck=$(get_version 'tools.staticcheck')
    local latest_staticcheck=$(get_goproxy_latest "honnef.co/go/tools")
    if [ -n "$latest_staticcheck" ]; then
        if version_lt "$current_staticcheck" "$latest_staticcheck"; then
            echo -e "${YELLOW}UPDATE AVAILABLE${NC}"
            updates_available+=("staticcheck|$current_staticcheck|$latest_staticcheck|https://github.com/dominikh/go-tools/releases")
        else
            print_success "Up to date ($current_staticcheck)"
        fi
    else
        print_warning "Check failed"
    fi

    # --- unparam ---
    # unparam publishes no tags, so the proxy returns a pseudo-version and any
    # upstream commit shows as an available update. That is the only signal
    # this module offers.
    echo -n "Checking unparam... "
    local current_unparam=$(get_version 'tools.unparam')
    local latest_unparam=$(get_goproxy_latest "mvdan.cc/unparam")
    if [ -n "$latest_unparam" ]; then
        if version_lt "$current_unparam" "$latest_unparam"; then
            echo -e "${YELLOW}UPDATE AVAILABLE${NC}"
            updates_available+=("unparam|$current_unparam|$latest_unparam|https://github.com/mvdan/unparam/commits/master")
        else
            print_success "Up to date ($current_unparam)"
        fi
    else
        print_warning "Check failed"
    fi

    # --- govulncheck ---
    # Also proxy-queried: golang/vuln's GitHub releases page trails its module
    # tags by several minor versions.
    echo -n "Checking govulncheck... "
    local current_govulncheck=$(get_version 'tools.govulncheck')
    local latest_govulncheck=$(get_goproxy_latest "golang.org/x/vuln")
    if [ -n "$latest_govulncheck" ]; then
        if version_lt "$current_govulncheck" "$latest_govulncheck"; then
            echo -e "${YELLOW}UPDATE AVAILABLE${NC}"
            updates_available+=("govulncheck|$current_govulncheck|$latest_govulncheck|https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck")
        else
            print_success "Up to date ($current_govulncheck)"
        fi
    else
        print_warning "Check failed"
    fi

    # --- Alpine ---
    # The release images' final stage. alpine:X.Y picks up patch releases at
    # the next image build, so only a newer minor is an update (#396).
    echo -n "Checking Alpine... "
    local current_alpine=$(get_version 'tools.alpine')
    local latest_alpine=$(get_alpine_latest)
    if [ -n "$latest_alpine" ]; then
        if version_lt "$current_alpine" "$latest_alpine"; then
            echo -e "${YELLOW}UPDATE AVAILABLE${NC}"
            updates_available+=("Alpine|$current_alpine|$latest_alpine|https://alpinelinux.org/releases/")
        else
            print_success "Up to date ($current_alpine)"
        fi
    else
        print_warning "Check failed"
    fi

    # --- daisyUI ---
    echo -n "Checking daisyUI... "
    local current_daisyui=$(get_version 'vendored.daisyui')
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
    local current_humanize=$(get_version 'vendored.humanize-duration')
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

    # --- cropperjs ---
    # Only 1.x: 2.x is a rewrite with another API, which the admin console's croppers don't use.
    echo -n "Checking cropperjs... "
    local current_cropper=$(get_version 'vendored.cropperjs')
    local latest_cropper=$(get_npm_latest "cropperjs")
    if [ -n "$latest_cropper" ]; then
        if [ "${latest_cropper%%.*}" != "${current_cropper%%.*}" ]; then
            print_success "Up to date on ${current_cropper%%.*}.x ($current_cropper); $latest_cropper is another API"
        elif version_lt "$current_cropper" "$latest_cropper"; then
            echo -e "${YELLOW}UPDATE AVAILABLE${NC}"
            updates_available+=("cropperjs|$current_cropper|$latest_cropper|https://www.npmjs.com/package/cropperjs")
        else
            print_success "Up to date ($current_cropper)"
        fi
    else
        print_warning "Check failed"
    fi

    # --- x/tools override ---
    echo ""
    override_report

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
    local GO_VERSION=$(get_version 'tools.go')
    local TAILWIND_VERSION=$(get_version 'tools.tailwind')
    local GOLANGCI_VERSION=$(get_version 'tools.golangci-lint')
    local MOCKERY_VERSION=$(get_version 'tools.mockery')
    local STATICCHECK_VERSION=$(get_version 'tools.staticcheck')
    local UNPARAM_VERSION=$(get_version 'tools.unparam')
    local GOVULNCHECK_VERSION=$(get_version 'tools.govulncheck')
    local XTOOLS_OVERRIDE=$(get_version 'tools."x-tools-override"')
    local ALPINE_VERSION=$(get_version 'tools.alpine')
    local DAISYUI_VERSION=$(get_version 'vendored.daisyui')
    local HUMANIZE_VERSION=$(get_version 'vendored.humanize-duration')
    local CROPPER_VERSION=$(get_version 'vendored.cropperjs')

    local success_count=0
    local fail_count=0

    # -------------------------------------------------------------------------
    # Product version: not handled here
    # -------------------------------------------------------------------------
    # The build scripts' VERSION= lines, the setup tool's Makefile, its
    # `const version` and the four leodip/goiabada image tags in its main.go
    # used to be generated from project.goiabada and project.goiabada-setup.
    # All of them now come from the git tag via ldflags at build time, so there
    # is nothing to write: the tag and the version compiled into the binaries
    # cannot disagree, rather than agreeing only because the release procedure
    # was followed in the right order.

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

        # staticcheck: staticcheck@vX.Y.Z
        if update_file "$BASE_DIR/src/.devcontainer/Dockerfile" \
            "s|staticcheck@v[0-9.]*|staticcheck@v${STATICCHECK_VERSION}|g" \
            "staticcheck"; then
            ((success_count++))
        else
            ((fail_count++))
        fi

        # unparam: unparam@v0.0.0-TIMESTAMP-HASH. The character class has to be
        # wider than the others because upstream publishes no tags, so this is
        # always a pseudo-version.
        if update_file "$BASE_DIR/src/.devcontainer/Dockerfile" \
            "s|unparam@v[0-9A-Za-z.-]*|unparam@v${UNPARAM_VERSION}|g" \
            "unparam"; then
            ((success_count++))
        else
            ((fail_count++))
        fi

        # govulncheck: govulncheck@vX.Y.Z
        if update_file "$BASE_DIR/src/.devcontainer/Dockerfile" \
            "s|govulncheck@v[0-9.]*|govulncheck@v${GOVULNCHECK_VERSION}|g" \
            "govulncheck"; then
            ((success_count++))
        else
            ((fail_count++))
        fi

        # The x/tools unparam and mockery are built against: golang.org/x/tools@vX.Y.Z, an
        # argument of go-install-with-x-tools.sh. gopls and goimports are installed from
        # golang.org/x/tools/... paths, which this pattern does not match.
        if [ -n "$XTOOLS_OVERRIDE" ] && [ "$XTOOLS_OVERRIDE" != "null" ]; then
            if update_file "$BASE_DIR/src/.devcontainer/Dockerfile" \
                "s|golang.org/x/tools@v[0-9.]*|golang.org/x/tools@v${XTOOLS_OVERRIDE}|g" \
                "x/tools override"; then
                ((success_count++))
            else
                ((fail_count++))
            fi
        fi
    fi

    # -------------------------------------------------------------------------
    # Generated mock header
    # -------------------------------------------------------------------------
    # src/mockery-header.txt is inlined verbatim into the header of every
    # generated mock, through template-data.boilerplate-file in the two
    # .mockery.yaml files, so a clone can read which generator wrote the tree
    # rather than having to run one to find out.
    #
    # Writing it here is what keeps that line the pin instead of a literal
    # somebody remembered to change. It does not carry itself into the mocks:
    # regenerating does that, which is why this is the one target of `update`
    # whose application needs a second command. Both halves are checked --
    # every module's unit tier holds the mocks to this file and this file to
    # versions.yaml, and generate-mocks.sh refuses a mockery that is not the
    # pin, so the stamped version is the generator that ran (#338).
    echo -e "\n${BOLD}Generated Mocks${NC}"

    if [ -f "$BASE_DIR/src/mockery-header.txt" ]; then
        # Generator version: mockery vX.Y.Z
        if update_file "$BASE_DIR/src/mockery-header.txt" \
            "s|mockery v[0-9.]*|mockery v${MOCKERY_VERSION}|g" \
            "mockery header"; then
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
                      "$BASE_DIR/src/build/Dockerfile-authserver"; do
        if [ -f "$dockerfile" ]; then
            # Go base image: golang:X.Y.Z-alpine
            if update_file "$dockerfile" \
                "s|golang:[0-9.]*-alpine|golang:${GO_VERSION}-alpine|g" \
                "Go base image"; then
                ((success_count++))
            else
                ((fail_count++))
            fi

            # Alpine base of the release images' final stage: FROM alpine:X.Y.
            if update_file "$dockerfile" \
                "s|^FROM alpine:[0-9.]* |FROM alpine:${ALPINE_VERSION} |" \
                "Alpine base image"; then
                ((success_count++))
            else
                ((fail_count++))
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
                 "$BASE_DIR/src/cmd/goiabada-setup/go.mod"; do
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
    # Vendored web dependencies
    # -------------------------------------------------------------------------
    # The pinned version of each, downloaded into the repository with its license and
    # its digest written beside the pin; no page loads them from a CDN (#542).
    echo -e "\n${BOLD}Vendored web dependencies${NC}"
    local daisyui_before
    daisyui_before=$(get_version 'vendored."daisyui-sha256"')
    # One bundle, beside each server's input.css, so a copy of either tailwindcss folder builds on
    # its own, as the customization guide has operators copy it.
    local daisyui_ok=1
    for m in authserver adminconsole; do
        local tw="$BASE_DIR/src/$m/web/tailwindcss"
        vendor_fetch "https://github.com/saadeghi/daisyui/releases/download/v${DAISYUI_VERSION}/daisyui.mjs" \
            "$tw/daisyui.mjs" "daisyui-sha256" &&
            vendor_fetch "https://cdn.jsdelivr.net/npm/daisyui@${DAISYUI_VERSION}/LICENSE" \
                "$tw/daisyui.LICENSE" || daisyui_ok=0
    done
    if [ "$daisyui_ok" -eq 1 ]; then
        ((success_count++))
    else
        ((fail_count++))
    fi
    local humanize_dir="$BASE_DIR/src/adminconsole/web/static/vendor/humanize-duration"
    if vendor_fetch "https://cdn.jsdelivr.net/npm/humanize-duration@${HUMANIZE_VERSION}/humanize-duration.js" \
            "$humanize_dir/humanize-duration.js" "humanize-duration-sha256" &&
        vendor_fetch "https://cdn.jsdelivr.net/npm/humanize-duration@${HUMANIZE_VERSION}/LICENSE.txt" \
            "$humanize_dir/LICENSE"; then
        ((success_count++))
    else
        ((fail_count++))
    fi
    local cropper_dir="$BASE_DIR/src/adminconsole/web/static/vendor/cropperjs"
    if vendor_fetch "https://cdn.jsdelivr.net/npm/cropperjs@${CROPPER_VERSION}/dist/cropper.min.js" \
            "$cropper_dir/cropper.min.js" "cropperjs-js-sha256" &&
        vendor_fetch "https://cdn.jsdelivr.net/npm/cropperjs@${CROPPER_VERSION}/dist/cropper.min.css" \
            "$cropper_dir/cropper.min.css" "cropperjs-css-sha256" &&
        vendor_fetch "https://cdn.jsdelivr.net/npm/cropperjs@${CROPPER_VERSION}/LICENSE" \
            "$cropper_dir/LICENSE"; then
        ((success_count++))
    else
        ((fail_count++))
    fi
    if [ "$daisyui_before" != "$(get_version 'vendored."daisyui-sha256"')" ]; then
        print_warning "daisyUI changed: regenerate main.css with ./build.sh in src/authserver and"
        echo "  src/adminconsole, inside the dev container, and commit it with the new bundle."
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
    echo "  2. If tools.mockery changed, rebuild the dev container and run ./generate-mocks.sh:"
    echo "     the header above is written here, but only the generator carries it into the mocks"
    echo "  3. Run tests: make test-ci"
    echo "  4. Commit changes"
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

    echo ""
    print_success "Dependency update complete"
}

# =============================================================================
# Command: override-status
# =============================================================================
# Whether unparam and mockery still need tools.x-tools-override: for each, the golang.org/x/tools
# its latest upstream version requires, from the Go module proxy, against the override. The daily
# Upstream tools workflow runs this and opens an issue on exit 3. Plain text, no colour, because the
# workflow puts it in the issue.
#
# Exit status: 0 when both still need the override or none is pinned, 3 when at least one no
# longer does, 1 when a lookup failed.

# override_report prints one line per tool and sets OVERRIDE_CAUGHT_UP and OVERRIDE_FAILED.
override_report() {
    OVERRIDE_CAUGHT_UP=0
    OVERRIDE_FAILED=0
    local override
    override=$(get_version 'tools."x-tools-override"')
    if [ -z "$override" ] || [ "$override" = "null" ]; then
        echo "No x/tools override is pinned: unparam and mockery are installed with plain go install."
        return 0
    fi
    echo "unparam and mockery are built against golang.org/x/tools v${override} (tools.x-tools-override)."
    local entry name module latest required
    for entry in "unparam|mvdan.cc/unparam" "mockery|github.com/vektra/mockery/v3"; do
        IFS='|' read -r name module <<< "$entry"
        latest=$(get_goproxy_latest "$module")
        if [ -z "$latest" ]; then
            echo "- ${name}: unable to read its latest version from the Go module proxy"
            OVERRIDE_FAILED=1
            continue
        fi
        required=$(get_goproxy_requirement "$module" "$latest" "golang.org/x/tools")
        if [ -z "$required" ]; then
            echo "- ${name} v${latest}: unable to read the golang.org/x/tools its go.mod requires"
            OVERRIDE_FAILED=1
            continue
        fi
        if version_lt "$required" "$override"; then
            echo "- ${name} v${latest} requires golang.org/x/tools v${required}, older than the override: still needed"
        else
            echo "- ${name} v${latest} requires golang.org/x/tools v${required}, at least the override: pin ${name} to v${latest} and install it with plain go install again"
            OVERRIDE_CAUGHT_UP=1
        fi
    done
}

cmd_override_status() {
    require_yq
    override_report
    if [ "$OVERRIDE_FAILED" -ne 0 ]; then
        return 1
    fi
    if [ "$OVERRIDE_CAUGHT_UP" -ne 0 ]; then
        return 3
    fi
    return 0
}

# =============================================================================
# Command: generate
# =============================================================================
# Regenerate committed "// Code generated" data files from their upstream
# sources. Each target has a `generate/` sub-package run with `go run .`:
#   timezones -> src/core/timezones/data_generated.go  (from IANA tzdata)
#   countries -> src/core/countries/data_generated.go  (from datahub CSV)
#
# Usage: generate [timezones|countries|all]   (default: all)
#
# Exit status: the script omits 'set -e', so exit codes are captured
# explicitly. An unknown target, a missing generator dir, or any `go run`
# failure returns non-zero; for 'all', any target failing fails the whole
# command. (Verified via documented manual checks -- see the migration plan --
# rather than a shell-test framework, which the repo does not use.)

cmd_generate() {
    local target="${1:-all}"

    local pkgs=()
    case "$target" in
        timezones) pkgs=("timezones") ;;
        countries) pkgs=("countries") ;;
        all)       pkgs=("timezones" "countries") ;;
        *)
            print_error "Unknown generate target: ${target}"
            echo "Valid targets: timezones, countries, all"
            return 1
            ;;
    esac

    print_header "Regenerating data (${target})"

    local rc=0
    for pkg in "${pkgs[@]}"; do
        local gen_dir="${BASE_DIR}/src/core/${pkg}/generate"
        if [ ! -d "$gen_dir" ]; then
            print_error "generator directory not found: ${gen_dir}"
            rc=1
            continue
        fi

        echo -e "\n${BOLD}Generating ${pkg}${NC}"
        pushd "$gen_dir" > /dev/null 2>&1 || { print_error "cannot enter ${gen_dir}"; rc=1; continue; }

        go run .
        local status=$?
        popd > /dev/null 2>&1

        if [ "$status" -eq 0 ]; then
            print_success "generated ${pkg}"
        else
            print_error "generate ${pkg} failed (exit ${status})"
            rc=1
        fi
    done

    if [ "$rc" -ne 0 ]; then
        print_error "generate failed"
        return 1
    fi
    echo ""
    print_success "Generation complete. Review changes: git diff"
    return 0
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
    echo "  generate Regenerate committed data files (timezones, countries)"
    echo "  override-status  Report whether unparam and mockery still need tools.x-tools-override"
    echo "  all     Run all commands in sequence"
    echo ""
    echo "Scope: toolchain and CDN pins only. The product version comes from"
    echo "the git tag, not from versions.yaml."
    echo ""
    echo "Workflow, for bumping a tool or CDN pin:"
    echo "  1. Edit versions.yaml to set desired versions"
    echo "  2. Run: $0 update"
    echo "  3. Review changes: git diff"
    echo "  4. Run tests and build"
    echo ""
    echo "To release:"
    echo "  git tag vX.Y.Z && git push origin vX.Y.Z"
    echo ""
    echo "Examples:"
    echo "  $0 show          # See current versions"
    echo "  $0 check         # Check for newer versions online"
    echo "  $0 update        # Apply versions from yaml to files"
    echo "  $0 generate      # Regenerate timezones + countries data files"
    echo ""
}

# =============================================================================
# Main Entry Point
# =============================================================================

# Sourced rather than run, as a test does to call one function, the script stops
# here with its functions defined.
if [ "${BASH_SOURCE[0]}" != "$0" ]; then
    return 0
fi

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
    generate)
        cmd_generate "${2:-all}"
        ;;
    override-status)
        cmd_override_status
        exit $?
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
