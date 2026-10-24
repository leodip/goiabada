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
#   generate - Regenerate committed data files (timezones, countries, passwordblocklist)
#   all     - Run all commands in sequence (check → update → deps)
#
# Scope: this script manages TOOLCHAIN and CDN pins (Go, Tailwind, Node.js,
# golangci-lint, mockery, staticcheck, unparam, govulncheck, the release
# images' Alpine base, Trivy, Grype, cropperjs, acorn). It does NOT
# manage the product version.
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
#   - mikefarah's yq (YAML parser) - installed in devcontainer
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

# Verify yq is installed (required for YAML parsing), and that it is mikefarah's, the one the
# devcontainer installs. Debian and Ubuntu's yq package is another program of the same name, a
# Python wrapper handing the filter to jq, which reads a key like golangci-lint as a subtraction.
require_yq() {
    if ! command -v yq &> /dev/null; then
        print_error "yq is required but not installed."
        echo "Install yq: https://github.com/mikefarah/yq#install"
        echo "Or rebuild the devcontainer which includes yq."
        exit 1
    fi
    if ! yq --version 2>/dev/null | grep -q 'mikefarah/yq'; then
        print_error "$(command -v yq) is not mikefarah's yq, which this script is written for."
        echo "Debian and Ubuntu's yq package is a different program with the same name."
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
# A key holding a hyphen is quoted, tools."golangci-lint", which every yq reads as one key.
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
        echo "tools.node=$(get_version 'tools.node')"
        echo "tools.golangci-lint=$(get_version 'tools."golangci-lint"')"
        echo "tools.mockery=$(get_version 'tools.mockery')"
        echo "tools.staticcheck=$(get_version 'tools.staticcheck')"
        echo "tools.unparam=$(get_version 'tools.unparam')"
        echo "tools.govulncheck=$(get_version 'tools.govulncheck')"
        echo "tools.alpine=$(get_version 'tools.alpine')"
        echo "tools.trivy=$(get_version 'tools.trivy')"
        echo "tools.grype=$(get_version 'tools.grype')"
        echo "vendored.cropperjs=$(get_version 'vendored.cropperjs')"
        echo "vendored.acorn=$(get_version 'vendored.acorn')"
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

# Fetch latest Go version from go.dev
get_go_latest() {
    local response
    response=$(curl -s --connect-timeout 10 "https://go.dev/dl/?mode=json" 2>/dev/null)
    if [ $? -eq 0 ] && [ -n "$response" ]; then
        echo "$response" | grep -o '"version"[[:space:]]*:[[:space:]]*"go[0-9.]*"' | head -1 | cut -d'"' -f4 | sed 's/^go//'
    fi
}

# Fetch the newest Node.js LTS release from nodejs.org. index.json lists releases newest first, an
# LTS one with its line's codename in "lts" and the others with false.
get_node_latest() {
    local response
    response=$(curl -s --connect-timeout 10 "https://nodejs.org/dist/index.json" 2>/dev/null)
    if [ $? -eq 0 ] && [ -n "$response" ]; then
        echo "$response" | grep -o '"version":"v[0-9.]*"[^}]*"lts":"' | head -1 | cut -d'"' -f4 | sed 's/^v//'
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

# The days GitHub must have recorded a release public before check suggests it.
# A pin cannot be swapped once it is set, so the danger left is bumping to a
# release that is already poisoned: Trivy's malicious v0.69.4 was public for
# about 12 hours before it was pulled (#520).
RELEASE_MIN_AGE_DAYS=7

# utc_timestamp prints seconds since the epoch as GitHub writes a time,
# 2026-10-21T11:18:34Z, which compares as text in time order. GNU date, then BSD.
utc_timestamp() {
    date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "$1" +%Y-%m-%dT%H:%M:%SZ
}

# Reduce a GitHub releases API answer, read on stdin, to the newest vX.Y.Z
# release, as X.Y.Z, that GitHub records published at least
# RELEASE_MIN_AGE_DAYS before NOW, given in seconds since the epoch.
# Usage: github_settled_release NOW < releases.json
#
# The age is published_at, when the release was made public. created_at is the
# tagged commit's date, which whoever pushes the tag sets. A draft and a
# prerelease are passed over, and so is a tag that is not vX.Y.Z.
#
# The fields are read in the order GitHub writes a release's: tag_name, then
# draft, prerelease and published_at, each once. Nothing nested in a release
# carries those names, and a release's body escapes its quotes. An answer in
# any other order selects nothing, rather than pairing one release's tag with
# another's publication time.
github_settled_release() {
    local cutoff
    cutoff=$(utc_timestamp $(( $1 - RELEASE_MIN_AGE_DAYS * 86400 ))) || return 1
    grep -oE '"(tag_name|draft|prerelease|published_at)"[[:space:]]*:[[:space:]]*("[^"]*"|true|false|null)' \
        | awk -v cutoff="$cutoff" '
            function settle() {
                if (!open) return
                if (draft == "" || pre == "" || pub == "") { bad = 1; return }
                if (draft == "false" && pre == "false" && pub ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z$/ && pub <= cutoff) {
                    found[++n] = tag
                }
            }
            {
                key = $0; sub(/^"/, "", key); sub(/".*/, "", key)
                value = $0; sub(/^"[^"]*"[ \t]*:[ \t]*/, "", value); gsub(/"/, "", value)
                if (key == "tag_name") { settle(); open = 1; tag = value; draft = pre = pub = ""; next }
                if (!open) { bad = 1; next }
                if (key == "draft") { if (draft != "") bad = 1; draft = value }
                else if (key == "prerelease") { if (pre != "") bad = 1; pre = value }
                else if (key == "published_at") { if (pub != "") bad = 1; pub = value }
            }
            END {
                settle()
                if (bad) exit
                for (i = 1; i <= n; i++) print found[i]
            }' \
        | sed 's/^v//' \
        | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' \
        | sort -V \
        | tail -1
}

# Fetch the newest settled release of a GitHub repository, as github_settled_release
# selects it from the ten newest releases.
# Usage: get_github_settled "aquasecurity/trivy"
get_github_settled() {
    local repo="$1"
    local response
    response=$(curl -s --connect-timeout 10 "https://api.github.com/repos/${repo}/releases?per_page=10" 2>/dev/null)
    if [ $? -eq 0 ] && [ -n "$response" ]; then
        echo "$response" | github_settled_release "$(date -u +%s)"
    fi
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
# Usage: get_npm_latest "acorn"
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
    printf "  %-23s ${GREEN}%s${NC}\n" "node" "$(get_version 'tools.node')"
    printf "  %-23s ${GREEN}%s${NC}\n" "golangci-lint" "$(get_version 'tools."golangci-lint"')"
    printf "  %-23s ${GREEN}%s${NC}\n" "mockery" "$(get_version 'tools.mockery')"
    printf "  %-23s ${GREEN}%s${NC}\n" "staticcheck" "$(get_version 'tools.staticcheck')"
    printf "  %-23s ${GREEN}%s${NC}\n" "unparam" "$(get_version 'tools.unparam')"
    printf "  %-23s ${GREEN}%s${NC}\n" "govulncheck" "$(get_version 'tools.govulncheck')"
    printf "  %-23s ${GREEN}%s${NC}\n" "alpine" "$(get_version 'tools.alpine')"
    printf "  %-23s ${GREEN}%s${NC}\n" "trivy" "$(get_version 'tools.trivy')"
    printf "  %-23s ${GREEN}%s${NC}\n" "grype" "$(get_version 'tools.grype')"

    # Vendored dependencies
    echo -e "\n${BOLD}Vendored dependencies:${NC}"
    printf "  %-23s ${GREEN}%s${NC}\n" "cropperjs" "$(get_version 'vendored.cropperjs')"
    printf "  %-23s ${GREEN}%s${NC}\n" "acorn" "$(get_version 'vendored.acorn')"

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

    # --- Node.js ---
    # Compared with the newest LTS release, so a pin on a line before it enters LTS reads as up
    # to date.
    echo -n "Checking Node.js... "
    local current_node=$(get_version 'tools.node')
    local latest_node=$(get_node_latest)
    if [ -n "$latest_node" ]; then
        if version_lt "$current_node" "$latest_node"; then
            echo -e "${YELLOW}UPDATE AVAILABLE${NC}"
            updates_available+=("Node.js|$current_node|$latest_node|https://nodejs.org/en/about/previous-releases")
        else
            print_success "Up to date ($current_node)"
        fi
    else
        print_warning "Check failed"
    fi

    # --- golangci-lint ---
    echo -n "Checking golangci-lint... "
    local current_lint=$(get_version 'tools."golangci-lint"')
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

    # --- Trivy ---
    # Built from source at the pin in CI. A release is suggested only once
    # GitHub has recorded it public for RELEASE_MIN_AGE_DAYS, so a newer one
    # younger than that reads as up to date (#520).
    echo -n "Checking Trivy... "
    local current_trivy=$(get_version 'tools.trivy')
    local latest_trivy=$(get_github_settled "aquasecurity/trivy")
    if [ -n "$latest_trivy" ]; then
        if version_lt "$current_trivy" "$latest_trivy"; then
            echo -e "${YELLOW}UPDATE AVAILABLE${NC}"
            updates_available+=("Trivy|$current_trivy|$latest_trivy|https://github.com/aquasecurity/trivy/releases")
        else
            print_success "Up to date ($current_trivy)"
        fi
    else
        print_warning "Check failed"
    fi

    # --- Grype ---
    # Built from source at the pin in the weekly Image scan, and suggested under
    # the same RELEASE_MIN_AGE_DAYS as Trivy (#520).
    echo -n "Checking Grype... "
    local current_grype=$(get_version 'tools.grype')
    local latest_grype=$(get_github_settled "anchore/grype")
    if [ -n "$latest_grype" ]; then
        if version_lt "$current_grype" "$latest_grype"; then
            echo -e "${YELLOW}UPDATE AVAILABLE${NC}"
            updates_available+=("Grype|$current_grype|$latest_grype|https://github.com/anchore/grype/releases")
        else
            print_success "Up to date ($current_grype)"
        fi
    else
        print_warning "Check failed"
    fi

    # --- cropperjs ---
    echo -n "Checking cropperjs... "
    local current_cropper=$(get_version 'vendored.cropperjs')
    local latest_cropper=$(get_npm_latest "cropperjs")
    if [ -n "$latest_cropper" ]; then
        if version_lt "$current_cropper" "$latest_cropper"; then
            echo -e "${YELLOW}UPDATE AVAILABLE${NC}"
            updates_available+=("cropperjs|$current_cropper|$latest_cropper|https://www.npmjs.com/package/cropperjs")
        else
            print_success "Up to date ($current_cropper)"
        fi
    else
        print_warning "Check failed"
    fi

    # --- acorn ---
    echo -n "Checking acorn... "
    local current_acorn=$(get_version 'vendored.acorn')
    local latest_acorn=$(get_npm_latest "acorn")
    if [ -n "$latest_acorn" ]; then
        if version_lt "$current_acorn" "$latest_acorn"; then
            echo -e "${YELLOW}UPDATE AVAILABLE${NC}"
            updates_available+=("acorn|$current_acorn|$latest_acorn|https://www.npmjs.com/package/acorn")
        else
            print_success "Up to date ($current_acorn)"
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
    local GO_VERSION=$(get_version 'tools.go')
    local TAILWIND_VERSION=$(get_version 'tools.tailwind')
    local NODE_VERSION=$(get_version 'tools.node')
    local GOLANGCI_VERSION=$(get_version 'tools."golangci-lint"')
    local MOCKERY_VERSION=$(get_version 'tools.mockery')
    local STATICCHECK_VERSION=$(get_version 'tools.staticcheck')
    local UNPARAM_VERSION=$(get_version 'tools.unparam')
    local GOVULNCHECK_VERSION=$(get_version 'tools.govulncheck')
    local ALPINE_VERSION=$(get_version 'tools.alpine')
    local CROPPER_VERSION=$(get_version 'vendored.cropperjs')
    local ACORN_VERSION=$(get_version 'vendored.acorn')

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

        # Node.js: nodejs.org/dist/vX.Y.Z/node-vX.Y.Z-linux-x64.tar.gz, and the binary's path in it
        if update_file "$BASE_DIR/src/.devcontainer/Dockerfile" \
            "s|nodejs\.org/dist/v[0-9.]*/|nodejs.org/dist/v${NODE_VERSION}/|g; s|node-v[0-9.]*-linux-x64|node-v${NODE_VERSION}-linux-x64|g" \
            "Node.js"; then
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
    # Node.js images
    # -------------------------------------------------------------------------
    # The docs site and the e2e test app build on the same Node.js as the dev
    # container and the test jobs, so one pin covers every Node.js in the tree.
    echo -e "\n${BOLD}Node.js images${NC}"

    for dockerfile in "$BASE_DIR/site/Dockerfile" \
                      "$BASE_DIR/e2e/testapp/Dockerfile"; do
        if [ -f "$dockerfile" ]; then
            # Node base image: node:X.Y.Z-alpine
            if update_file "$dockerfile" \
                "s|node:[0-9.]*-alpine|node:${NODE_VERSION}-alpine|g" \
                "Node base image"; then
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
    # Vendored dependencies
    # -------------------------------------------------------------------------
    # The pinned version of each, downloaded into the repository with its license and
    # its digest written beside the pin; no page loads them from a CDN (#542).
    echo -e "\n${BOLD}Vendored dependencies${NC}"
    local cropper_dir="$BASE_DIR/src/adminconsole/web/static/vendor/cropperjs"
    # 2.x draws its own elements and carries their styles, so there is no stylesheet to fetch.
    if vendor_fetch "https://cdn.jsdelivr.net/npm/cropperjs@${CROPPER_VERSION}/dist/cropper.min.js" \
            "$cropper_dir/cropper.min.js" "cropperjs-js-sha256" &&
        vendor_fetch "https://cdn.jsdelivr.net/npm/cropperjs@${CROPPER_VERSION}/LICENSE" \
            "$cropper_dir/LICENSE"; then
        ((success_count++))
    else
        ((fail_count++))
    fi
    # acorn's single-file build, which core/guard embeds and runs under Node to parse the static
    # scripts (#617).
    local acorn_dir="$BASE_DIR/src/core/guard/scriptcheck"
    if vendor_fetch "https://cdn.jsdelivr.net/npm/acorn@${ACORN_VERSION}/dist/acorn.js" \
            "$acorn_dir/acorn.js" "acorn-sha256" &&
        vendor_fetch "https://cdn.jsdelivr.net/npm/acorn@${ACORN_VERSION}/LICENSE" \
            "$acorn_dir/acorn.LICENSE"; then
        ((success_count++))
    else
        ((fail_count++))
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
# Command: generate
# =============================================================================
# Regenerate committed "// Code generated" data files from their upstream
# sources. Each target has a `generate/` sub-package run with `go run .`:
#   timezones -> src/core/timezones/data_generated.go  (from IANA tzdata)
#   countries -> src/core/countries/data_generated.go  (from datahub CSV)
#   passwordblocklist -> src/core/passwordblocklist/data_generated.go
#                        (from three SecLists password lists)
#
# Usage: generate [timezones|countries|passwordblocklist|all]   (default: all)
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
        passwordblocklist) pkgs=("passwordblocklist") ;;
        all)       pkgs=("timezones" "countries" "passwordblocklist") ;;
        *)
            print_error "Unknown generate target: ${target}"
            echo "Valid targets: timezones, countries, passwordblocklist, all"
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
    echo "  generate Regenerate committed data files (timezones, countries, passwordblocklist)"
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
    echo "  $0 generate      # Regenerate timezones, countries and passwordblocklist data files"
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
