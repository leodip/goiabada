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
#   check   - Check online for newer versions of dependencies [--now]
#   update  - Update version strings in all project files
#   deps    - Update Go modules and npm packages, and Playwright's browsers [--now]
#   generate - Regenerate committed data files (timezones, countries, passwordblocklist)
#   all     - Run all commands in sequence (check → update → deps)
#
# Scope: this script manages TOOLCHAIN and CDN pins (Go, Tailwind, Node.js,
# golangci-lint, mockery, staticcheck, unparam, govulncheck, Trivy, Grype,
# npm-check-updates, cropperjs, acorn), and
# the dependencies of the Go modules and of the npm projects in NPM_PROJECTS.
# check also reports when the pinned sources of generate's data have moved.
# It does NOT manage the product version.
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
#   - go, node, npm (for dependency updates; npm-check-updates runs through npx
#     at the version versions.yaml pins)
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
        echo "tools.trivy=$(get_version 'tools.trivy')"
        echo "tools.grype=$(get_version 'tools.grype')"
        echo "tools.npm-check-updates=$(get_version 'tools."npm-check-updates"')"
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

# Fetch latest version from the Go module proxy
# Usage: get_goproxy_latest "honnef.co/go/tools"
#
# Used instead of get_github_settled for Go tools whose module version does not
# match their GitHub release tag. dominikh/go-tools tags releases as "2026.1"
# while the module is v0.7.0, so comparing against the release tag would report
# an update forever; golang/vuln's releases page trails its module tags by
# several minors, so it would never report one. The proxy is authoritative for
# what `go install` will actually fetch, which is what we pin.
#
# Prints the version and, after a space, the time the proxy records it
# published, which check holds to RELEASE_MIN_AGE_DAYS.
get_goproxy_latest() {
    local module="$1"
    local response
    response=$(curl -s --connect-timeout 10 "https://proxy.golang.org/${module}/@latest" 2>/dev/null)
    if [ $? -eq 0 ] && [ -n "$response" ]; then
        goproxy_info_fields <<< "$response"
    fi
}

# Reduce a Go module proxy .info answer, read on stdin, to its version without
# the v and its time, separated by a space.
goproxy_info_fields() {
    local info version time
    info=$(cat)
    version=$(echo "$info" | grep -o '"Version"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4 | sed 's/^v//')
    time=$(echo "$info" | grep -o '"Time"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)
    [ -n "$version" ] && echo "$version $time"
}

# Fetch latest Go version from go.dev, with the time the Go module proxy records
# its toolchain published, separated by a space.
get_go_latest() {
    local response version info
    response=$(curl -s --connect-timeout 10 "https://go.dev/dl/?mode=json" 2>/dev/null)
    if [ $? -eq 0 ] && [ -n "$response" ]; then
        version=$(echo "$response" | grep -o '"version"[[:space:]]*:[[:space:]]*"go[0-9.]*"' | head -1 | cut -d'"' -f4 | sed 's/^go//')
        [ -n "$version" ] || return 0
        info=$(curl -s --connect-timeout 10 "https://proxy.golang.org/golang.org/toolchain/@v/v0.0.1-go${version}.linux-amd64.info" 2>/dev/null)
        echo "$version $(goproxy_info_fields <<< "$info" | cut -d' ' -f2)"
    fi
}

# Fetch the newest settled Node.js LTS release from nodejs.org, as
# node_settled_lts selects it.
get_node_latest() {
    local response
    response=$(curl -s --connect-timeout 10 "https://nodejs.org/dist/index.json" 2>/dev/null)
    if [ $? -eq 0 ] && [ -n "$response" ]; then
        echo "$response" | node_settled_lts "$(date -u +%s)" 2>/dev/null
    fi
}

# Reduce nodejs.org's index.json, read on stdin, to the newest LTS release, an
# entry with its line's codename in "lts" rather than false, dated at least
# RELEASE_MIN_AGE_DAYS before NOW, given in seconds since the epoch. index.json
# dates a release by its day alone, so a release counts from that day's start.
# Usage: node_settled_lts NOW < index.json
node_settled_lts() {
    node -e '
        const [now, days] = process.argv.slice(1).map(Number);
        const cutoff = (now - days * 86400) * 1000;
        const releases = JSON.parse(require("fs").readFileSync(0, "utf8"));
        const newer = (a, b) => (a[0] - b[0] || a[1] - b[1] || a[2] - b[2]) > 0;
        let best = null;
        for (const r of releases) {
            if (!r.lts || !/^v\d+\.\d+\.\d+$/.test(r.version)) continue;
            if (!(Date.parse(r.date + "T00:00:00Z") <= cutoff)) continue;
            const parts = r.version.slice(1).split(".").map(Number);
            if (!best || newer(parts, best)) best = parts;
        }
        if (best) console.log(best.join("."));
    ' "$1" "$RELEASE_MIN_AGE_DAYS"
}

# The days a release must have been public before check suggests it or deps
# upgrades to it, as its source records the publication: GitHub's releases, the
# Go module proxy, nodejs.org, the npm registry. --now sets it to 0, for an
# urgent fix. A pin written into versions.yaml by hand is applied whatever its
# age; this shapes only what the script picks. A pin cannot be swapped once it is set, so the danger left is
# bumping to a release that is already poisoned: Trivy's malicious v0.69.4 was
# public for about 12 hours before it was pulled (#520).
RELEASE_MIN_AGE_DAYS=3

# Whether a release published at TIME, as RFC 3339 in UTC, is younger than
# RELEASE_MIN_AGE_DAYS. One whose time is unknown counts as too young.
# Usage: released_too_recently TIME
released_too_recently() {
    local cutoff
    cutoff=$(utc_timestamp $(( $(date -u +%s) - RELEASE_MIN_AGE_DAYS * 86400 ))) || return 0
    [ -z "$1" ] || [[ "$1" > "$cutoff" ]]
}

# check's line for a newer release still younger than RELEASE_MIN_AGE_DAYS,
# where its source names only the newest release, so no older one can stand in.
# Usage: held_back CURRENT LATEST PUBLISHED
held_back() {
    print_info "Held back ($1): $2, published ${3:-at an unknown time}, is under $RELEASE_MIN_AGE_DAYS days old"
}

# take_now_flag reads a command's arguments: --now sets RELEASE_MIN_AGE_DAYS to
# 0, for an urgent fix that cannot wait. Anything else is refused.
# Usage: take_now_flag "$@"
take_now_flag() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --now) RELEASE_MIN_AGE_DAYS=0 ;;
            *) print_error "Unknown option: $1"; return 1 ;;
        esac
        shift
    done
}

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

# Reduce `npm view <package> time versions --json`, read on stdin, to the newest
# X.Y.Z release the registry records published at least RELEASE_MIN_AGE_DAYS
# before NOW, given in seconds since the epoch, as Trivy's are chosen (#520).
# Usage: npm_settled_release NOW < view.json
#
# Only a version still in versions counts: the time map keeps an unpublished
# version's date. A prerelease is passed over. Prints nothing when no release
# is old enough, and fails on an answer that is not that JSON.
npm_settled_release() {
    node -e '
        const [now, days] = process.argv.slice(1).map(Number);
        const view = JSON.parse(require("fs").readFileSync(0, "utf8"));
        const cutoff = (now - days * 86400) * 1000;
        const newer = (a, b) => (a[0] - b[0] || a[1] - b[1] || a[2] - b[2]) > 0;
        let best = null;
        for (const version of [].concat(view.versions || [])) {
            if (!/^\d+\.\d+\.\d+$/.test(version)) continue;
            if (!(Date.parse((view.time || {})[version]) <= cutoff)) continue;
            const parts = version.split(".").map(Number);
            if (!best || newer(parts, best)) best = parts;
        }
        if (best) console.log(best.join("."));
    ' "$1" "$RELEASE_MIN_AGE_DAYS"
}

# Fetch the newest settled release of an npm package, as npm_settled_release
# selects it.
# Usage: get_npm_settled "acorn"
get_npm_settled() {
    local response
    response=$(npm view "$1" time versions --json 2>/dev/null) || return 0
    [ -n "$response" ] && echo "$response" | npm_settled_release "$(date -u +%s)" 2>/dev/null
}

# The npm projects deps upgrades and check reports on, from the repository root.
NPM_PROJECTS=(site e2e/playwright e2e/testapp)

# run_ncu runs npm-check-updates, at the version versions.yaml pins, over the npm
# project in DIR, considering only releases public for RELEASE_MIN_AGE_DAYS.
# With no --target it looks up to the newest release, a new major version included.
# Usage: run_ncu DIR [npm-check-updates options]
run_ncu() {
    local dir="$1"
    shift
    npx --yes "npm-check-updates@$(get_version 'tools."npm-check-updates"')" --cwd "$dir" \
        --cooldown "$RELEASE_MIN_AGE_DAYS" --loglevel error "$@"
}

# The upgrade deps makes: within what a caret on the current version accepts, the
# same major from 1.0.0 and the same minor below it, where a minor is a breaking
# change. A new major version is a change of its own, with its own fixes.
NCU_COMPATIBLE_CONFIG='module.exports = {
  target: (name, semver) => (semver[0] && semver[0].major === "0" ? "patch" : "minor"),
};'

# run_ncu_compatible runs run_ncu with NCU_COMPATIBLE_CONFIG's target.
# Usage: run_ncu_compatible DIR [npm-check-updates options]
run_ncu_compatible() {
    local dir="$1"
    shift
    local config status
    config=$(mktemp -d) || return 1
    printf '%s\n' "$NCU_COMPATIBLE_CONFIG" > "$config/.ncurc.cjs"
    run_ncu "$dir" --configFilePath "$config" "$@"
    status=$?
    rm -rf "$config"
    return $status
}

# npm_project_updates prints, for the npm project in DIR, a line per dependency
# with a newer settled release: "update" and the release deps would move it to,
# or "major" and a new major version, each as NAME, CURRENT and NEW range,
# separated by tabs. Fails when npm-check-updates does.
# Usage: npm_project_updates DIR
npm_project_updates() {
    local dir="$1" compatible latest
    compatible=$(run_ncu_compatible "$dir" --jsonUpgraded) || return 1
    latest=$(run_ncu "$dir" --jsonUpgraded) || return 1
    local -A current=() wanted=()
    local name range
    while IFS=$'\t' read -r name range; do
        [ -n "$name" ] && current[$name]=$range
    done < <(yq -p json -r '(.dependencies // {}) * (.devDependencies // {}) | to_entries | .[] | .key + "\t" + .value' "$dir/package.json")
    while IFS=$'\t' read -r name range; do
        [ -n "$name" ] || continue
        wanted[$name]=$range
        printf 'update\t%s\t%s\t%s\n' "$name" "${current[$name]}" "$range"
    done < <(echo "$compatible" | yq -p json -r 'to_entries | .[] | .key + "\t" + .value')
    while IFS=$'\t' read -r name range; do
        [ -n "$name" ] || continue
        [ "${wanted[$name]:-}" = "$range" ] && continue
        printf 'major\t%s\t%s\t%s\n' "$name" "${current[$name]}" "$range"
    done < <(echo "$latest" | yq -p json -r 'to_entries | .[] | .key + "\t" + .value')
}

# The data generators pin their upstream sources in their own code: a release or
# commit, with the hash its bytes must have. check reads those pins to report
# when upstream has moved; moving one is the generator's own steps, at the top
# of its main.go, then ./version-manager.sh generate.
TZ_GENERATOR="$BASE_DIR/src/core/timezones/generate/main.go"
COUNTRIES_GENERATOR="$BASE_DIR/src/core/countries/generate/main.go"
PASSWORDS_GENERATOR="$BASE_DIR/src/core/passwordblocklist/generate/main.go"

# go_const prints the string a Go constant is set to in FILE, written as
# NAME = "value" on a line of its own, as the generators write their pins.
# Usage: go_const FILE NAME
go_const() {
    sed -n -E "s/^[[:space:]]*$2[[:space:]]*=[[:space:]]*\"([^\"]*)\".*/\1/p" "$1" | head -1
}

# The file names the password blocklist generator fetches, one per line.
password_list_files() {
    sed -n -E 's/^[[:space:]]*file:[[:space:]]*"([^"]+)".*/\1/p' "$PASSWORDS_GENERATOR"
}

# Reduce a GitHub commits API answer, read on stdin, one commit or a list of
# them, to the first commit's SHA and committer time, separated by a space.
# Prints nothing for an empty list, and fails on an answer that is not JSON.
github_commit_fields() {
    node -e '
        const answer = JSON.parse(require("fs").readFileSync(0, "utf8"));
        const commit = Array.isArray(answer) ? answer[0] : answer;
        if (commit && commit.sha && commit.commit) console.log(commit.sha + " " + commit.commit.committer.date);
    '
}

# get_github_path_change prints the newest commit of REPO that changed one of
# PATHS after the commit PIN, as SHA and time, or nothing when none did. Fails
# when GitHub does not answer.
# Usage: get_github_path_change REPO PIN PATH...
get_github_path_change() {
    local repo="$1" pin="$2"
    shift 2
    local pinned pinned_time path change change_time newest="" newest_time=""
    pinned=$(curl -sf --connect-timeout 10 "https://api.github.com/repos/${repo}/commits/${pin}" | github_commit_fields) || return 1
    pinned_time=${pinned#* }
    [ -n "$pinned_time" ] || return 1
    for path in "$@"; do
        change=$(curl -sf --connect-timeout 10 "https://api.github.com/repos/${repo}/commits?path=${path}&per_page=1" | github_commit_fields) || return 1
        change_time=${change#* }
        [ -n "$change" ] && [[ "$change_time" > "$pinned_time" ]] && [[ "$change_time" > "$newest_time" ]] || continue
        newest=${change%% *}
        newest_time=$change_time
    done
    [ -z "$newest" ] || echo "$newest $newest_time"
}

# Fetch IANA's newest tzdata release, with the time its tarball was published
# (its Last-Modified, as RFC 3339 in UTC), separated by a space.
get_tzdata_latest() {
    local release modified
    release=$(curl -sf --connect-timeout 10 "https://data.iana.org/time-zones/tzdb/version" 2>/dev/null | tr -d '[:space:]')
    [ -n "$release" ] || return 0
    modified=$(curl -sfI --connect-timeout 10 "https://data.iana.org/time-zones/releases/tzdata${release}.tar.gz" 2>/dev/null \
        | tr -d '\r' | sed -n 's/^[Ll]ast-[Mm]odified: //p')
    [ -n "$modified" ] && modified=$(date -u -d "$modified" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)
    echo "$release $modified"
}

# check's lines for a data source pinned at a commit, given the newest commit
# that changed what the generator reads, as get_github_path_change prints it.
# Usage: report_data_commit NAME PIN CHANGE GENERATOR
report_data_commit() {
    local name="$1" pin="$2" change="$3" generator="$4"
    local sha=${change%% *} time=${change#* }
    if [ -z "$change" ]; then
        print_success "Up to date (${pin:0:10})"
    elif released_too_recently "$time"; then
        held_back "${pin:0:10}" "${sha:0:10}" "$time"
    else
        echo -e "${YELLOW}UPDATE AVAILABLE${NC}"
        data_updates+=("$name|${pin:0:10}|${sha:0:10}|${generator#"$BASE_DIR"/}")
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
    printf "  %-23s ${GREEN}%s${NC}\n" "trivy" "$(get_version 'tools.trivy')"
    printf "  %-23s ${GREEN}%s${NC}\n" "grype" "$(get_version 'tools.grype')"
    printf "  %-23s ${GREEN}%s${NC}\n" "npm-check-updates" "$(get_version 'tools."npm-check-updates"')"

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
    take_now_flag "$@" || return 1
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
    local latest_go published_go
    read -r latest_go published_go <<< "$(get_go_latest)"
    if [ -n "$latest_go" ]; then
        if version_lt "$current_go" "$latest_go" && released_too_recently "$published_go"; then
            held_back "$current_go" "$latest_go" "$published_go"
        elif version_lt "$current_go" "$latest_go"; then
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
    local latest_tailwind=$(get_github_settled "tailwindlabs/tailwindcss")
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
    local latest_lint=$(get_github_settled "golangci/golangci-lint")
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
    local latest_mockery=$(get_github_settled "vektra/mockery")
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
    local latest_staticcheck published_staticcheck
    read -r latest_staticcheck published_staticcheck <<< "$(get_goproxy_latest "honnef.co/go/tools")"
    if [ -n "$latest_staticcheck" ]; then
        if version_lt "$current_staticcheck" "$latest_staticcheck" && released_too_recently "$published_staticcheck"; then
            held_back "$current_staticcheck" "$latest_staticcheck" "$published_staticcheck"
        elif version_lt "$current_staticcheck" "$latest_staticcheck"; then
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
    local latest_unparam published_unparam
    read -r latest_unparam published_unparam <<< "$(get_goproxy_latest "mvdan.cc/unparam")"
    if [ -n "$latest_unparam" ]; then
        if version_lt "$current_unparam" "$latest_unparam" && released_too_recently "$published_unparam"; then
            held_back "$current_unparam" "$latest_unparam" "$published_unparam"
        elif version_lt "$current_unparam" "$latest_unparam"; then
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
    local latest_govulncheck published_govulncheck
    read -r latest_govulncheck published_govulncheck <<< "$(get_goproxy_latest "golang.org/x/vuln")"
    if [ -n "$latest_govulncheck" ]; then
        if version_lt "$current_govulncheck" "$latest_govulncheck" && released_too_recently "$published_govulncheck"; then
            held_back "$current_govulncheck" "$latest_govulncheck" "$published_govulncheck"
        elif version_lt "$current_govulncheck" "$latest_govulncheck"; then
            echo -e "${YELLOW}UPDATE AVAILABLE${NC}"
            updates_available+=("govulncheck|$current_govulncheck|$latest_govulncheck|https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck")
        else
            print_success "Up to date ($current_govulncheck)"
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

    # --- npm-check-updates ---
    # Run through npx at its pin by deps and by the npm packages' check below.
    # It and the vendored packages after it are suggested under the same
    # RELEASE_MIN_AGE_DAYS as Trivy (#520).
    echo -n "Checking npm-check-updates... "
    local current_ncu=$(get_version 'tools."npm-check-updates"')
    local latest_ncu=$(get_npm_settled "npm-check-updates")
    if [ -n "$latest_ncu" ]; then
        if version_lt "$current_ncu" "$latest_ncu"; then
            echo -e "${YELLOW}UPDATE AVAILABLE${NC}"
            updates_available+=("npm-check-updates|$current_ncu|$latest_ncu|https://github.com/raineorshine/npm-check-updates/releases")
        else
            print_success "Up to date ($current_ncu)"
        fi
    else
        print_warning "Check failed"
    fi

    # --- cropperjs ---
    echo -n "Checking cropperjs... "
    local current_cropper=$(get_version 'vendored.cropperjs')
    local latest_cropper=$(get_npm_settled "cropperjs")
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
    local latest_acorn=$(get_npm_settled "acorn")
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

    # --- npm packages ---
    # Each npm project's dependencies, through npm-check-updates. An update is
    # one deps applies; a new major version is left for a change of its own.
    local npm_updates=() npm_majors=()
    local project kind name current latest found
    for project in "${NPM_PROJECTS[@]}"; do
        echo -n "Checking ${project}'s npm packages... "
        if ! found=$(npm_project_updates "$BASE_DIR/$project" 2>/dev/null); then
            print_warning "Check failed"
            continue
        fi
        if [ -z "$found" ]; then
            print_success "Up to date"
            continue
        fi
        echo -e "${YELLOW}UPDATE AVAILABLE${NC}"
        while IFS=$'\t' read -r kind name current latest; do
            if [ "$kind" = "update" ]; then
                npm_updates+=("$name ($project)|$current|$latest")
            else
                npm_majors+=("$name ($project)|$current|$latest")
            fi
        done <<< "$found"
    done

    # --- Data sources ---
    # The pinned upstreams of ./version-manager.sh generate, held to the same
    # RELEASE_MIN_AGE_DAYS.
    local data_updates=()
    echo -n "Checking tzdata (timezones)... "
    local current_tz latest_tz published_tz
    current_tz=$(go_const "$TZ_GENERATOR" pinnedRelease)
    read -r latest_tz published_tz <<< "$(get_tzdata_latest)"
    if [ -z "$current_tz" ] || [ -z "$latest_tz" ]; then
        print_warning "Check failed"
    elif version_lt "$current_tz" "$latest_tz" && released_too_recently "$published_tz"; then
        held_back "$current_tz" "$latest_tz" "$published_tz"
    elif version_lt "$current_tz" "$latest_tz"; then
        echo -e "${YELLOW}UPDATE AVAILABLE${NC}"
        data_updates+=("tzdata|$current_tz|$latest_tz|${TZ_GENERATOR#"$BASE_DIR"/}")
    else
        print_success "Up to date ($current_tz)"
    fi

    echo -n "Checking country-codes (countries)... "
    local pin_countries change_countries
    pin_countries=$(go_const "$COUNTRIES_GENERATOR" pinnedCommit)
    if [ -n "$pin_countries" ] && change_countries=$(get_github_path_change "datasets/country-codes" "$pin_countries" "data/country-codes.csv"); then
        report_data_commit "country-codes" "$pin_countries" "$change_countries" "$COUNTRIES_GENERATOR"
    else
        print_warning "Check failed"
    fi

    echo -n "Checking SecLists (passwordblocklist)... "
    local pin_passwords change_passwords
    local -a password_paths=()
    local file
    while read -r file; do
        [ -n "$file" ] && password_paths+=("Passwords/Common-Credentials/$file")
    done < <(password_list_files)
    pin_passwords=$(go_const "$PASSWORDS_GENERATOR" pinnedCommit)
    if [ -n "$pin_passwords" ] && [ ${#password_paths[@]} -gt 0 ] \
        && change_passwords=$(get_github_path_change "danielmiessler/SecLists" "$pin_passwords" "${password_paths[@]}"); then
        report_data_commit "SecLists" "$pin_passwords" "$change_passwords" "$PASSWORDS_GENERATOR"
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
    fi
    if [ ${#npm_updates[@]} -gt 0 ]; then
        print_header "npm Package Updates"
        printf "%-44s %-12s %s\n" "Package" "Current" "Latest"
        printf "%-44s %-12s %s\n" "-------" "-------" "------"
        for info in "${npm_updates[@]}"; do
            IFS='|' read -r name current latest <<< "$info"
            printf "${YELLOW}%-44s${NC} %-12s ${GREEN}%s${NC}\n" "$name" "$current" "$latest"
        done
        echo ""
        print_info "To update: ./version-manager.sh deps"
    fi
    if [ ${#npm_majors[@]} -gt 0 ]; then
        print_header "New Major Versions"
        printf "%-44s %-12s %s\n" "Package" "Current" "Latest"
        printf "%-44s %-12s %s\n" "-------" "-------" "------"
        for info in "${npm_majors[@]}"; do
            IFS='|' read -r name current latest <<< "$info"
            printf "${YELLOW}%-44s${NC} %-12s ${GREEN}%s${NC}\n" "$name" "$current" "$latest"
        done
        echo ""
        print_info "deps leaves these: each is a change of its own, made in its package.json"
    fi
    if [ ${#data_updates[@]} -gt 0 ]; then
        print_header "Data Source Updates"
        printf "%-20s %-12s %-12s %s\n" "Source" "Current" "Latest" "Pinned in"
        printf "%-20s %-12s %-12s %s\n" "------" "-------" "------" "---------"
        for info in "${data_updates[@]}"; do
            IFS='|' read -r name current latest url <<< "$info"
            printf "${YELLOW}%-20s${NC} %-12s ${GREEN}%-12s${NC} ${BLUE}%s${NC}\n" "$name" "$current" "$latest" "$url"
        done
        echo ""
        print_info "To update: follow the steps at the top of that file, then ./version-manager.sh generate"
    fi
    if [ ${#updates_available[@]} -eq 0 ] && [ ${#npm_updates[@]} -eq 0 ] && [ ${#npm_majors[@]} -eq 0 ] && [ ${#data_updates[@]} -eq 0 ]; then
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

# settled_go_version reads candidate versions of a module, newest first, each
# with the time the Go module proxy records it published (RFC 3339, UTC), and
# prints the first published at or before CUTOFF, or FALLBACK when none is.
# Usage: settled_go_version CUTOFF FALLBACK < "VERSION TIME" lines
settled_go_version() {
    awk -v cutoff="$1" -v fallback="$2" '
        NF == 2 && $2 <= cutoff { print $1; found = 1; exit }
        END { if (!found) print fallback }'
}

# hold_young_go_modules runs in a Go module's directory after go get -u, given
# the file of "PATH VERSION" lines go list -m printed before it. A module the
# upgrade moved to a version younger than CUTOFF goes back to its newest
# release between the two that is old enough, or to where it was: go get -u
# takes the newest release whatever its age.
# Usage: hold_young_go_modules BEFORE CUTOFF
hold_young_go_modules() {
    local before="$1" cutoff="$2" path version time old target
    local -a held=()
    while read -r path version time; do
        [ -n "$version" ] || continue
        [ -n "$time" ] && [[ "$time" > "$cutoff" ]] || continue
        old=$(awk -v p="$path" '$1 == p { print $2 }' "$before")
        [ "$old" = "$version" ] && continue
        target=$(go list -m -versions -f '{{range .Versions}}{{.}}{{"\n"}}{{end}}' "$path" 2>/dev/null \
            | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -rV \
            | while read -r candidate; do
                version_lt "$candidate" "$version" || continue
                [ -z "$old" ] || version_lt "$old" "$candidate" || break
                echo "$candidate $(go list -m -f '{{if .Time}}{{.Time.UTC.Format "2006-01-02T15:04:05Z"}}{{end}}' "$path@$candidate" 2>/dev/null)"
            done | settled_go_version "$cutoff" "${old:-$version}")
        [ "$target" = "$version" ] && continue
        held+=("$path@$target")
        print_info "Held back: $path $version is under $RELEASE_MIN_AGE_DAYS days old; $target instead"
    done < <(go list -m -f '{{.Path}} {{.Version}} {{if .Time}}{{.Time.UTC.Format "2006-01-02T15:04:05Z"}}{{end}}' all 2>/dev/null)
    [ ${#held[@]} -eq 0 ] || go get "${held[@]}"
}

# modernc.org/sqlite is SQLite transpiled to Go, running on modernc.org/libc, and asks to be built
# with exactly the libc version its own go.mod names ("Fragile modernc.org/libc dependency" in its
# package documentation, https://gitlab.com/cznic/sqlite/-/issues/177). go get -u takes the newest
# libc whatever sqlite asks for, and hold_young_go_modules can keep sqlite on an older release than
# the libc it would pair with, so deps sets libc back to the selected sqlite's own after both.

# sqlite_libc_version reads `go mod graph` on stdin and prints the modernc.org/libc version that
# modernc.org/sqlite at VERSION requires, or nothing when the graph holds no such requirement.
# Usage: sqlite_libc_version VERSION < graph
sqlite_libc_version() {
    awk -v from="modernc.org/sqlite@$1" '
        $1 == from && index($2, "modernc.org/libc@") == 1 { print substr($2, length("modernc.org/libc@") + 1); exit }'
}

# pin_sqlite_libc runs in a Go module's directory after go get -u and hold_young_go_modules. In a
# module that requires modernc.org/sqlite, it sets modernc.org/libc to exactly the version the
# selected sqlite requires; in any other it does nothing. Fails when that version cannot be read
# from the module graph, or go get cannot set it.
# Usage: pin_sqlite_libc
pin_sqlite_libc() {
    local sqlite libc want
    sqlite=$(go list -m -f '{{.Version}}' modernc.org/sqlite 2>/dev/null) && [ -n "$sqlite" ] || return 0
    want=$(go mod graph | sqlite_libc_version "$sqlite")
    [ -n "$want" ] || return 1
    libc=$(go list -m -f '{{.Version}}' modernc.org/libc 2>/dev/null)
    [ "$libc" = "$want" ] && return 0
    print_info "Pinned: modernc.org/libc ${libc:-(none)} is not the $want modernc.org/sqlite $sqlite requires; $want instead"
    go get "modernc.org/libc@$want"
}

# =============================================================================
# Command: deps
# =============================================================================
# Update Go modules and npm packages, and the browsers the e2e suite's
# Playwright needs.
#
# An npm project's dependencies move within what a caret on the current
# version accepts (NCU_COMPATIBLE_CONFIG), to releases public for
# RELEASE_MIN_AGE_DAYS; npm then resolves the lock file, and with npm update the
# transitive dependencies, under the same cutoff. A new major version stays a
# change of its own, which check lists.
#
# A Go module's modernc.org/libc follows its modernc.org/sqlite, to the exact
# version sqlite requires (pin_sqlite_libc).

cmd_deps() {
    take_now_flag "$@" || return 1
    print_header "Updating Dependencies"

    local cutoff before
    cutoff=$(utc_timestamp $(( $(date -u +%s) - RELEASE_MIN_AGE_DAYS * 86400 )))
    before=$(mktemp) || return 1

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

            go list -m -f '{{.Path}} {{.Version}}' all > "$before" 2>/dev/null
            if go get -u ./... 2>&1; then
                # Reset core module back to v0.0.0 (local pseudo-version)
                # This is needed because go get -u tries to fetch from remote
                go mod edit -require=github.com/leodip/goiabada/core@v0.0.0 2>/dev/null || true
                print_success "go get -u ./..."
                if ! hold_young_go_modules "$before" "$cutoff"; then
                    print_error "go get of the held-back versions failed"
                elif ! pin_sqlite_libc; then
                    print_error "pinning modernc.org/libc to modernc.org/sqlite's version failed"
                fi
                go mod edit -require=github.com/leodip/goiabada/core@v0.0.0 2>/dev/null || true
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

            go list -m -f '{{.Path}} {{.Version}}' all > "$before" 2>/dev/null
            if go get -u ./... 2>&1; then
                print_success "go get -u ./..."
                if ! hold_young_go_modules "$before" "$cutoff"; then
                    print_error "go get of the held-back versions failed"
                elif ! pin_sqlite_libc; then
                    print_error "pinning modernc.org/libc to modernc.org/sqlite's version failed"
                fi
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

    local project dir
    for project in "${NPM_PROJECTS[@]}"; do
        dir="$BASE_DIR/$project"
        [ -f "$dir/package.json" ] || continue
        echo -e "\n${BOLD}Updating ${dir}${NC}"
        if ! run_ncu_compatible "$dir" --upgrade; then
            print_error "npm-check-updates failed"
            continue
        fi
        if (cd "$dir" && npm install --before="$cutoff" --no-fund --no-audit); then
            print_success "npm install"
        else
            print_error "npm install failed"
            continue
        fi
        if (cd "$dir" && npm update --before="$cutoff" --no-fund --no-audit); then
            print_success "npm update"
        else
            print_error "npm update failed"
        fi
    done

    # -------------------------------------------------------------------------
    # Playwright Browsers
    # -------------------------------------------------------------------------
    # The browser builds the e2e suite's Playwright expects, and the system
    # libraries they need, which a new build can add to: installing those takes
    # sudo, so this only says which command does it.
    echo -e "\n${BOLD}Playwright Browsers${NC}"
    local suite="$BASE_DIR/e2e/playwright"
    if (cd "$suite" && npx playwright install); then
        print_success "npx playwright install"
    else
        print_error "npx playwright install failed"
    fi
    if (cd "$suite" && npx playwright install-deps --dry-run 2>&1) | grep -q 'All system dependencies are installed'; then
        print_success "The browsers' system libraries are installed"
    else
        print_warning "The browsers need system libraries this machine lacks. Install them with:"
        echo "  (cd e2e/playwright && npx playwright install-deps)   # asks for sudo itself"
    fi

    rm -f "$before"

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
    echo "  deps    Update Go modules and npm packages, and Playwright's browsers"
    echo "  generate Regenerate committed data files (timezones, countries, passwordblocklist)"
    echo "  all     Run all commands in sequence"
    echo ""
    echo "check and deps take a release only once it has been public for $RELEASE_MIN_AGE_DAYS days."
    echo "With --now they take the newest, for an urgent fix that cannot wait."
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
    echo "  $0 deps          # Update Go modules and npm packages"
    echo "  $0 deps --now    # The same, with releases younger than $RELEASE_MIN_AGE_DAYS days"
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
        shift
        cmd_check "$@"
        ;;
    update)
        cmd_update
        ;;
    deps)
        shift
        cmd_deps "$@"
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
