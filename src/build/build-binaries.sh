#!/bin/bash
# Cross-compiles authserver + adminconsole for every supported platform and
# packages each pair as a zip.
#
# The version is no longer edited into this file. It comes from the caller,
# which in a release is the git tag (see docs/ci-v2-design.md 4.1). A plain
# local run produces "dev".
#
# set -euo pipefail matters more here than it looks: without it, build_platform
# ran cd, go build and zip with no status checks, the loop continued across all
# five platforms regardless, and the script ended on an echo. A failed
# cross-compile therefore exited 0 with a success message, and whatever
# happened to be on disk -- including a previous run's zips -- got uploaded.
set -euo pipefail

VERSION="${GOIABADA_VERSION:-dev}"

while [ $# -gt 0 ]; do
    case "$1" in
        --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

BUILD_DATE=$(date +%Y-%m-%d)
GIT_COMMIT=$(git rev-parse --short HEAD)

# Absolute paths, because build_platform used to walk relative to wherever the
# previous iteration happened to leave the working directory. That worked, but
# only by coincidence, and under `set -e` a single unexpected cd would abort the
# run rather than silently building the wrong thing.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$SCRIPT_DIR"

echo "Version: $VERSION"
echo "Build date: $BUILD_DATE"
echo "Git commit: $GIT_COMMIT"
echo "Current directory: $(pwd)"

LDFLAGS='-X "github.com/leodip/goiabada/core/constants.Version='${VERSION}'" -X "github.com/leodip/goiabada/core/constants.BuildDate='${BUILD_DATE}'" -X "github.com/leodip/goiabada/core/constants.GitCommit='${GIT_COMMIT}'"'

# Function to build both applications for a specific platform
build_platform() {
    local os=$1
    local arch=$2
    local extension=$3  # Empty for Unix, .exe for Windows

    echo "Building for $os $arch..."

    echo "Building authserver..."
    ( cd "$SRC_DIR/authserver" && GOOS=$os GOARCH=$arch go build -v -tags=production \
        -ldflags "$LDFLAGS" \
        -o "$BUILD_DIR/goiabada-authserver${extension}" \
        ./cmd/goiabada-authserver/main.go )

    echo "Building adminconsole..."
    ( cd "$SRC_DIR/adminconsole" && GOOS=$os GOARCH=$arch go build -v -tags=production \
        -ldflags "$LDFLAGS" \
        -o "$BUILD_DIR/goiabada-adminconsole${extension}" \
        ./cmd/goiabada-adminconsole/main.go )

    echo "Creating ZIP package for $os $arch..."
    ( cd "$BUILD_DIR" && zip -v "goiabada-${VERSION}-${os}-${arch}.zip" \
        "goiabada-authserver${extension}" \
        "goiabada-adminconsole${extension}" )

    rm "$BUILD_DIR/goiabada-authserver${extension}" "$BUILD_DIR/goiabada-adminconsole${extension}"
}

# Verify go.mod files exist
if [ ! -f "$SRC_DIR/authserver/go.mod" ] || [ ! -f "$SRC_DIR/adminconsole/go.mod" ]; then
    echo "Error: Could not find go.mod files. Cannot proceed with build."
    exit 1
fi
echo "Found go.mod files"

# `export`, not `go env -w`. The latter writes CGO_ENABLED into the user's
# global Go configuration (~/.config/go/env), which persists well beyond this
# build and affects every other Go project on the machine. It also fails
# outright where that directory does not exist, which under `set -e` now aborts
# the build rather than being silently ignored. Scope it to this process
# instead, matching what the setup tool's build script already does.
echo "Setting CGO_ENABLED=0..."
export CGO_ENABLED=0

echo "Downloading dependencies for authserver..."
( cd "$SRC_DIR/authserver" && go mod download -x )

echo "Downloading dependencies for adminconsole..."
( cd "$SRC_DIR/adminconsole" && go mod download -x )

# Start clean, so nothing stale can survive into a release upload.
rm -f "$BUILD_DIR"/goiabada-*.zip

# Build for each platform
build_platform "linux" "amd64" ""
build_platform "linux" "arm64" ""
build_platform "darwin" "amd64" ""
build_platform "darwin" "arm64" ""
build_platform "windows" "amd64" ".exe"

# Explicit manifest of the expected artifacts. `set -e` catches a failing
# command; it does not catch a build that produced nothing.
EXPECTED=(
    "goiabada-${VERSION}-linux-amd64.zip"   "goiabada-${VERSION}-linux-arm64.zip"
    "goiabada-${VERSION}-darwin-amd64.zip"  "goiabada-${VERSION}-darwin-arm64.zip"
    "goiabada-${VERSION}-windows-amd64.zip"
)
for f in "${EXPECTED[@]}"; do
    [ -s "$BUILD_DIR/$f" ] || { echo "missing or empty artifact: $f" >&2; exit 1; }
done

echo "Build process completed successfully!"
echo "All binaries have been zipped and cleaned up."
ls -la "$BUILD_DIR"/goiabada-*.zip
