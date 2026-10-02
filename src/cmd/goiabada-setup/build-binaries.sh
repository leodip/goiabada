#!/bin/bash
# Cross-compiles goiabada-setup for every supported platform.
#
# The version is no longer edited into this file. It comes from the caller,
# which in a release is the git tag. A plain local run produces "dev", which
# is the honest answer for a source build.
set -euo pipefail

VERSION="${GOIABADA_VERSION:-dev}"

while [ $# -gt 0 ]; do
    case "$1" in
        --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
        # Turns a future typo into a failure rather than a silently ignored
        # argument.
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

echo "Version: $VERSION"
echo "Current directory: $(pwd)"

BUILD_DIR=./build

# Function to build for a specific platform
build_platform() {
    local os=$1
    local arch=$2
    local extension=$3  # Empty for Unix, .exe for Windows

    echo "Building goiabada-setup for $os $arch..."

    # imageTag gets the same value as version: the wizard writes deployment
    # manifests for users, and the images it points them at must be the ones
    # that shipped in this release. Both derive from one tag, so they cannot
    # disagree.
    #
    # -w drops the DWARF debug data, as the servers' release builds do (#331).
    # It is -w and not -s -w, which this script passed until then: -s drops
    # the symbol table too, which is what `govulncheck -mode=binary` matches at
    # symbol level, and without it the scan reported GO-2026-5932, in a package
    # the wizard never calls, as affecting it. Panics keep function, file and
    # line either way. For a debuggable copy of a release, run this script at
    # the release's tag with the release's --version and -w removed, on the
    # same Go version and at the same paths the release job compiled at (the
    # runner's checkout, /home/runner/work/goiabada/goiabada, its module cache,
    # /home/runner/go/pkg/mod, and the GOROOT setup-go installed): the
    # rebuild's code is byte-identical at identical addresses, so its DWARF
    # describes the shipped binary.
    GOOS=$os GOARCH=$arch go build -v \
        -ldflags "-w -X main.version=${VERSION} -X main.imageTag=${VERSION}" \
        -o "${BUILD_DIR}/goiabada-setup-${os}-${arch}${extension}" \
        .
}

# Verify go.mod exists
if [ ! -f "go.mod" ]; then
    echo "Error: Could not find go.mod. Run this script from src/cmd/goiabada-setup/"
    exit 1
fi

echo "Setting CGO_ENABLED=0..."
export CGO_ENABLED=0

echo "Downloading dependencies..."
go mod download -x

# Start clean, so a failed build cannot leave a previous run's binary on disk
# for the release job to pick up and upload.
mkdir -p "$BUILD_DIR"
rm -f "$BUILD_DIR"/goiabada-setup-*

# Build for each platform
build_platform "linux" "amd64" ""
build_platform "linux" "arm64" ""
build_platform "darwin" "amd64" ""
build_platform "darwin" "arm64" ""
build_platform "windows" "amd64" ".exe"

# Explicit manifest of what must exist. `set -e` catches a failing go build,
# but not a build that silently produced nothing, and the filenames are
# load-bearing: the docs link to /releases/latest/download/<these names>.
EXPECTED=(
    "goiabada-setup-linux-amd64"   "goiabada-setup-linux-arm64"
    "goiabada-setup-darwin-amd64"  "goiabada-setup-darwin-arm64"
    "goiabada-setup-windows-amd64.exe"
)
for f in "${EXPECTED[@]}"; do
    [ -s "${BUILD_DIR}/${f}" ] || { echo "missing or empty artifact: $f" >&2; exit 1; }
done

echo ""
echo "Build process completed successfully!"
echo "Artifacts:"
ls -la "$BUILD_DIR"/
