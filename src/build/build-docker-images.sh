#!/bin/bash
set -euo pipefail  # Exit on error, undefined variables, pipe failures

# Configuration
#
# The version is no longer edited into this file. It comes from the caller,
# which in a release is the git tag (see docs/ci-v2-design.md 4.1).
VERSION="${GOIABADA_VERSION:-dev}"
BUILD_DATE=$(date +%Y-%m-%d)
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Determine if this is a pre-release version (contains -alpha, -beta, -rc, etc.)
# Kept for reporting, and reinforced at the release level: `latest` is no longer
# this script's business at all (see below).
IS_PRERELEASE=false
if [[ "$VERSION" == *-* ]]; then
    IS_PRERELEASE=true
fi

# Platforms to build for:
# - linux/amd64: Standard x86_64 servers and PCs
# - linux/arm64: ARM servers (AWS Graviton, Raspberry Pi 4/5, Apple Silicon via Rosetta)
PLATFORMS="linux/amd64,linux/arm64"

# Builder name
BUILDER_NAME="goiabada-multiarch"

# Parse arguments.
#
# Proper long-option parsing rather than positional $1. An earlier proposal to
# read the version from $1 collided with the --push check that used to live
# here: `build-docker-images.sh --push` would have set VERSION=--push and
# published images tagged `authserver---push`, which is a legal Docker tag, so
# it would have succeeded. The *) arm turns a future typo into a failure
# instead of a silently ignored argument.
PUSH=false
while [ $# -gt 0 ]; do
    case "$1" in
        --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
        --push)    PUSH=true; shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

# Recompute after parsing, since --version may have changed it.
IS_PRERELEASE=false
if [[ "$VERSION" == *-* ]]; then
    IS_PRERELEASE=true
fi

# Validate Docker is available
if ! command -v docker &> /dev/null; then
    echo "Error: docker is not installed or not in PATH"
    exit 1
fi

echo "=== Build Configuration ==="
echo "Version: $VERSION"
echo "Build date: $BUILD_DATE"
echo "Git commit: $GIT_COMMIT"
if [[ "$IS_PRERELEASE" == true ]]; then
    echo "Pre-release: yes"
else
    echo "Pre-release: no"
fi
echo "Tags: version only ('latest' is moved by publish.yml on release)"
if [[ "$PUSH" == true ]]; then
    echo "Mode: Multi-platform build and push"
    echo "Platforms: $PLATFORMS"
else
    echo "Mode: Local build (single platform)"
    echo "Platform: linux/amd64"
fi
echo "Current directory: $(pwd)"

# Navigate to src directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."
echo "Working directory: $(pwd)"
echo ""

# Setup buildx builder
echo "=== Setting up buildx builder ==="
if ! docker buildx inspect "$BUILDER_NAME" &> /dev/null; then
    echo "Creating new buildx builder: $BUILDER_NAME"
    docker buildx create --name "$BUILDER_NAME" --driver docker-container --bootstrap --use
else
    echo "Using existing buildx builder: $BUILDER_NAME"
    docker buildx use "$BUILDER_NAME"
fi
echo ""

if [[ "$PUSH" == true ]]; then
    # Check if logged in to Docker Hub
    echo "=== Checking Docker Hub authentication ==="
    if ! docker info 2>/dev/null | grep -q "Username"; then
        echo "Warning: You may not be logged in to Docker Hub."
        echo "Run 'docker login' if the push fails."
    fi
    echo ""

    # Build and push authserver (multi-platform)
    echo "=== Building and pushing authserver image (multi-platform) ==="
    # Version tag only. The `latest` tags are no longer produced here: they are
    # moved by publish.yml when a release is deliberately published, so that the
    # tag every unpinned deployment follows changes at that moment rather than
    # whenever CI happens to go green (docs/ci-v2-design.md 4.6).
    AUTHSERVER_TAGS="-t leodip/goiabada:authserver-$VERSION"
    docker buildx build --progress=plain \
      --platform "$PLATFORMS" \
      -f ./build/Dockerfile-authserver \
      $AUTHSERVER_TAGS \
      --build-arg version=$VERSION \
      --build-arg buildDate=$BUILD_DATE \
      --build-arg gitCommit=$GIT_COMMIT \
      --push \
      .
    echo "✓ Authserver image built and pushed successfully"
    echo ""

    # Build and push adminconsole (multi-platform)
    echo "=== Building and pushing adminconsole image (multi-platform) ==="
    ADMINCONSOLE_TAGS="-t leodip/goiabada:adminconsole-$VERSION"
    docker buildx build --progress=plain \
      --platform "$PLATFORMS" \
      -f ./build/Dockerfile-adminconsole \
      $ADMINCONSOLE_TAGS \
      --build-arg version=$VERSION \
      --build-arg buildDate=$BUILD_DATE \
      --build-arg gitCommit=$GIT_COMMIT \
      --push \
      .
    echo "✓ Adminconsole image built and pushed successfully"
    echo ""

    echo "=== Multi-platform images pushed ==="
    echo "Images available for platforms: $PLATFORMS"
    echo ""
    echo "Verify with:"
    echo "  docker buildx imagetools inspect leodip/goiabada:authserver-$VERSION"
    echo "  docker buildx imagetools inspect leodip/goiabada:adminconsole-$VERSION"
else
    # Build authserver (local only, single platform)
    echo "=== Building authserver image (local) ==="
    # Version tag only. The `latest` tags are no longer produced here: they are
    # moved by publish.yml when a release is deliberately published, so that the
    # tag every unpinned deployment follows changes at that moment rather than
    # whenever CI happens to go green (docs/ci-v2-design.md 4.6).
    AUTHSERVER_TAGS="-t leodip/goiabada:authserver-$VERSION"
    docker buildx build --progress=plain \
      --platform linux/amd64 \
      -f ./build/Dockerfile-authserver \
      $AUTHSERVER_TAGS \
      --build-arg version=$VERSION \
      --build-arg buildDate=$BUILD_DATE \
      --build-arg gitCommit=$GIT_COMMIT \
      --load \
      .
    echo "✓ Authserver image built successfully"
    echo ""

    # Build adminconsole (local only, single platform)
    echo "=== Building adminconsole image (local) ==="
    ADMINCONSOLE_TAGS="-t leodip/goiabada:adminconsole-$VERSION"
    docker buildx build --progress=plain \
      --platform linux/amd64 \
      -f ./build/Dockerfile-adminconsole \
      $ADMINCONSOLE_TAGS \
      --build-arg version=$VERSION \
      --build-arg buildDate=$BUILD_DATE \
      --build-arg gitCommit=$GIT_COMMIT \
      --load \
      .
    echo "✓ Adminconsole image built successfully"
    echo ""

    echo "=== Built images ==="
    docker images | grep goiabada || echo "No goiabada images found"
    echo ""
    echo "To build and push multi-platform images, run: $0 --push"
fi

echo ""
echo "All done."
