#!/bin/bash
set -euo pipefail  # Exit on error, undefined variables, pipe failures

# Configuration
VERSION="1.4.4"
BUILD_DATE=$(date +%Y-%m-%d)
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Determine if this is a pre-release version (contains -alpha, -beta, -rc, etc.)
# Pre-release versions should NOT be tagged as "latest"
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

# Parse arguments
PUSH=false
if [[ "${1:-}" == "--push" ]]; then
    PUSH=true
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
    echo "Pre-release: yes (will NOT tag as 'latest')"
else
    echo "Pre-release: no (will tag as 'latest')"
fi
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
    AUTHSERVER_TAGS="-t leodip/goiabada:authserver-$VERSION"
    if [[ "$IS_PRERELEASE" == false ]]; then
        AUTHSERVER_TAGS="$AUTHSERVER_TAGS -t leodip/goiabada:authserver-latest"
    fi
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
    if [[ "$IS_PRERELEASE" == false ]]; then
        ADMINCONSOLE_TAGS="$ADMINCONSOLE_TAGS -t leodip/goiabada:adminconsole-latest"
    fi
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
    AUTHSERVER_TAGS="-t leodip/goiabada:authserver-$VERSION"
    if [[ "$IS_PRERELEASE" == false ]]; then
        AUTHSERVER_TAGS="$AUTHSERVER_TAGS -t leodip/goiabada:authserver-latest"
    fi
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
    if [[ "$IS_PRERELEASE" == false ]]; then
        ADMINCONSOLE_TAGS="$ADMINCONSOLE_TAGS -t leodip/goiabada:adminconsole-latest"
    fi
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
