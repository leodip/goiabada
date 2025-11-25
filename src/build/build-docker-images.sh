#!/bin/bash
set -euo pipefail  # Exit on error, undefined variables, pipe failures

# Configuration
VERSION="1.3.1"
BUILD_DATE=$(date +%Y-%m-%d)
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Validate Docker is available
if ! command -v docker &> /dev/null; then
    echo "Error: docker is not installed or not in PATH"
    exit 1
fi

echo "=== Build Configuration ==="
echo "Version: $VERSION"
echo "Build date: $BUILD_DATE"
echo "Git commit: $GIT_COMMIT"
echo "Current directory: $(pwd)"

# Navigate to src directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."
echo "Working directory: $(pwd)"
echo ""

# Build authserver
echo "=== Building authserver image ==="
docker build --progress=plain --no-cache \
  -f ./build/Dockerfile-authserver \
  -t leodip/goiabada:authserver-$VERSION \
  --build-arg version=$VERSION \
  --build-arg buildDate=$BUILD_DATE \
  --build-arg gitCommit=$GIT_COMMIT \
  .

docker tag leodip/goiabada:authserver-$VERSION leodip/goiabada:authserver-latest
echo "✓ Authserver image built successfully"
echo ""

# Build adminconsole
echo "=== Building adminconsole image ==="
docker build --progress=plain --no-cache \
  -f ./build/Dockerfile-adminconsole \
  -t leodip/goiabada:adminconsole-$VERSION \
  --build-arg version=$VERSION \
  --build-arg buildDate=$BUILD_DATE \
  --build-arg gitCommit=$GIT_COMMIT \
  .

docker tag leodip/goiabada:adminconsole-$VERSION leodip/goiabada:adminconsole-latest
echo "✓ Adminconsole image built successfully"
echo ""

echo "=== Built images ==="
docker images | grep goiabada || echo "No goiabada images found"
echo ""
echo "✓ All done."