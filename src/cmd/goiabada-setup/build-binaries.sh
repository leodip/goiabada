#!/bin/bash
VERSION="1.0.0"

echo "Version: $VERSION"
echo "Current directory: $(pwd)"

# Function to build for a specific platform
build_platform() {
    local os=$1
    local arch=$2
    local extension=$3  # Empty for Unix, .exe for Windows

    echo "Building goiabada-setup for $os $arch..."

    GOOS=$os GOARCH=$arch go build -v \
        -ldflags "-s -w" \
        -o "./build/goiabada-setup-${os}-${arch}${extension}" \
        ./main.go

    # Create ZIP
    echo "Creating ZIP package for $os $arch..."
    cd ./build
    zip "goiabada-setup-${VERSION}-${os}-${arch}.zip" "goiabada-setup-${os}-${arch}${extension}"
    rm "goiabada-setup-${os}-${arch}${extension}"
    cd ..
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

# Create build directory
mkdir -p ./build

# Build for each platform
build_platform "linux" "amd64" ""
build_platform "linux" "arm64" ""
build_platform "darwin" "amd64" ""
build_platform "darwin" "arm64" ""
build_platform "windows" "amd64" ".exe"

echo ""
echo "Build process completed successfully!"
echo "Artifacts:"
ls -la ./build/*.zip
