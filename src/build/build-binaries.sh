#!/bin/bash
VERSION="1.4.3"
BUILD_DATE=$(date +%Y-%m-%d)
GIT_COMMIT=$(git rev-parse --short HEAD)

echo "Version: $VERSION"
echo "Build date: $BUILD_DATE"
echo "Git commit: $GIT_COMMIT"
echo "Current directory: $(pwd)"

# Function to build both applications for a specific platform
build_platform() {
    local os=$1
    local arch=$2
    local extension=$3  # Empty for Unix, .exe for Windows
    
    echo "Building for $os $arch..."
    
    # Build authserver
    echo "Building authserver..."
    cd ../authserver
    GOOS=$os GOARCH=$arch go build -v -tags=production \
        -ldflags '-X "github.com/leodip/goiabada/core/constants.Version='${VERSION}'" -X "github.com/leodip/goiabada/core/constants.BuildDate='${BUILD_DATE}'" -X "github.com/leodip/goiabada/core/constants.GitCommit='${GIT_COMMIT}'"' \
        -o ../build/goiabada-authserver${extension} \
        ./cmd/goiabada-authserver/main.go
    
    # Build adminconsole
    echo "Building adminconsole..."
    cd ../adminconsole
    GOOS=$os GOARCH=$arch go build -v -tags=production \
        -ldflags '-X "github.com/leodip/goiabada/core/constants.Version='${VERSION}'" -X "github.com/leodip/goiabada/core/constants.BuildDate='${BUILD_DATE}'" -X "github.com/leodip/goiabada/core/constants.GitCommit='${GIT_COMMIT}'"' \
        -o ../build/goiabada-adminconsole${extension} \
        ./cmd/goiabada-adminconsole/main.go
    
    # Create ZIP with both binaries
    cd ../build
    echo "Creating ZIP package for $os $arch..."
    zip -v "goiabada-${VERSION}-${os}-${arch}.zip" \
        "goiabada-authserver${extension}" \
        "goiabada-adminconsole${extension}"
    
    # Clean up binaries
    rm "goiabada-authserver${extension}" "goiabada-adminconsole${extension}"
}

# Verify go.mod files exist
if [ ! -f "../authserver/go.mod" ] || [ ! -f "../adminconsole/go.mod" ]; then
    echo "Error: Could not find go.mod files. Cannot proceed with build."
    exit 1
fi
echo "Found go.mod files"

echo "Setting CGO_ENABLED=0..."
go env -w CGO_ENABLED=0

echo "Downloading dependencies for authserver..."
cd ../authserver
go mod download -x

echo "Downloading dependencies for adminconsole..."
cd ../adminconsole
go mod download -x

# Build for each platform
build_platform "linux" "amd64" ""
build_platform "linux" "arm64" ""
build_platform "darwin" "amd64" ""
build_platform "darwin" "arm64" ""
build_platform "windows" "amd64" ".exe"

echo "Build process completed successfully!"
echo "All binaries have been zipped and cleaned up."