# Goiabada Setup CLI - Build Makefile
# Builds cross-platform binaries for Linux, macOS, and Windows

VERSION ?= 1.2.1
BUILD_DIR = ./build
BINARY_NAME = goiabada-setup

# Build targets
.PHONY: all clean build build-all build-linux build-darwin build-windows

all: build-all

clean:
	rm -rf $(BUILD_DIR)

build:
	go build -o $(BUILD_DIR)/$(BINARY_NAME) ./main.go

# Build for all platforms
build-all: clean build-linux build-darwin build-windows
	@echo "All builds completed!"
	@ls -la $(BUILD_DIR)/

# Linux builds
build-linux: build-linux-amd64 build-linux-arm64

build-linux-amd64:
	@echo "Building for Linux amd64..."
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./main.go

build-linux-arm64:
	@echo "Building for Linux arm64..."
	GOOS=linux GOARCH=arm64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./main.go

# macOS builds
build-darwin: build-darwin-amd64 build-darwin-arm64

build-darwin-amd64:
	@echo "Building for macOS amd64..."
	GOOS=darwin GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./main.go

build-darwin-arm64:
	@echo "Building for macOS arm64 (Apple Silicon)..."
	GOOS=darwin GOARCH=arm64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./main.go

# Windows builds
build-windows: build-windows-amd64

build-windows-amd64:
	@echo "Building for Windows amd64..."
	GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./main.go

# Create release archives
release: build-all
	@echo "Creating release archives..."
	@mkdir -p $(BUILD_DIR)/release
	@cd $(BUILD_DIR) && zip release/goiabada-setup-$(VERSION)-linux-amd64.zip $(BINARY_NAME)-linux-amd64
	@cd $(BUILD_DIR) && zip release/goiabada-setup-$(VERSION)-linux-arm64.zip $(BINARY_NAME)-linux-arm64
	@cd $(BUILD_DIR) && zip release/goiabada-setup-$(VERSION)-darwin-amd64.zip $(BINARY_NAME)-darwin-amd64
	@cd $(BUILD_DIR) && zip release/goiabada-setup-$(VERSION)-darwin-arm64.zip $(BINARY_NAME)-darwin-arm64
	@cd $(BUILD_DIR) && zip release/goiabada-setup-$(VERSION)-windows-amd64.zip $(BINARY_NAME)-windows-amd64.exe
	@echo "Release archives created in $(BUILD_DIR)/release/"
	@ls -la $(BUILD_DIR)/release/
