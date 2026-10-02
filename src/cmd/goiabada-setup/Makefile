# Goiabada Setup CLI - Build Makefile
# build is a local dev build for this machine. build-all cross-compiles every
# release platform by running build-binaries.sh, the release build itself, so
# it produces what a release ships: the production tag, -w and the version
# stamp. TestReleaseBuilds_TheRealWizardMakefileDelegates, in core's unit
# tier, fails when this file cross-compiles with a go build of its own (#463).

# The product version comes from the git tag at release time, not from this
# file. A local `make` build is honestly marked "dev".
VERSION ?= $(or $(GOIABADA_VERSION),dev)
BUILD_DIR = ./build
BINARY_NAME = goiabada-setup

.PHONY: all clean build build-all check format

all: build-all

clean:
	rm -rf $(BUILD_DIR)

# Like the servers' dev builds, it sets no tag and ships nothing.
build:
	go build -o $(BUILD_DIR)/$(BINARY_NAME) .

build-all:
	./build-binaries.sh --version "$(VERSION)"

check:
	unparam -exported ./...
	golangci-lint run ./...

format:
	gofmt -w -s .
