#!/bin/sh
# go-install-with-x-tools.sh <package>@<version> golang.org/x/tools@<version> <binary>
#
# Installs <package> at <version>, as `go install <package>@<version>` would, but built against the
# golang.org/x/tools version named instead of the one the tool's own go.mod requires. The binary
# lands in GOBIN, or in GOPATH/bin when GOBIN is unset, under the name given.
#
# `go install pkg@version` always builds with the tool's own requirements and accepts no override,
# so this builds the package from a throwaway module that requires both: the tool's code is the
# pinned release's, unchanged, and only the library that reads compiled packages is newer. Every
# module it fetches is verified against the Go checksum database, as `go install` verifies them.
#
# It exists because Go 1.27.2 writes export data version 5, which golang.org/x/tools v0.49.0 cannot
# read ("export data version 5 is greater than maximum supported version 4"), and unparam and
# mockery both require v0.49.0 (mvdan/unparam#94, vektra/mockery#1187). The dev container's image
# and CI's Lint job build those two through here, against tools.x-tools-override in versions.yaml.
# The daily Upstream tools workflow opens an issue when either tool's latest version requires that
# x/tools or newer; once both do, they go back to plain `go install` and this script can go.
set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: $0 <package>@<version> golang.org/x/tools@<version> <binary>" >&2
    exit 2
fi
tool="$1"
xtools="$2"
binary="$3"
package="${tool%@*}"

case "$xtools" in
    golang.org/x/tools@v*) ;;
    *) echo "$0: the second argument must be golang.org/x/tools@v<version>, got $xtools" >&2; exit 2 ;;
esac

gobin="$(go env GOBIN)"
[ -n "$gobin" ] || gobin="$(go env GOPATH)/bin"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT
cd "$workdir"

go mod init goiabada.local/go-install-with-x-tools >/dev/null 2>&1
go get "$tool" "$xtools"
GOFLAGS=-mod=mod go build -o "$gobin/$binary" "$package"
echo "installed $gobin/$binary: $tool against $xtools"
