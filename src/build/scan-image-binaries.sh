#!/bin/bash
# Build validation's gate on the binaries the release images ship (#808). The images are built
# FROM scratch and hold no operating system package, so what an image scanner can find in them is
# the server's binary; this scans that binary, on every platform a release pushes, before a
# release publishes anything.
#
# For each image, named under the platform it was built for, it copies the server's binary out of
# a container created from it and never started, and checks it:
#
#   - The image is of that platform, and its binary an ELF executable of the platform's
#     architecture, as file(1) reads it.
#   - The binary is statically linked: a scratch image holds no C library or loader for it.
#   - The build settings Go embedded in it, read with go version -m, carry CGO_ENABLED=0 and the
#     production tag, the build the Dockerfiles' cross-compile asks for.
#
# Then govulncheck -mode=binary scans it, in its default text output, which exits 3 on a finding.
# Its JSON, SARIF and OpenVEX outputs exit 0 "regardless of the number of detected
# vulnerabilities" (govulncheck v1.9.0, Exit codes), so the weekly Image scan's JSON invocation is
# not one to copy here; src/core/guard/release_binary_scan_test.go holds this script to the text
# output. A binary-mode finding is a vulnerable symbol present in the binary, which does not prove
# the code reaches it: "It may also report false positives for code that is in the binary but
# unreachable" (govulncheck v1.9.0, Limitations).
#
# The images it reads are build validation's own builds of the commit, from the release's
# Dockerfiles and build arguments, and never the published images: a release's Images job rebuilds
# and pushes its own, which this does not see, and the weekly Image scan reads the published ones.
#
# Every image is checked and scanned even after one fails, so one run shows every failure. A
# failed check, a binary that cannot be copied out, and a scan that finds or errors each fail the
# run.
#
# Usage: ./scan-image-binaries.sh --platform <os/arch> <image>... [--platform <os/arch> <image>...]
#
# Exits 0 when every binary passes, 1 when any fails, and 2 on a usage error.
set -euo pipefail

# The architecture file(1) names in each platform's ELF executables, for the platforms a release
# pushes, build-docker-images.sh's PLATFORMS.
declare -A MACHINE=([linux/amd64]="x86-64" [linux/arm64]="ARM aarch64")

usage() {
    [ $# -eq 0 ] || echo "$1" >&2
    echo "usage: scan-image-binaries.sh --platform <os/arch> <image>... [--platform <os/arch> <image>...]" >&2
    exit 2
}

TARGETS=()
platform=""
named=0
while [ $# -gt 0 ]; do
    case "$1" in
        --platform)
            [ $# -ge 2 ] || usage "--platform needs a value"
            [ -z "$platform" ] || [ "$named" -gt 0 ] || usage "--platform $platform names no image"
            [ -n "$2" ] && [ -n "${MACHINE[$2]+set}" ] || usage "$2 is not a platform a release pushes: linux/amd64 or linux/arm64"
            platform="$2"
            named=0
            shift 2
            ;;
        -*) usage "unknown argument: $1" ;;
        *)
            [ -n "$platform" ] || usage "$1 is named before any --platform"
            TARGETS+=("$platform $1")
            named=$((named + 1))
            shift
            ;;
    esac
done
[ -z "$platform" ] || [ "$named" -gt 0 ] || usage "--platform $platform names no image"
[ "${#TARGETS[@]}" -gt 0 ] || usage

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
failed=0
scans=0

fail() {
    echo "::error::$1"
    failed=1
}

# Checks and scans the binary of one image, which must be of the platform given.
scan_image() {
    local platform="$1" image="$2" got binary container dir file out copied description settings cgo tags status
    local machine="${MACHINE[$platform]}"

    if ! got=$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$image" 2>"$WORK/stderr"); then
        fail "$image: unable to inspect it: $(cat "$WORK/stderr")"
        return
    fi
    if [ "$got" != "$platform" ]; then
        fail "$image is $got, where it must be $platform"
        return
    fi
    # The entrypoint's first element is the server's binary.
    if ! binary=$(docker image inspect --format '{{index .Config.Entrypoint 0}}' "$image" 2>"$WORK/stderr"); then
        fail "$image: unable to read its entrypoint: $(cat "$WORK/stderr")"
        return
    fi
    if ! container=$(docker create --platform "$platform" "$image" 2>"$WORK/stderr"); then
        fail "$image: unable to create a container to copy its binary out of: $(cat "$WORK/stderr")"
        return
    fi
    scans=$((scans + 1))
    dir="$WORK/$scans"
    mkdir "$dir"
    file="$dir/${binary##*/}"
    copied=0
    out=$(docker cp -q "$container:$binary" "$file" 2>&1) || copied=1
    docker rm "$container" >/dev/null 2>&1 || true
    if [ "$copied" -ne 0 ]; then
        fail "$image: unable to copy $binary out of it: $out"
        return
    fi

    if ! description=$(file -b "$file" 2>&1); then
        fail "$image: unable to read what $binary is: $description"
    else
        echo "$binary: $description"
        case "$description" in
            "ELF 64-bit LSB "*", $machine, "*) ;;
            *) fail "$image: $binary is not an $machine executable: $description" ;;
        esac
        case "$description" in
            *", statically linked, "* | *", statically linked") ;;
            *) fail "$image: $binary is not statically linked: $description" ;;
        esac
    fi

    # go version -m prints each build setting as a tab, "build", a tab and key=value.
    if ! settings=$(go version -m "$file" 2>&1); then
        fail "$image: unable to read the build settings of $binary: $settings"
    else
        cgo=$(awk -F '\t' '$2 == "build" && $3 ~ /^CGO_ENABLED=/ { print substr($3, 13) }' <<<"$settings")
        tags=$(awk -F '\t' '$2 == "build" && $3 ~ /^-tags=/ { print substr($3, 7) }' <<<"$settings")
        echo "$binary: CGO_ENABLED=$cgo -tags=$tags"
        [ "$cgo" = 0 ] || fail "$image: $binary was built with CGO_ENABLED=$cgo, where it must be 0"
        [[ ",$tags," == *,production,* ]] || fail "$image: $binary was built without the production tag (-tags=$tags)"
    fi

    status=0
    govulncheck -mode=binary "$file" || status=$?
    case "$status" in
        0) ;;
        3) fail "$image: govulncheck found vulnerable symbols present in $binary; their presence does not show the code reaches them" ;;
        *) fail "$image: govulncheck could not scan $binary, exit code $status" ;;
    esac
}

for target in "${TARGETS[@]}"; do
    platform="${target%% *}"
    image="${target#* }"
    echo "::group::$image ($platform)"
    scan_image "$platform" "$image"
    echo "::endgroup::"
done

if [ "$failed" -ne 0 ]; then
    echo "A binary failed its checks or its scan; each failure is above."
fi
exit "$failed"
