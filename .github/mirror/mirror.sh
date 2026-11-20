#!/bin/bash
# The mirror of the images CI pulls, public packages under ghcr.io/leodip/goiabada-ci/ (#867).
# Docker Hub allows an account 200 pulls in 6 hours, and every job of every Check run pulled its own
# images from it until a few runs in one hour were refused. The tags are the lines of images, beside
# this script, each a Docker Hub address whose {tools.<name>} is read from
# src/authserver/versions.yaml.
#
#   mirror.sh list     Prints each tag's Docker Hub address and mirror address, one tag per line.
#   mirror.sh copy     The Mirror workflow's copy. Copies each tag whose digest at the mirror is not
#                      Docker Hub's, every platform and with upstream's digests, using skopeo, which
#                      the ubuntu-24.04 runner image ships. Docker Hub is read logged in with
#                      DOCKERHUB_USERNAME and DOCKERHUB_TOKEN, a token that reads public images and
#                      nothing else, and the mirror written with GHCR_USERNAME and GHCR_TOKEN.
#   mirror.sh missing  Asks the mirror anonymously for every tag and names each one it lacks, or
#                      holds in a package that is not public, and what to do.
#   mirror.sh public   Reads every tag anonymously, as a pull on the runner does, and names each
#                      package whose registry refuses a read, so is not public, with where to make it
#                      public: a new GHCR package starts private, and GitHub has no API to change
#                      that. A read the registry answers otherwise, an error or a stall, is reported
#                      with that answer, as no answer on the package.
#
# Docker Hub counts a pull per manifest GET, once per platform for a multi-platform image, and none
# for a HEAD, which answers a tag's digest in its Docker-Content-Digest header. So copy asks both
# registries for each tag's digest with a HEAD, and pulls only the tags whose digests differ: the
# first fill costs a pull per platform of every tag, a version bump the new tag's, and a refresh
# what upstream moved. The Mirror workflow runs one copy at a time, across branches, so each compares
# against what the one before it wrote. The copy names upstream's image by the digest it compared,
# so what lands in the mirror is that digest even when upstream moves meanwhile, and both digests
# are asked again after it: a tag is copied again while they differ.
#
# Every tag is handled even after one fails, so one run names every failure. Messages are GitHub
# error annotations. Exits 0 when every tag passes, 1 when any fails, and 2 on a usage error.
set -euo pipefail

MIRROR=ghcr.io/leodip/goiabada-ci
# The GitHub account the packages belong to, whose package settings make one public.
MIRROR_OWNER=leodip

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
IMAGES=${MIRROR_IMAGES:-$here/images}
VERSIONS=${MIRROR_VERSIONS:-$here/../../src/authserver/versions.yaml}

# Every registry request gives up after MIRROR_REQUEST_SECONDS, connecting within 5, so a registry
# that stalls fails its tag in seconds and the other tags are still asked: the Versions job, which
# every pulling job of Check waits for, asks the mirror for every tag on every run.
REQUEST_SECONDS=${MIRROR_REQUEST_SECONDS:-20}
CURL_LIMITS=(--connect-timeout 5 --max-time "$REQUEST_SECONDS")

# How many times copy copies one tag before it gives up on a mirror that is still not upstream's.
COPY_ATTEMPTS=3

# The platform of the runners Check pulls on, whose image of a multi-platform tag public reads.
RUNNER_OS=linux
RUNNER_ARCH=amd64

# The manifest types a HEAD accepts: a multi-platform index or list first, so its digest is the one
# answered, and a single platform's manifest for an image that has no index.
MANIFEST_TYPES="application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"

error() { echo "::error::$*"; }

usage() {
    [ $# -eq 0 ] || echo "$1" >&2
    echo "usage: mirror.sh list|copy|missing|public" >&2
    exit 2
}

# mirror_list prints "<Docker Hub address> <mirror address>" for each tag of the list, with its
# pins read from versions.yaml. A pin versions.yaml lacks, a line that is not a Docker Hub address,
# and two images whose packages would share a name each fail.
mirror_list() {
    local line image tag key value package n=0
    local -A packages=()
    [ -r "$IMAGES" ] || { error "cannot read the mirror's list, $IMAGES"; return 1; }
    while IFS= read -r line || [ -n "$line" ]; do
        n=$((n + 1))
        line=${line%%#*}
        line=${line//[[:space:]]/}
        [ -n "$line" ] || continue
        if ! [[ $line =~ ^docker\.io/[a-z0-9._/-]+:[A-Za-z0-9_.{}-]+$ ]]; then
            error "$IMAGES:$n: $line is not a Docker Hub image with a tag, docker.io/<repository>:<tag>"
            return 1
        fi
        image=${line%:*}
        tag=${line##*:}
        while [[ $tag =~ \{(tools\.[a-z0-9_-]+)\} ]]; do
            key=${BASH_REMATCH[1]}
            value=$(yq -r ".tools.\"${key#tools.}\"" "$VERSIONS") || { error "cannot read $VERSIONS"; return 1; }
            if ! [[ $value =~ ^[A-Za-z0-9_.-]+$ ]] || [ "$value" = null ]; then
                error "$IMAGES:$n names {$key}, which $VERSIONS does not hold as a version"
                return 1
            fi
            tag=${tag//"{$key}"/$value}
        done
        if [[ $tag == *[{}]* ]]; then
            error "$IMAGES:$n: $tag holds a brace that is not a {tools.<name>} of $VERSIONS"
            return 1
        fi
        package=${image##*/}
        if [ -n "${packages[$package]:-}" ] && [ "${packages[$package]}" != "$image" ]; then
            error "$IMAGES:$n: $image and ${packages[$package]} would share the package $MIRROR/$package"
            return 1
        fi
        packages[$package]=$image
        echo "$image:$tag $MIRROR/$package:$tag"
    done < "$IMAGES"
}

# http_status prints the status code of the answer curl --include or --head printed.
http_status() {
    local first
    first=$(printf '%s\n' "$1" | head -n 1)
    first=${first%$'\r'}
    [[ $first =~ ^HTTP/[0-9.]+\ ([0-9]{3}) ]] && echo "${BASH_REMATCH[1]}"
}

# registry_token <registry> <repository> [netrc] prints a token to pull repository with, logged in
# when netrc holds a login for the token service. Returns 1 when the registry refuses one, as GHCR
# does anonymously for a package that is not public, and 2 when it cannot be asked.
registry_token() {
    local registry=$1 repository=$2 netrc=${3:-} url answer status token
    case $registry in
        docker.io) url="https://auth.docker.io/token?service=registry.docker.io&scope=repository:$repository:pull" ;;
        ghcr.io) url="https://ghcr.io/token?service=ghcr.io&scope=repository:$repository:pull" ;;
        *) echo "mirror.sh: no token service known for $registry" >&2; return 2 ;;
    esac
    answer=$(curl --silent --show-error --include "${CURL_LIMITS[@]}" ${netrc:+--netrc-file "$netrc"} "$url") || return 2
    status=$(http_status "$answer")
    case $status in
        200) ;;
        401 | 403 | 404) return 1 ;;
        *) echo "mirror.sh: $registry answered ${status:-no status} to a token request for $repository" >&2; return 2 ;;
    esac
    token=$(printf '%s\n' "$answer" | tr -d '\r' | sed '1,/^$/d' | yq -p json -r '.token // .access_token // ""' 2>/dev/null) || token=""
    [ -n "$token" ] || { echo "mirror.sh: $registry answered no token for $repository" >&2; return 2; }
    echo "$token"
}

# registry_digest <address> [netrc] prints the digest a registry holds for an image's tag, asked
# with a HEAD, which Docker Hub does not count as a pull. Returns 1 when the registry holds no such
# tag for the asker, and 2 when it cannot be asked. The token reaches curl on its standard input,
# as a header, never on its command line, which any process on the runner can read.
registry_digest() {
    local ref=$1 netrc=${2:-} registry rest repository tag host token answer status digest
    registry=${ref%%/*}
    rest=${ref#*/}
    repository=${rest%:*}
    tag=${rest##*:}
    host=$registry
    [ "$registry" != docker.io ] || host=registry-1.docker.io
    token=$(registry_token "$registry" "$repository" "$netrc") || return
    answer=$(printf 'Authorization: Bearer %s\n' "$token" | curl --silent --show-error --head "${CURL_LIMITS[@]}" \
        --header @- --header "Accept: $MANIFEST_TYPES" \
        "https://$host/v2/$repository/manifests/$tag") || return 2
    status=$(http_status "$answer")
    case $status in
        200) ;;
        401 | 403 | 404) return 1 ;;
        *) echo "mirror.sh: $registry answered ${status:-no status} for $ref" >&2; return 2 ;;
    esac
    digest=$(printf '%s\n' "$answer" | tr -d '\r' | awk 'tolower($1) == "docker-content-digest:" { print $2; exit }')
    [[ $digest =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "mirror.sh: $registry answered no digest for $ref" >&2; return 2; }
    echo "$digest"
}

# copy_tag copies one tag from upstream to mirror until the mirror holds the digest upstream holds
# when it is asked again after the copy: upstream can move while a copy runs, and the copy lands the
# digest it compared. Returns 1, after an error, when it cannot.
copy_tag() {
    local upstream=$1 mirror=$2 netrc=$3 authfile=$4 want have status copies=0
    while :; do
        if ! want=$(registry_digest "$upstream" "$netrc"); then
            error "cannot read the digest of $upstream from Docker Hub"
            return 1
        fi
        have=$(registry_digest "$mirror" "$netrc") && status=0 || status=$?
        if [ "$status" = 2 ]; then
            error "cannot read the digest of $mirror"
            return 1
        fi
        [ "$status" = 0 ] || have=""
        if [ "$have" = "$want" ]; then
            if [ "$copies" = 0 ]; then
                echo "$mirror is $want, as upstream: not copied"
            else
                echo "$mirror is $want, as upstream"
            fi
            return 0
        fi
        if [ "$copies" = "$COPY_ATTEMPTS" ]; then
            error "$mirror is ${have:-absent} after $copies copies, not upstream's $want; re-run this job"
            return 1
        fi
        echo "copying $upstream ($want) to $mirror, which is ${have:-absent}"
        if ! skopeo copy --authfile "$authfile" --retry-times 3 --all --preserve-digests \
            "docker://${upstream%:*}@$want" "docker://$mirror"; then
            error "cannot copy $upstream ($want) to $mirror"
            return 1
        fi
        copies=$((copies + 1))
    done
}

mirror_copy() {
    local list secrets upstream mirror failed=0 v
    for v in DOCKERHUB_USERNAME DOCKERHUB_TOKEN GHCR_USERNAME GHCR_TOKEN; do
        if [ -z "${!v:-}" ]; then
            error "$v is empty. The Mirror workflow reads Docker Hub logged in, with the repository secrets DOCKERHUB_USERNAME and DOCKERHUB_TOKEN, a Docker Hub user and an access token that can read public images, and writes the mirror with the job's GITHUB_TOKEN as GHCR_USERNAME and GHCR_TOKEN"
            return 1
        fi
    done
    command -v skopeo >/dev/null || { error "skopeo is not installed; the ubuntu-24.04 runner image ships it"; return 1; }
    list=$(mirror_list) || { echo "$list"; return 1; }

    # The logins live in files of this run alone: curl reads a netrc and skopeo an auth file, and
    # the tokens reach neither on a command line, which any process on the runner can read.
    secrets=$(mktemp -d)
    trap "rm -rf '$secrets'" EXIT
    (
        umask 077
        printf 'machine auth.docker.io login %s password %s\nmachine ghcr.io login %s password %s\n' \
            "$DOCKERHUB_USERNAME" "$DOCKERHUB_TOKEN" "$GHCR_USERNAME" "$GHCR_TOKEN" > "$secrets/netrc"
    )
    printf '%s' "$DOCKERHUB_TOKEN" | skopeo login --authfile "$secrets/auth.json" \
        --username "$DOCKERHUB_USERNAME" --password-stdin docker.io >/dev/null || { error "cannot log in to Docker Hub as $DOCKERHUB_USERNAME"; return 1; }
    printf '%s' "$GHCR_TOKEN" | skopeo login --authfile "$secrets/auth.json" \
        --username "$GHCR_USERNAME" --password-stdin ghcr.io >/dev/null || { error "cannot log in to ghcr.io as $GHCR_USERNAME"; return 1; }

    while read -r upstream mirror <&3; do
        copy_tag "$upstream" "$mirror" "$secrets/netrc" "$secrets/auth.json" || failed=1
    done 3<<< "$list"
    return $failed
}

mirror_missing() {
    local list upstream mirror status missing=0 n=0
    list=$(mirror_list) || { echo "$list"; return 1; }
    while read -r upstream mirror <&3; do
        n=$((n + 1))
        registry_digest "$mirror" >/dev/null && status=0 || status=$?
        case $status in
            0) ;;
            1)
                error "$mirror is not in the mirror, or its package is not public. The Mirror workflow copies the tags of .github/mirror/images, whose versions src/authserver/versions.yaml pins, on a push to a branch of this repository that changes either: wait for that push's Mirror run, or start the Mirror workflow from the Actions tab, then re-run this job. A fork's pull request needs a maintainer to push the change to a branch of this repository first."
                missing=1
                ;;
            *)
                error "cannot ask ghcr.io for $mirror (upstream $upstream); re-run this job"
                missing=1
                ;;
        esac
    done 3<<< "$list"
    [ "$missing" = 1 ] || echo "the mirror holds all $n tags"
    return $missing
}

# registry_answer <token> <url> [curl options] prints the registry's answer to a request made with
# the token, its status line and headers, then its body. Returns 2 when the registry cannot be asked.
registry_answer() {
    local token=$1 url=$2
    shift 2
    printf 'Authorization: Bearer %s\n' "$token" | curl --silent --show-error --include "${CURL_LIMITS[@]}" \
        --header @- "$@" "$url" || return 2
}

# anonymous_read <address> reads a tag anonymously as a pull on the runner does, without downloading
# a layer: a token with no login, the tag's manifest, the runner's platform's image's manifest when
# the tag is a multi-platform index, then a HEAD of that image's config and of each of its layers,
# which answers each blob's headers alone, with the access its download would get: GHCR answers 200,
# and a redirect, which would leave the blob unread, is no answer. Prints how many blobs it read, or
# what failed. Returns 1 when the registry refuses a request for want of access, 401 or 403, or the
# token, and 2 when it cannot be asked or answers anything else.
anonymous_read() {
    local ref=$1 registry rest repository tag token answer status body digest blob n=0
    registry=${ref%%/*}
    rest=${ref#*/}
    repository=${rest%:*}
    tag=${rest##*:}
    token=$(registry_token "$registry" "$repository" 2>&1) && status=0 || status=$?
    case $status in
        0) ;;
        1) echo "$registry refused an anonymous token"; return 1 ;;
        *) echo "$token"; return 2 ;;
    esac
    digest=$tag
    while :; do
        answer=$(registry_answer "$token" "https://$registry/v2/$repository/manifests/$digest" --header "Accept: $MANIFEST_TYPES") ||
            { echo "cannot ask $registry for the manifest of $ref"; return 2; }
        status=$(http_status "$answer")
        case $status in
            200) ;;
            401 | 403) echo "$registry answered $status to the manifest request"; return 1 ;;
            *) echo "$registry answered ${status:-no status} to the manifest request"; return 2 ;;
        esac
        body=$(printf '%s\n' "$answer" | tr -d '\r' | sed '1,/^$/d')
        [ "$(yq -p json -r 'has("manifests")' <<< "$body" 2>/dev/null)" = true ] || break
        [ "$digest" = "$tag" ] || { echo "$registry answered an index for the image $digest"; return 2; }
        digest=$(yq -p json -r "[.manifests[] | select(.platform.os == \"$RUNNER_OS\" and .platform.architecture == \"$RUNNER_ARCH\")][0].digest // \"\"" <<< "$body" 2>/dev/null) || digest=""
        [[ $digest =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "$registry holds no $RUNNER_OS/$RUNNER_ARCH image for $ref"; return 2; }
    done
    for blob in $(yq -p json -r '.config.digest, .layers[].digest' <<< "$body" 2>/dev/null); do
        [[ $blob =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "$registry answered a manifest naming $blob as a blob"; return 2; }
        answer=$(registry_answer "$token" "https://$registry/v2/$repository/blobs/$blob" --head) ||
            { echo "cannot ask $registry for the blob $blob"; return 2; }
        status=$(http_status "$answer")
        case $status in
            200) ;;
            401 | 403) echo "$registry answered $status to the request for the blob $blob"; return 1 ;;
            *) echo "$registry answered ${status:-no status} to the request for the blob $blob"; return 2 ;;
        esac
        n=$((n + 1))
    done
    [ "$n" -gt 0 ] || { echo "$registry answered a manifest naming no blob"; return 2; }
    echo "$n"
}

mirror_public() {
    local list upstream mirror package out status failed=0
    local -a order=()
    local -A refused=()
    list=$(mirror_list) || { echo "$list"; return 1; }
    while read -r upstream mirror <&3; do
        out=$(anonymous_read "$mirror") && status=0 || status=$?
        case $status in
            0)
                echo "read $mirror anonymously: its manifest and $out blobs, $RUNNER_OS/$RUNNER_ARCH, none downloaded"
                continue
                ;;
            1) echo "$mirror: $out" ;;
            *)
                error "the anonymous read of $mirror failed, and not for want of access, so this says nothing of whether its package is public: $out. Re-run this job."
                failed=1
                continue
                ;;
        esac
        package=${mirror%:*}
        [ -n "${refused[$package]:-}" ] || order+=("$package")
        refused[$package]+=" ${mirror##*:}"
    done 3<<< "$list"
    for package in "${order[@]}"; do
        local name=${package#ghcr.io/"$MIRROR_OWNER"/}
        error "$package refused an anonymous read (tags:${refused[$package]}), so the package is not public: a new GHCR package starts private. Make it public at https://github.com/users/$MIRROR_OWNER/packages/container/${name//\//%2F}/settings, under Danger Zone, Change visibility, then re-run this job."
    done
    [ "${#order[@]}" = 0 ] && [ "$failed" = 0 ]
}

[ $# -eq 1 ] || usage
case $1 in
    list) mirror_list ;;
    copy) mirror_copy ;;
    missing) mirror_missing ;;
    public) mirror_public ;;
    *) usage "unknown command: $1" ;;
esac
