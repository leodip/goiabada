package guard

// CI's images come from a mirror, public packages under ghcr.io/leodip/goiabada-ci/, so a Check run
// draws nothing from Docker Hub's pull allowance (#867). .github/mirror/images is the list of the
// tags the mirror holds, eight tags in seven packages, their versions read from versions.yaml, and
// .github/mirror/mirror.sh is what reads it: list prints each tag with its mirror address, copy
// (the Mirror workflow's) copies from Docker Hub, logged in, every tag whose digest at the mirror
// is not upstream's, missing asks the mirror anonymously for every tag and names each one it lacks,
// and public reads every tag anonymously, as a pull on the runner does but without downloading its
// layers, and names each package that is not public.
//
// The script runs here with curl and skopeo replaced by stubs that answer as the registries do, from
// a registry the test writes, so no test reaches a network. Docker Hub counts a manifest GET as a
// pull and a HEAD as none, so the stubs log every request and the tests hold Docker Hub to HEADs;
// skopeo copy, the one pull, is held to every platform and upstream's digest.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mirrorScript, mirrorList and mirrorWorkflow are relative to the repository root.
const (
	mirrorScript   = ".github/mirror/mirror.sh"
	mirrorList     = ".github/mirror/images"
	mirrorWorkflow = ".github/workflows/mirror.yml"
)

// mirrorVersions is a versions.yaml whose pins are none of the committed ones, so a list that
// follows it is told apart from one that copies today's pins.
const mirrorVersions = `tools:
  go: "1.28.0"
  tailwind: "4.3.5"
  node: "27.0.1"
  golangci-lint: "2.15.0"
  mailpit: "1.40.2"
`

// mirrorTags are the eight tags mirrorVersions makes of the committed list, upstream and at the
// mirror, in the list's order.
var mirrorTags = [][2]string{
	{"docker.io/library/golang:1.28.0-bookworm", "ghcr.io/leodip/goiabada-ci/golang:1.28.0-bookworm"},
	{"docker.io/library/golang:1.28.0-alpine", "ghcr.io/leodip/goiabada-ci/golang:1.28.0-alpine"},
	{"docker.io/library/node:27.0.1-alpine", "ghcr.io/leodip/goiabada-ci/node:27.0.1-alpine"},
	{"docker.io/library/nginx:alpine", "ghcr.io/leodip/goiabada-ci/nginx:alpine"},
	{"docker.io/library/mysql:26", "ghcr.io/leodip/goiabada-ci/mysql:26"},
	{"docker.io/library/postgres:18", "ghcr.io/leodip/goiabada-ci/postgres:18"},
	{"docker.io/axllent/mailpit:v1.40.2", "ghcr.io/leodip/goiabada-ci/mailpit:v1.40.2"},
	{"docker.io/moby/buildkit:buildx-stable-1", "ghcr.io/leodip/goiabada-ci/buildkit:buildx-stable-1"},
}

// mirrorDigest is a digest of 64 hex digits made of one, so each tag of a test has its own.
func mirrorDigest(c byte) string {
	return "sha256:" + strings.Repeat(string(c), 64)
}

// upstreamDigests are Docker Hub's digests of mirrorTags, one per tag.
func upstreamDigests() map[string]string {
	digests := map[string]string{}
	for i, tag := range mirrorTags {
		digests[tag[0]] = mirrorDigest("0123456789abcdef"[i])
	}
	return digests
}

// The stubs keep the registry as a file per tag, <stub>/registry/<registry>/<repository>/<tag>,
// holding its digest, and a repository named under <stub>/private as a package that is not public:
// a request for it without credentials is refused. A manifest or blob request without the token the
// token request answered is refused, and a manifest request for a repository named under
// <stub>/stall answers nothing until curl's --max-time, an hour without one. A GET of a tag's
// manifest answers a multi-platform index, or the image's manifest for a repository named under
// <stub>/single; each platform's manifest names its config and two layers, whose digests tell the
// platforms apart. A file <stub>/status/<repository>/<token, manifest or blob> holds a status that
// request is answered with instead. skopeo refuses a copy into a package named under
// <stub>/copy-fails, and a copy into a package named under <stub>/moves lands, then moves upstream
// to what that file holds, "<upstream address> <digest>", as upstream moving while the copy ran;
// with STUB_KEEP_MOVING set it moves so after every copy. Each logs its arguments, one line per
// call, curl the headers it read on its standard input after " stdin=".
const (
	stubMirrorCurl = `#!/bin/bash
url=${!#}
netrc=0 head=0 maxtime="" headers="" stdin="" prev=""
for a in "$@"; do
    case "$prev" in
        --max-time) maxtime=$a ;;
        --header) if [ "$a" = @- ]; then stdin=$(cat); headers+="$stdin"$'\n'; else headers+="$a"$'\n'; fi ;;
    esac
    [ "$a" = --netrc-file ] && netrc=1
    [ "$a" = --head ] && head=1
    prev=$a
done
{ printf 'curl'; printf ' %s' "$@"; [ -z "$stdin" ] || printf ' stdin=%s' "$(tr '\n' ';' <<< "$stdin")"; echo; } >> "$STUB/log"
case "$url" in
    https://auth.docker.io/token\?*|https://ghcr.io/token\?*)
        repo=${url#*scope=repository:}; repo=${repo%:pull*}
        if [ -f "$STUB/status/$repo/token" ]; then
            printf 'HTTP/2 %s \r\ncontent-type: application/json\r\n\r\n' "$(cat "$STUB/status/$repo/token")"
            exit 0
        fi
        if [ $netrc = 0 ] && [ -e "$STUB/private/$repo" ]; then
            printf 'HTTP/2 403 \r\ncontent-type: application/json\r\n\r\n{"errors":[{"code":"DENIED","message":"requested access to the resource is denied"}]}\n'
            exit 0
        fi
        printf 'HTTP/2 200 \r\ncontent-type: application/json\r\n\r\n{"token":"stub-token","access_token":"stub-token","expires_in":300}\n'
        ;;
    https://registry-1.docker.io/v2/*/manifests/*|https://ghcr.io/v2/*/manifests/*)
        host=${url#https://}; host=${host%%/*}
        [ "$host" = registry-1.docker.io ] && host=docker.io
        path=${url#https://*/v2/}
        if [ -e "$STUB/stall/${path%/manifests/*}" ]; then
            sleep "${maxtime:-3600}"
            echo "curl: (28) Operation timed out after ${maxtime:-3600}000 milliseconds with 0 bytes received" >&2
            exit 28
        fi
        repo=${path%/manifests/*}; ref=${path##*/manifests/}
        f="$STUB/registry/$host/$repo/$ref"
        if [ -f "$STUB/status/$repo/manifest" ]; then
            printf 'HTTP/2 %s \r\ncontent-type: application/json\r\n\r\n' "$(cat "$STUB/status/$repo/manifest")"
        elif ! grep -qx 'Authorization: Bearer stub-token' <<< "$headers"; then
            printf 'HTTP/2 401 \r\ncontent-type: application/json\r\n\r\n'
        elif [[ $ref == sha256:* ]]; then
            # A platform's manifest, by the digest the index gave: amd64's blobs are c, 1 and 2.
            blobs='"config":{"digest":"sha256:9999999999999999999999999999999999999999999999999999999999999999"},"layers":[{"digest":"sha256:8888888888888888888888888888888888888888888888888888888888888888"}]'
            [ "$ref" != sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd ] ||
                blobs='"config":{"digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},"layers":[{"digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111"},{"digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222"}]'
            printf 'HTTP/2 200 \r\ncontent-type: application/vnd.oci.image.manifest.v1+json\r\n\r\n{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",%s}\n' "$blobs"
        elif [ ! -f "$f" ]; then
            printf 'HTTP/2 404 \r\ncontent-type: application/json\r\n\r\n'
        elif [ $head = 1 ]; then
            printf 'HTTP/2 200 \r\ncontent-type: application/vnd.oci.image.index.v1+json\r\ndocker-content-digest: %s\r\n\r\n' "$(cat "$f")"
        elif [ -e "$STUB/single/$repo" ]; then
            printf 'HTTP/2 200 \r\ncontent-type: application/vnd.docker.distribution.manifest.v2+json\r\n\r\n{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","config":{"digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},"layers":[{"digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111"},{"digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222"}]}\n'
        else
            # The amd64 image between an arm64 one and an attestation, as Buildx writes an index.
            printf 'HTTP/2 200 \r\ncontent-type: application/vnd.oci.image.index.v1+json\r\n\r\n{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[%s,%s,%s]}\n' \
                '{"digest":"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","platform":{"architecture":"arm64","os":"linux","variant":"v8"}}' \
                '{"digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","platform":{"architecture":"amd64","os":"linux"}}' \
                '{"digest":"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","platform":{"architecture":"unknown","os":"unknown"}}'
        fi
        ;;
    https://ghcr.io/v2/*/blobs/*)
        path=${url#https://ghcr.io/v2/}; repo=${path%/blobs/*}
        if [ -f "$STUB/status/$repo/blob" ]; then
            printf 'HTTP/2 %s \r\ncontent-type: application/json\r\n\r\n' "$(cat "$STUB/status/$repo/blob")"
        elif ! grep -qx 'Authorization: Bearer stub-token' <<< "$headers"; then
            printf 'HTTP/2 401 \r\ncontent-type: application/json\r\n\r\n'
        else
            printf 'HTTP/2 200 \r\ncontent-type: application/octet-stream\r\ncontent-length: 1048576\r\n\r\n'
        fi
        ;;
    *) echo "stub curl: unexpected $*" >&2; exit 7 ;;
esac
`
	stubMirrorSkopeo = `#!/bin/bash
case "$1" in
    login)
        { printf 'skopeo'; printf ' %s' "$@"; printf ' stdin=%s\n' "$(cat)"; } >> "$STUB/log"
        ;;
    copy)
        { printf 'skopeo'; printf ' %s' "$@"; echo; } >> "$STUB/log"
        src=${@: -2:1}; dst=${!#}
        src=${src#docker://}; dst=${dst#docker://}
        case "$src" in *@sha256:*) ;; *) echo "stub skopeo: $src names no digest" >&2; exit 1 ;; esac
        package=${dst%:*}; package=${package##*/}
        if [ -e "$STUB/copy-fails/$package" ]; then echo "stub skopeo: copy refused" >&2; exit 1; fi
        f="$STUB/registry/${dst%:*}/${dst##*:}"
        mkdir -p "$(dirname "$f")"
        echo "${src##*@}" > "$f"
        if [ -e "$STUB/moves/$package" ]; then
            read -r ref digest < "$STUB/moves/$package"
            # Under STUB_KEEP_MOVING upstream moves after every copy, never to the digest just copied.
            [ "$digest" != "${src##*@}" ] || digest=sha256:$(printf '3%.0s' {1..64})
            echo "$digest" > "$STUB/registry/${ref%:*}/${ref##*:}"
            [ -n "${STUB_KEEP_MOVING:-}" ] || rm "$STUB/moves/$package"
        fi
        ;;
    *) { printf 'skopeo'; printf ' %s' "$@"; echo; } >> "$STUB/log"; echo "stub skopeo: unexpected $*" >&2; exit 64 ;;
esac
`
)

// mirrorRegistry is what the stubbed registries hold: each tag's digest, by its address, the
// repositories whose package is not public, the mirror packages a copy into is refused, the
// repositories whose manifest requests stall, the mirror packages whose copy upstream moves past,
// to an upstream address and its new digest, the repositories whose tags are single-platform images
// rather than indexes, and the statuses a repository's requests are answered with, by repository
// and then by request: token, manifest or blob.
type mirrorRegistry struct {
	digests    map[string]string
	private    []string
	refuseCopy []string
	stall      []string
	moves      map[string][2]string
	single     []string
	statuses   map[string]map[string]string
}

// mirrorRun is a run of mirror.sh: whether it succeeded, what it printed, each stub call it made,
// and the registry as the run left it.
type mirrorRun struct {
	ok      bool
	out     string
	calls   []string
	stub    string
	elapsed time.Duration
}

// runMirror runs mirror.sh command with the stubs over registry, versions.yaml being versions, and
// env added to the environment.
func runMirror(t *testing.T, command, versions string, registry mirrorRegistry, env ...string) mirrorRun {
	t.Helper()
	return runMirrorOn(t, newMirrorStub(t, versions, registry), command, env...)
}

// newMirrorStub writes the stubs and registry to a directory of their own, versions.yaml being
// versions, and returns it, for one run or several over the same registry. HOME holds a Docker
// configuration logged in to ghcr.io, as a runner may, so a request made anonymously is one the
// script made so on purpose.
func newMirrorStub(t *testing.T, versions string, registry mirrorRegistry) string {
	t.Helper()
	stub := t.TempDir()
	bin := filepath.Join(stub, "bin")
	require.NoError(t, os.MkdirAll(bin, 0o755))
	for name, body := range map[string]string{"curl": stubMirrorCurl, "skopeo": stubMirrorSkopeo} {
		require.NoError(t, os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755))
	}
	for ref, digest := range registry.digests {
		f := filepath.Join(stub, "registry", ref[:strings.LastIndex(ref, ":")], ref[strings.LastIndex(ref, ":")+1:])
		require.NoError(t, os.MkdirAll(filepath.Dir(f), 0o755))
		require.NoError(t, os.WriteFile(f, []byte(digest+"\n"), 0o600))
	}
	for _, repo := range registry.private {
		require.NoError(t, os.MkdirAll(filepath.Join(stub, "private", repo), 0o755))
	}
	for _, pkg := range registry.refuseCopy {
		require.NoError(t, os.MkdirAll(filepath.Join(stub, "copy-fails", pkg), 0o755))
	}
	for _, repo := range registry.stall {
		require.NoError(t, os.MkdirAll(filepath.Join(stub, "stall", repo), 0o755))
	}
	for _, repo := range registry.single {
		require.NoError(t, os.MkdirAll(filepath.Join(stub, "single", repo), 0o755))
	}
	for repo, statuses := range registry.statuses {
		for request, status := range statuses {
			f := filepath.Join(stub, "status", repo, request)
			require.NoError(t, os.MkdirAll(filepath.Dir(f), 0o755))
			require.NoError(t, os.WriteFile(f, []byte(status+"\n"), 0o600))
		}
	}
	for pkg, move := range registry.moves {
		require.NoError(t, os.MkdirAll(filepath.Join(stub, "moves"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(stub, "moves", pkg), []byte(move[0]+" "+move[1]+"\n"), 0o600))
	}
	require.NoError(t, os.MkdirAll(filepath.Join(stub, ".docker"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(stub, ".docker", "config.json"),
		[]byte(`{"auths":{"ghcr.io":{"auth":"c3R1YjpzdHVi"}}}`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(stub, "versions.yaml"), []byte(versions), 0o600))
	return stub
}

// runMirrorOn runs mirror.sh command over the stub newMirrorStub wrote, with env added to the
// environment. The run's calls are the ones it logged, not an earlier run's over the same stub.
func runMirrorOn(t *testing.T, stub, command string, env ...string) mirrorRun {
	t.Helper()
	bin := filepath.Join(stub, "bin")
	logFile := filepath.Join(stub, "log")
	require.NoError(t, os.RemoveAll(logFile))

	// A run that waits on a stalled request ends here rather than at the test binary's timeout.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", filepath.Join(filepath.Dir(SourceRoot(t)), mirrorScript), command)
	cmd.WaitDelay = time.Second
	cmd.Env = append([]string{
		"PATH=" + bin + ":" + os.Getenv("PATH"), "STUB=" + stub, "HOME=" + stub, "TMPDIR=" + t.TempDir(),
		"MIRROR_VERSIONS=" + filepath.Join(stub, "versions.yaml"),
	}, env...)
	start := time.Now()
	out, err := cmd.CombinedOutput()
	run := mirrorRun{ok: err == nil, out: string(out), stub: stub, elapsed: time.Since(start)}
	if log, err := os.ReadFile(logFile); err == nil {
		run.calls = strings.Split(strings.TrimRight(string(log), "\n"), "\n")
	}
	return run
}

// digest is the digest the registry holds for ref after the run, or "" when it holds none.
func (r mirrorRun) digest(t *testing.T, ref string) string {
	t.Helper()
	i := strings.LastIndex(ref, ":")
	content, err := os.ReadFile(filepath.Join(r.stub, "registry", ref[:i], ref[i+1:]))
	if os.IsNotExist(err) {
		return ""
	}
	require.NoError(t, err)
	return strings.TrimSpace(string(content))
}

// copies are the skopeo copy calls of the run, each as its arguments after copy.
func (r mirrorRun) copies() []string {
	var out []string
	for _, c := range r.calls {
		if rest, ok := strings.CutPrefix(c, "skopeo copy "); ok {
			out = append(out, rest)
		}
	}
	return out
}

// errors are the lines the run printed as GitHub error annotations.
func (r mirrorRun) errors() []string {
	var out []string
	for line := range strings.SplitSeq(r.out, "\n") {
		if strings.HasPrefix(line, "::error::") {
			out = append(out, line)
		}
	}
	return out
}

// mirrorCredentials are the Mirror workflow's logins: the read-only Docker Hub token and the job's
// GitHub token.
var mirrorCredentials = []string{
	"DOCKERHUB_USERNAME=hub-user", "DOCKERHUB_TOKEN=dckr_pat_hub-secret",
	"GHCR_USERNAME=github-actor", "GHCR_TOKEN=ghs_job-secret",
}

// ---- the list --------------------------------------------------------------------------------

func TestMirrorList_FollowsVersionsYAML(t *testing.T) {
	run := runMirror(t, "list", mirrorVersions, mirrorRegistry{})
	require.True(t, run.ok, "list failed:\n%s", run.out)
	var want []string
	for _, tag := range mirrorTags {
		want = append(want, tag[0]+" "+tag[1])
	}
	assert.Equal(t, want, strings.Split(strings.TrimSpace(run.out), "\n"))
	assert.Empty(t, run.calls, "list asked a registry")
}

// The committed list, over the committed versions.yaml, is eight tags in the seven packages the
// maintainer makes public, the four without a pin at the tags Check and the docs build use today.
func TestMirrorList_TheCommittedListIsEightTagsInSevenPackages(t *testing.T) {
	versions, err := os.ReadFile(filepath.Join(SourceRoot(t), "authserver", "versions.yaml"))
	require.NoError(t, err)
	run := runMirror(t, "list", string(versions), mirrorRegistry{})
	require.True(t, run.ok, "list failed:\n%s", run.out)
	lines := strings.Split(strings.TrimSpace(run.out), "\n")
	assert.Len(t, lines, 8, "%s should hold eight tags", mirrorList)
	var packages []string
	var mirrored []string
	for _, line := range lines {
		upstream, mirror, ok := strings.Cut(line, " ")
		require.True(t, ok, "list printed %q, not an upstream and a mirror address", line)
		mirrored = append(mirrored, mirror)
		name := mirror[:strings.LastIndex(mirror, ":")]
		upstreamTag := upstream[strings.LastIndex(upstream, ":"):]
		assert.Equal(t, upstreamTag, mirror[strings.LastIndex(mirror, ":"):], "%s keeps upstream's tag", mirror)
		if !slices.Contains(packages, name) {
			packages = append(packages, name)
		}
	}
	assert.ElementsMatch(t, []string{
		"ghcr.io/leodip/goiabada-ci/golang", "ghcr.io/leodip/goiabada-ci/node", "ghcr.io/leodip/goiabada-ci/nginx",
		"ghcr.io/leodip/goiabada-ci/mysql", "ghcr.io/leodip/goiabada-ci/postgres", "ghcr.io/leodip/goiabada-ci/mailpit",
		"ghcr.io/leodip/goiabada-ci/buildkit",
	}, packages)
	for _, fixed := range []string{"nginx:alpine", "mysql:26", "postgres:18", "buildkit:buildx-stable-1"} {
		assert.Contains(t, mirrored, "ghcr.io/leodip/goiabada-ci/"+fixed)
	}
	assert.Contains(t, mirrored, "ghcr.io/leodip/goiabada-ci/mailpit:v"+mailpitPin(t))
}

// A pin the list names and versions.yaml lacks fails, naming it, rather than mirroring a tag
// with nothing where the version goes.
func TestMirrorList_APinVersionsYAMLLacksFails(t *testing.T) {
	versions := strings.Replace(mirrorVersions, "  node: \"27.0.1\"\n", "", 1)
	run := runMirror(t, "list", versions, mirrorRegistry{})
	assert.False(t, run.ok, "list passed without tools.node:\n%s", run.out)
	assert.Contains(t, run.out, "tools.node")
}

// ---- copy ------------------------------------------------------------------------------------

// The first run finds the mirror empty and copies every tag, from Docker Hub by upstream's digest,
// with every platform and that digest kept, leaving the mirror at upstream's digests.
func TestMirrorCopy_AnEmptyMirrorGetsEveryTagAtUpstreamsDigest(t *testing.T) {
	upstream := upstreamDigests()
	run := runMirror(t, "copy", mirrorVersions, mirrorRegistry{digests: upstream}, mirrorCredentials...)
	require.True(t, run.ok, "copy failed:\n%s", run.out)
	var want []string
	for _, tag := range mirrorTags {
		repo := tag[0][:strings.LastIndex(tag[0], ":")]
		want = append(want, "docker://"+repo+"@"+upstream[tag[0]]+" docker://"+tag[1])
		assert.Equal(t, upstream[tag[0]], run.digest(t, tag[1]), "%s after the copy", tag[1])
	}
	var copied []string
	for _, c := range run.copies() {
		words := strings.Fields(c)
		assert.Contains(t, words, "--all", "a copy without --all leaves out every platform but one: skopeo copy %s", c)
		assert.Contains(t, words, "--preserve-digests", "a copy that may change the digest: skopeo copy %s", c)
		require.GreaterOrEqual(t, len(words), 2)
		copied = append(copied, strings.Join(words[len(words)-2:], " "))
	}
	assert.Equal(t, want, copied)
}

// A tag whose digest at the mirror is upstream's is not copied again: a refresh pulls only what
// upstream moved and the tags the mirror lacks.
func TestMirrorCopy_ATagWhoseDigestMatchesIsNotCopied(t *testing.T) {
	digests := upstreamDigests()
	for _, tag := range mirrorTags {
		digests[tag[1]] = digests[tag[0]]
	}
	moved := mirrorTags[1] // golang alpine, moved upstream since the last copy
	digests[moved[1]] = mirrorDigest('f')
	absent := mirrorTags[6] // mailpit at a new pin
	delete(digests, absent[1])

	run := runMirror(t, "copy", mirrorVersions, mirrorRegistry{digests: digests}, mirrorCredentials...)
	require.True(t, run.ok, "copy failed:\n%s", run.out)
	var copiedTo []string
	for _, c := range run.copies() {
		words := strings.Fields(c)
		copiedTo = append(copiedTo, strings.TrimPrefix(words[len(words)-1], "docker://"))
	}
	assert.Equal(t, []string{moved[1], absent[1]}, copiedTo)
	for _, tag := range mirrorTags {
		assert.Equal(t, digests[tag[0]], run.digest(t, tag[1]), "%s after the copy", tag[1])
	}
}

// Docker Hub counts a manifest GET as a pull and a HEAD as none, so every request copy makes to it
// beside skopeo's copy asks for a digest only, with a HEAD, logged in.
func TestMirrorCopy_DockerHubIsAskedOnlyForDigests(t *testing.T) {
	digests := upstreamDigests()
	for _, tag := range mirrorTags {
		digests[tag[1]] = digests[tag[0]]
	}
	run := runMirror(t, "copy", mirrorVersions, mirrorRegistry{digests: digests}, mirrorCredentials...)
	require.True(t, run.ok, "copy failed:\n%s", run.out)
	manifests, tokens := 0, 0
	for _, c := range run.calls {
		words := strings.Fields(c)
		switch {
		case strings.Contains(c, "https://registry-1.docker.io/"):
			manifests++
			assert.Contains(t, words, "--head", "a request to Docker Hub that is not a HEAD may count as a pull: %s", c)
		case strings.Contains(c, "https://auth.docker.io/"):
			tokens++
			assert.Contains(t, words, "--netrc-file", "Docker Hub is asked anonymously: %s", c)
		}
	}
	assert.Equal(t, len(mirrorTags), manifests, "copy should ask Docker Hub once for each tag's digest")
	assert.Positive(t, tokens)
	assert.Empty(t, run.copies(), "nothing differed, yet copy pulled")
}

// The logins reach skopeo on its standard input and curl in a file, and the bearer token a registry
// answers reaches curl's manifest request on its standard input, never on a command line, which any
// process on the runner can read.
func TestMirrorCopy_TheTokensAreOnNoCommandLine(t *testing.T) {
	run := runMirror(t, "copy", mirrorVersions, mirrorRegistry{digests: upstreamDigests()}, mirrorCredentials...)
	require.True(t, run.ok, "copy failed:\n%s", run.out)
	logins := map[string]string{}
	manifests := 0
	for _, c := range run.calls {
		args, stdin, _ := strings.Cut(c, " stdin=")
		for _, secret := range []string{"dckr_pat_hub-secret", "ghs_job-secret", "stub-token"} {
			assert.NotContains(t, args, secret, "a token on a command line: %s", args)
		}
		if strings.HasPrefix(c, "skopeo login ") {
			words := strings.Fields(args)
			logins[words[len(words)-1]] = stdin
		}
		if strings.HasPrefix(c, "curl ") && strings.Contains(args, "/manifests/") {
			manifests++
			assert.Equal(t, "Authorization: Bearer stub-token;", stdin, "the manifest request should read its token on standard input: %s", c)
		}
	}
	assert.Equal(t, map[string]string{"docker.io": "dckr_pat_hub-secret", "ghcr.io": "ghs_job-secret"}, logins,
		"copy should log skopeo in to Docker Hub and GHCR, each token on standard input")
	assert.Positive(t, manifests, "copy asked no registry for a digest")
	for _, tag := range mirrorTags {
		assert.Equal(t, upstreamDigests()[tag[0]], run.digest(t, tag[1]), "%s after the copy: the registry took the token", tag[1])
	}
}

// Upstream can move while a copy runs. The copy lands digest A, which it compared, after upstream
// moved to B: asking both registries again after its copy, it finds upstream at B and the mirror at
// A, and copies B, so the mirror is left at upstream's digest.
func TestMirrorCopy_UpstreamMovingDuringACopyLeavesUpstreamsDigest(t *testing.T) {
	digests := upstreamDigests()
	for _, tag := range mirrorTags {
		digests[tag[1]] = digests[tag[0]]
	}
	nginx := mirrorTags[3]
	older, newer := mirrorDigest('1'), mirrorDigest('2')
	digests[nginx[0]] = older
	digests[nginx[1]] = mirrorDigest('0')
	run := runMirror(t, "copy", mirrorVersions, mirrorRegistry{
		digests: digests,
		moves:   map[string][2]string{"nginx": {nginx[0], newer}},
	}, mirrorCredentials...)
	require.True(t, run.ok, "copy failed:\n%s", run.out)
	assert.Equal(t, newer, run.digest(t, nginx[1]), "the mirror is left at the older digest the copy landed")
	assert.Equal(t, []string{
		"docker://docker.io/library/nginx@" + older + " docker://" + nginx[1],
		"docker://docker.io/library/nginx@" + newer + " docker://" + nginx[1],
	}, copiedRefs(run))
}

// The Mirror workflow's copies run one at a time, across branches (mirrorConcurrencyFindings), so
// each refresh asks both registries after the one before it has written. A refresh after one that
// copied upstream's digest copies nothing, and one after upstream moved copies the newer digest:
// the mirror ends at upstream's, and no digest is copied twice.
func TestMirrorCopy_RefreshesOneAfterAnotherCopyEachDigestOnce(t *testing.T) {
	nginx := mirrorTags[3]
	older, newer := mirrorDigest('1'), mirrorDigest('2')
	digests := upstreamDigests()
	for _, tag := range mirrorTags {
		digests[tag[1]] = digests[tag[0]]
	}
	digests[nginx[0]] = older
	delete(digests, nginx[1])
	stub := newMirrorStub(t, mirrorVersions, mirrorRegistry{digests: digests})
	upstream := filepath.Join(stub, "registry", "docker.io", "library", "nginx", "alpine")

	first := runMirrorOn(t, stub, "copy", mirrorCredentials...)
	require.True(t, first.ok, "the first refresh failed:\n%s", first.out)
	assert.Equal(t, []string{"docker://docker.io/library/nginx@" + older + " docker://" + nginx[1]}, copiedRefs(first))

	second := runMirrorOn(t, stub, "copy", mirrorCredentials...)
	require.True(t, second.ok, "the second refresh failed:\n%s", second.out)
	assert.Empty(t, second.copies(), "a refresh after the one that copied upstream's digest copied it again")

	require.NoError(t, os.WriteFile(upstream, []byte(newer+"\n"), 0o600))
	third := runMirrorOn(t, stub, "copy", mirrorCredentials...)
	require.True(t, third.ok, "the refresh after upstream moved failed:\n%s", third.out)
	assert.Equal(t, []string{"docker://docker.io/library/nginx@" + newer + " docker://" + nginx[1]}, copiedRefs(third))
	assert.Equal(t, newer, third.digest(t, nginx[1]))
}

// A mirror that is still not upstream's after three copies fails its tag rather than copying on.
func TestMirrorCopy_AMirrorThatNeverHoldsUpstreamsDigestFailsAfterThreeCopies(t *testing.T) {
	digests := upstreamDigests()
	for _, tag := range mirrorTags {
		digests[tag[1]] = digests[tag[0]]
	}
	nginx := mirrorTags[3]
	digests[nginx[1]] = mirrorDigest('0')
	run := runMirrorMoving(t, mirrorRegistry{digests: digests}, "nginx", nginx[0])
	assert.False(t, run.ok, "copy passed with the mirror never at upstream's digest:\n%s", run.out)
	errs := run.errors()
	require.Len(t, errs, 1, "%s", run.out)
	assert.Contains(t, errs[0], nginx[1]+" is ")
	assert.Contains(t, errs[0], "after 3 copies")
	assert.Len(t, copiedRefs(run), 3)
}

// runMirrorMoving runs copy over registry with upstream's digest of ref moving after every copy into
// pkg, as it would were upstream moving during each copy.
func runMirrorMoving(t *testing.T, registry mirrorRegistry, pkg, ref string) mirrorRun {
	t.Helper()
	registry.moves = map[string][2]string{pkg: {ref, mirrorDigest('2')}}
	return runMirror(t, "copy", mirrorVersions, registry, append([]string{"STUB_KEEP_MOVING=1"}, mirrorCredentials...)...)
}

// copiedRefs are the source and destination of each skopeo copy of run.
func copiedRefs(run mirrorRun) []string {
	var out []string
	for _, c := range run.copies() {
		words := strings.Fields(c)
		out = append(out, strings.Join(words[len(words)-2:], " "))
	}
	return out
}

// The Mirror workflow reads Docker Hub logged in (decision 11): without the token it asks nothing.
func TestMirrorCopy_WithoutDockerHubCredentialsItAsksNothing(t *testing.T) {
	env := slices.DeleteFunc(slices.Clone(mirrorCredentials), func(e string) bool { return strings.HasPrefix(e, "DOCKERHUB_TOKEN=") })
	run := runMirror(t, "copy", mirrorVersions, mirrorRegistry{digests: upstreamDigests()}, env...)
	assert.False(t, run.ok, "copy ran without Docker Hub's token:\n%s", run.out)
	assert.Empty(t, run.calls, "copy asked a registry without Docker Hub's token")
	assert.Contains(t, run.out, "DOCKERHUB_TOKEN")
}

// A copy that fails fails the run, naming the tag, after the other tags are copied.
func TestMirrorCopy_AFailedCopyFailsTheRunAfterTheOthers(t *testing.T) {
	stubbed := mirrorRegistry{digests: upstreamDigests(), refuseCopy: []string{"node"}}
	run := runMirror(t, "copy", mirrorVersions, stubbed, mirrorCredentials...)
	assert.False(t, run.ok, "copy passed with node's copy refused:\n%s", run.out)
	errs := run.errors()
	require.Len(t, errs, 1, "%s", run.out)
	assert.Contains(t, errs[0], mirrorTags[2][1])
	assert.Len(t, run.copies(), len(mirrorTags), "copy stopped at the failed one")
	assert.Equal(t, stubbed.digests[mirrorTags[7][0]], run.digest(t, mirrorTags[7][1]))
}

// ---- missing ---------------------------------------------------------------------------------

func TestMirrorMissing_AllEightPresentPasses(t *testing.T) {
	digests := map[string]string{}
	for _, tag := range mirrorTags {
		digests[tag[1]] = mirrorDigest('a')
	}
	run := runMirror(t, "missing", mirrorVersions, mirrorRegistry{digests: digests}, mirrorCredentials...)
	assert.True(t, run.ok, "missing failed with every tag present:\n%s", run.out)
	assert.Empty(t, run.errors())
	assertAnonymousMirrorRequests(t, run)
}

// Each tag the mirror lacks, or holds in a package that is not public, is named, with what to do.
func TestMirrorMissing_EachMissingTagIsNamedWithWhatToDo(t *testing.T) {
	digests := map[string]string{}
	for _, tag := range mirrorTags {
		digests[tag[1]] = mirrorDigest('a')
	}
	delete(digests, mirrorTags[0][1]) // a Go bump not yet copied
	delete(digests, mirrorTags[6][1]) // a Mailpit bump not yet copied
	run := runMirror(t, "missing", mirrorVersions,
		mirrorRegistry{digests: digests, private: []string{"leodip/goiabada-ci/postgres"}}, mirrorCredentials...)
	assert.False(t, run.ok, "missing passed with three tags missing:\n%s", run.out)
	errs := run.errors()
	require.Len(t, errs, 3, "%s", run.out)
	for i, ref := range []string{mirrorTags[0][1], mirrorTags[5][1], mirrorTags[6][1]} {
		assert.Contains(t, errs[i], ref+" ")
		assert.Contains(t, errs[i], "Mirror workflow", "the message should say what copies the tag")
		assert.Contains(t, errs[i], "re-run", "the message should say a re-run passes once it is copied")
	}
	assertAnonymousMirrorRequests(t, run)
}

// A request that stalls fails its tag once curl gives up on it, in seconds, and the tags after it
// are still asked, so the Versions job names every tag the mirror lacks rather than waiting on one.
func TestMirrorMissing_AStalledRequestFailsItsTagAndTheOthersAreStillAsked(t *testing.T) {
	digests := map[string]string{}
	for _, tag := range mirrorTags {
		digests[tag[1]] = mirrorDigest('a')
	}
	delete(digests, mirrorTags[3][1]) // nginx, answered 404
	delete(digests, mirrorTags[6][1]) // mailpit, asked after the stalled mysql
	run := runMirror(t, "missing", mirrorVersions,
		mirrorRegistry{digests: digests, stall: []string{"leodip/goiabada-ci/mysql"}}, "MIRROR_REQUEST_SECONDS=1")
	assert.False(t, run.ok, "missing passed with a request stalled:\n%s", run.out)
	assert.Less(t, run.elapsed, 30*time.Second, "missing waited on the stalled request:\n%s", run.out)
	errs := run.errors()
	require.Len(t, errs, 3, "%s", run.out)
	assert.Contains(t, errs[0], mirrorTags[3][1]+" is not in the mirror")
	assert.Contains(t, errs[1], "cannot ask ghcr.io for "+mirrorTags[4][1])
	assert.Contains(t, errs[1], "re-run")
	assert.Contains(t, errs[2], mirrorTags[6][1]+" is not in the mirror")
	for _, c := range run.calls {
		assert.Regexp(t, ` --connect-timeout \d+ --max-time 1 `, c, "a request with no deadline: %s", c)
	}
}

// assertAnonymousMirrorRequests holds every request of run to the mirror and to no other registry,
// with no login, asking for each tag of the list: a token for each, and its digest when the token
// is given.
func assertAnonymousMirrorRequests(t *testing.T, run mirrorRun) {
	t.Helper()
	tokens := 0
	for _, c := range run.calls {
		require.True(t, strings.HasPrefix(c, "curl "), "missing ran %s", c)
		assert.NotContains(t, c, "--netrc-file", "the mirror is asked with a login: %s", c)
		assert.NotContains(t, c, "docker.io", "missing asked Docker Hub: %s", c)
		if strings.Contains(c, "https://ghcr.io/token?") {
			tokens++
		}
	}
	assert.Equal(t, len(mirrorTags), tokens)
}

// ---- public ----------------------------------------------------------------------------------

// publicRegistry holds every tag of the list at the mirror, each package public.
func publicRegistry() mirrorRegistry {
	digests := map[string]string{}
	for _, tag := range mirrorTags {
		digests[tag[1]] = mirrorDigest('a')
	}
	return mirrorRegistry{digests: digests}
}

func TestMirrorPublic_EveryTagReadAnonymouslyPasses(t *testing.T) {
	run := runMirror(t, "public", mirrorVersions, publicRegistry())
	assert.True(t, run.ok, "public failed with every package public:\n%s", run.out)
	assert.Empty(t, run.errors())
	assertAnonymousReads(t, run, nil)
}

// A tag that is one platform's image rather than an index is read through its own manifest.
func TestMirrorPublic_ASinglePlatformImageIsReadThroughItsManifest(t *testing.T) {
	registry := publicRegistry()
	registry.single = []string{"leodip/goiabada-ci/mailpit"}
	run := runMirror(t, "public", mirrorVersions, registry)
	assert.True(t, run.ok, "public failed with every package public:\n%s", run.out)
	assertAnonymousReads(t, run, nil)
}

// A package that is not public is named once, however many of its tags were refused, with where to
// make it public.
func TestMirrorPublic_APackageNotPublicIsNamedOnceWithHowToMakeItPublic(t *testing.T) {
	registry := publicRegistry()
	registry.private = []string{"leodip/goiabada-ci/golang", "leodip/goiabada-ci/buildkit"}
	run := runMirror(t, "public", mirrorVersions, registry)
	assert.False(t, run.ok, "public passed with two packages private:\n%s", run.out)
	errs := run.errors()
	require.Len(t, errs, 2, "%s", run.out)
	assert.Contains(t, errs[0], "ghcr.io/leodip/goiabada-ci/golang refused an anonymous read (tags: 1.28.0-bookworm 1.28.0-alpine)")
	assert.Contains(t, errs[0], "https://github.com/users/leodip/packages/container/goiabada-ci%2Fgolang/settings")
	assert.Contains(t, errs[1], "ghcr.io/leodip/goiabada-ci/buildkit refused an anonymous read")
	assert.Contains(t, errs[1], "https://github.com/users/leodip/packages/container/goiabada-ci%2Fbuildkit/settings")
	assertAnonymousReads(t, run, []string{"leodip/goiabada-ci/golang", "leodip/goiabada-ci/buildkit"})
}

// A request is taken for a package that is not public only when the registry refused it for want of
// access, at the token, the manifest or a layer, which a pull reads with the same anonymous token:
// any other answer says nothing of the package, and is reported with what the registry answered and
// no settings to change.
func TestMirrorPublic_OnlyARefusalIsTakenForAPackageNotPublic(t *testing.T) {
	for _, c := range []struct {
		request, status string
		refused         bool
	}{
		{"token", "403", true},
		{"token", "401", true},
		{"manifest", "403", true},
		{"manifest", "401", true},
		{"blob", "403", true},
		{"blob", "401", true},
		{"token", "503", false},
		{"manifest", "404", false},
		{"manifest", "503", false},
		{"blob", "404", false},
		{"blob", "500", false},
	} {
		t.Run(c.request+" "+c.status, func(t *testing.T) {
			registry := publicRegistry()
			registry.statuses = map[string]map[string]string{"leodip/goiabada-ci/nginx": {c.request: c.status}}
			run := runMirror(t, "public", mirrorVersions, registry)
			assert.False(t, run.ok, "public passed with a request answered %s:\n%s", c.status, run.out)
			errs := run.errors()
			require.Len(t, errs, 1, "%s", run.out)
			if c.refused {
				assert.Contains(t, errs[0], "ghcr.io/leodip/goiabada-ci/nginx refused an anonymous read (tags: alpine)")
				assert.Contains(t, errs[0], "https://github.com/users/leodip/packages/container/goiabada-ci%2Fnginx/settings")
			} else {
				assert.Contains(t, errs[0], "the anonymous read of ghcr.io/leodip/goiabada-ci/nginx:alpine failed, and not for want of access")
				assert.Contains(t, errs[0], c.status, "the message should keep what the registry answered")
				assert.NotContains(t, errs[0], "settings", "a registry error sent the maintainer to the package's visibility")
			}
		})
	}
}

// A request that stalls fails its tag in seconds, and the other tags are still read.
func TestMirrorPublic_AStalledRequestFailsItsTagAndTheOthersAreStillRead(t *testing.T) {
	registry := publicRegistry()
	registry.stall = []string{"leodip/goiabada-ci/node"}
	run := runMirror(t, "public", mirrorVersions, registry, "MIRROR_REQUEST_SECONDS=1")
	assert.False(t, run.ok, "public passed with a request stalled:\n%s", run.out)
	errs := run.errors()
	require.Len(t, errs, 1, "%s", run.out)
	assert.Contains(t, errs[0], "the anonymous read of ghcr.io/leodip/goiabada-ci/node:27.0.1-alpine failed, and not for want of access")
	assert.Less(t, run.elapsed, 30*time.Second)
	assert.Contains(t, run.out, "read ghcr.io/leodip/goiabada-ci/buildkit:buildx-stable-1 anonymously")
}

// assertAnonymousReads holds run to reading every tag of the list anonymously, as a pull on the
// runner does but without downloading a layer: no login, each tag's token, its manifest, and for a
// package outside refused a HEAD of the linux/amd64 image's config and each of its layers, and no
// other platform's.
func assertAnonymousReads(t *testing.T, run mirrorRun, refused []string) {
	t.Helper()
	blobs := map[string][]string{}
	tokens := map[string]bool{}
	for _, c := range run.calls {
		require.True(t, strings.HasPrefix(c, "curl "), "public ran %s", c)
		assert.NotContains(t, c, "--netrc", "a request that may be logged in: %s", c)
		url := strings.Fields(strings.Split(c, " stdin=")[0])
		target := url[len(url)-1]
		switch {
		case strings.HasPrefix(target, "https://ghcr.io/token?"):
			repo := strings.TrimSuffix(strings.SplitN(target, "scope=repository:", 2)[1], ":pull")
			tokens[repo] = true
		case strings.Contains(target, "/blobs/"):
			assert.Contains(t, c, " --head ", "a blob read whole: %s", c)
			repo := strings.SplitN(strings.TrimPrefix(target, "https://ghcr.io/v2/"), "/blobs/", 2)
			blobs[repo[0]] = append(blobs[repo[0]], repo[1])
		case strings.Contains(target, "/manifests/"):
		default:
			t.Errorf("public asked %s", target)
		}
	}
	amd64 := []string{mirrorDigest('c'), mirrorDigest('1'), mirrorDigest('2')}
	for _, tag := range mirrorTags {
		repo := strings.TrimPrefix(tag[1][:strings.LastIndex(tag[1], ":")], "ghcr.io/")
		assert.True(t, tokens[repo], "public asked no token for %s", repo)
		if slices.Contains(refused, repo) {
			assert.Empty(t, blobs[repo], "public read the blobs of %s, which refused its token", repo)
			continue
		}
		read := slices.Compact(slices.Sorted(slices.Values(blobs[repo])))
		assert.Equal(t, slices.Sorted(slices.Values(amd64)), read, "the blobs of %s read", repo)
	}
}

// ---- the workflow ----------------------------------------------------------------------------

// The Mirror workflow runs on a push to any branch that changes what it mirrors, weekly and by
// hand, and never on a pull request: its copying job holds packages: write and Docker Hub's token,
// the one job that does, and the anonymous read that proves the packages public runs after it.
func TestMirrorWorkflow_TriggersAndPermissions(t *testing.T) {
	lines := workflowLines(repositoryFiles(t, []string{mirrorWorkflow})[mirrorWorkflow])
	text := strings.Join(lines, "\n")
	for _, trigger := range []string{"pull_request", "pull_request_target", "workflow_run"} {
		assert.NotRegexp(t, `(?m)^  `+trigger+`:`, text, "%s runs on %s", mirrorWorkflow, trigger)
	}
	assert.Regexp(t, `(?m)^  push:\n    branches: \["\*\*"\]\n    paths:\n`, text,
		"%s should run on a push to any branch, filtered by paths", mirrorWorkflow)
	paths := regexp.MustCompile(`(?m)^      - (\S+)$`).FindAllStringSubmatch(text, -1)
	var filtered []string
	for _, p := range paths {
		filtered = append(filtered, p[1])
	}
	for _, p := range []string{mirrorList, mirrorScript, mirrorWorkflow, "src/authserver/versions.yaml"} {
		assert.Contains(t, filtered, p, "%s should run on a push that changes %s", mirrorWorkflow, p)
	}
	assert.Regexp(t, `(?m)^  schedule:\n    - cron: "[^"]+"$`, text, "%s should run weekly", mirrorWorkflow)
	assert.Regexp(t, `(?m)^  workflow_dispatch:\s*$`, text, "%s should run by hand", mirrorWorkflow)

	jobs := workflowJobs(lines)
	holders := map[string][]string{}
	for i, line := range lines {
		if strings.TrimSpace(line) != "packages: write" {
			continue
		}
		job := ""
		for name, numbers := range jobs {
			if slices.Contains(numbers, i+1) {
				job = name
			}
		}
		holders[job] = append(holders[job], strconv.Itoa(i+1))
	}
	require.Len(t, holders, 1, "%s: packages: write should be held by one job, the copying one: %v", mirrorWorkflow, holders)
	for job := range holders {
		require.NotEmpty(t, job, "%s grants packages: write to the whole workflow", mirrorWorkflow)
		body := mirrorJobText(lines, jobs[job])
		assert.Contains(t, body, mirrorScript+" copy", "%s: the job holding packages: write should be the copying one", mirrorWorkflow)
		assert.Contains(t, body, "secrets.DOCKERHUB_TOKEN")
	}
	public := ""
	for name, numbers := range jobs {
		if body := mirrorJobText(lines, numbers); strings.Contains(body, mirrorScript+" public") {
			public = name
		}
	}
	require.NotEmpty(t, public, "%s should end by reading every image anonymously, %s public", mirrorWorkflow, mirrorScript)
	body := mirrorJobText(lines, jobs[public])
	assert.NotContains(t, body, "secrets.", "%s: the anonymous read should hold no secret", mirrorWorkflow)
	assert.Regexp(t, `(?m)^    needs: \[?`+regexp.QuoteMeta(firstKey(holders))+`\]?$`, body,
		"%s: the anonymous read should run after the copy", mirrorWorkflow)
}

// mirrorConcurrencyFindings holds the Mirror workflow's copying job, the one that runs mirror.sh
// copy, to one concurrency group shared by every branch and run, a name with no expression in it,
// that queues every pending run (queue: max) and cancels none in progress. Two copies that overlap
// each compare a tag's digests before the other writes, so the one that read upstream first can
// land the older digest last, and both can pull the same digest. A group per branch lets runs of
// two branches overlap so, and a shared group that queues one pending run cancels another branch's
// waiting refresh, which holds its new tags. Any other concurrency block of the workflow queues
// every pending run too, so none cancels a branch's refresh.
func mirrorConcurrencyFindings(file, text string) []string {
	lines := workflowLines(text)
	var findings []string
	add := func(n int, format string, args ...any) {
		findings = append(findings, fmt.Sprintf("%s:%d ", file, n)+fmt.Sprintf(format, args...))
	}
	// blocks maps the line, from 1, of each concurrency: key to the keys and values beneath it.
	type block struct {
		line   int
		indent int
		keys   map[string]string
	}
	var blocks []block
	for i, line := range lines {
		trimmed := strings.TrimLeft(line, " ")
		if strings.TrimSpace(trimmed) != "concurrency:" {
			continue
		}
		b := block{line: i + 1, indent: len(line) - len(trimmed), keys: map[string]string{}}
		for _, next := range lines[i+1:] {
			nt := strings.TrimLeft(next, " ")
			if strings.TrimSpace(nt) == "" || strings.HasPrefix(nt, "#") {
				continue
			}
			if len(next)-len(nt) <= b.indent {
				break
			}
			if k, v, ok := strings.Cut(nt, ":"); ok {
				v, _, _ = strings.Cut(v, " #")
				b.keys[strings.TrimSpace(k)] = yamlLineScalar(strings.TrimSpace(v))
			}
		}
		blocks = append(blocks, b)
	}
	copyJob := ""
	jobs := workflowJobs(lines)
	for name, numbers := range jobs {
		if strings.Contains(mirrorJobText(lines, numbers), mirrorScript+" copy") {
			copyJob = name
		}
	}
	if copyJob == "" {
		return append(findings, file+" has no job that runs "+mirrorScript+" copy")
	}
	copyGroup := false
	for _, b := range blocks {
		if b.keys["queue"] != "max" {
			add(b.line, "a concurrency group without queue: max keeps one pending run and cancels the others, a branch's refresh among them: add queue: max")
		}
		if b.keys["cancel-in-progress"] != "" && b.keys["cancel-in-progress"] != "false" {
			add(b.line, "a concurrency group that cancels a copy in progress can leave a tag half refreshed: remove cancel-in-progress")
		}
		if !slices.Contains(jobs[copyJob], b.line) {
			continue
		}
		copyGroup = true
		if group := b.keys["group"]; group == "" || strings.Contains(group, "${{") {
			add(b.line, "the %s job's concurrency group should be one name shared by every branch and run, not %q: copies that overlap can land an older digest last", copyJob, group)
		}
	}
	if !copyGroup {
		add(jobs[copyJob][0], "the %s job should run in one concurrency group shared by every branch, with queue: max, so copies run one at a time and each compares against the last one's result", copyJob)
	}
	return findings
}

func TestMirrorWorkflow_CopiesRunOneAtATimeAcrossBranches(t *testing.T) {
	text := repositoryFiles(t, []string{mirrorWorkflow})[mirrorWorkflow]
	assert.Empty(t, mirrorConcurrencyFindings(mirrorWorkflow, text))
}

func TestMirrorWorkflow_ConcurrencyFindings(t *testing.T) {
	workflow := func(top, job string) string {
		return "name: Mirror\n" + top + "jobs:\n  copy:\n    name: Copy\n    runs-on: ubuntu-24.04\n" + job +
			"    steps:\n      - run: " + mirrorScript + " copy\n  public:\n    needs: copy\n    steps:\n      - run: " + mirrorScript + " public\n"
	}
	shared := "    concurrency:\n      group: mirror-copy\n      queue: max\n"
	for _, c := range []struct {
		name, top, job, want string
	}{
		{"one queued group", "", shared, ""},
		{"one queued group, not cancelled", "", shared + "      cancel-in-progress: false\n", ""},
		{"a group per branch", "", "    concurrency:\n      group: mirror-${{ github.ref }}\n      queue: max\n", "not \"mirror-${{ github.ref }}\""},
		{"one pending run", "", "    concurrency:\n      group: mirror-copy\n", "without queue: max"},
		{"cancelled in progress", "", "    concurrency:\n      group: mirror-copy\n      queue: max\n      cancel-in-progress: true\n", "remove cancel-in-progress"},
		{"no group", "", "", "should run in one concurrency group"},
		{"the workflow's group per branch", "concurrency:\n  group: mirror-${{ github.ref }}\n", shared, "mirror.yml:2 a concurrency group without queue: max"},
		{"the workflow's group alone", "concurrency:\n  group: mirror\n  queue: max\n", "", "should run in one concurrency group"},
	} {
		t.Run(c.name, func(t *testing.T) {
			findings := mirrorConcurrencyFindings("mirror.yml", workflow(c.top, c.job))
			if c.want == "" {
				assert.Empty(t, findings)
				return
			}
			require.Len(t, findings, 1, "%v", findings)
			assert.Contains(t, findings[0], c.want)
		})
	}
	assert.Equal(t, []string{"mirror.yml has no job that runs " + mirrorScript + " copy"},
		mirrorConcurrencyFindings("mirror.yml", "name: Mirror\njobs:\n  public:\n    steps:\n      - run: true\n"))
}

// mirrorJobText is the text of a job's lines, by their numbers from 1.
func mirrorJobText(lines []string, numbers []int) string {
	var b strings.Builder
	for _, n := range numbers {
		b.WriteString(lines[n-1])
		b.WriteString("\n")
	}
	return b.String()
}

// firstKey is the one key of a map holding one.
func firstKey(m map[string][]string) string {
	for k := range m {
		return k
	}
	return ""
}
