package guard

// CI's images come from a mirror, public packages under ghcr.io/leodip/goiabada-ci/, so a Check run
// draws nothing from Docker Hub's pull allowance (#867). .github/mirror/images is the list of the
// tags the mirror holds, eight tags in seven packages, their versions read from versions.yaml, and
// .github/mirror/mirror.sh is what reads it: list prints each tag with its mirror address, copy
// (the Mirror workflow's) copies from Docker Hub, logged in, every tag whose digest at the mirror
// is not upstream's, missing asks the mirror anonymously for every tag and names each one it lacks,
// and public pulls every tag anonymously and names each package that is not public.
//
// The script runs here with curl, skopeo and docker replaced by stubs that answer as the registries
// do, from a registry the test writes, so no test reaches a network. Docker Hub counts a manifest
// GET as a pull and a HEAD as none, so the stubs log every request and the tests hold Docker Hub to
// HEADs; skopeo copy, the one pull, is held to every platform and upstream's digest.

import (
	"context"
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
// a request for it without credentials is refused. A manifest request without the token the token
// request answered is refused, and one for a repository named under <stub>/stall answers nothing
// until curl's --max-time, an hour without one. skopeo refuses a copy into a package named under
// <stub>/copy-fails, and a copy into a package named under <stub>/moves lands, then moves upstream
// to what that file holds, "<upstream address> <digest>", as another run's copy of a newer digest
// would have just before it; with STUB_KEEP_MOVING set it moves so after every copy. docker answers a pull of a repository named under <stub>/pull-fails
// with a registry error. Each logs its arguments, one line per call, curl the headers it read on
// its standard input after " stdin=".
const (
	stubMirrorCurl = `#!/bin/bash
url=${!#}
netrc=0 maxtime="" headers="" stdin="" prev=""
for a in "$@"; do
    case "$prev" in
        --max-time) maxtime=$a ;;
        --header) if [ "$a" = @- ]; then stdin=$(cat); headers+="$stdin"$'\n'; else headers+="$a"$'\n'; fi ;;
    esac
    [ "$a" = --netrc-file ] && netrc=1
    prev=$a
done
{ printf 'curl'; printf ' %s' "$@"; [ -z "$stdin" ] || printf ' stdin=%s' "$(tr '\n' ';' <<< "$stdin")"; echo; } >> "$STUB/log"
case "$url" in
    https://auth.docker.io/token\?*|https://ghcr.io/token\?*)
        repo=${url#*scope=repository:}; repo=${repo%:pull*}
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
        f="$STUB/registry/$host/${path%/manifests/*}/${path##*/manifests/}"
        if ! grep -qx 'Authorization: Bearer stub-token' <<< "$headers"; then
            printf 'HTTP/2 401 \r\ncontent-type: application/json\r\n\r\n'
        elif [ -f "$f" ]; then
            printf 'HTTP/2 200 \r\ncontent-type: application/vnd.oci.image.index.v1+json\r\ndocker-content-digest: %s\r\n\r\n' "$(cat "$f")"
        else
            printf 'HTTP/2 404 \r\ncontent-type: application/json\r\n\r\n'
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
	stubMirrorDocker = `#!/bin/bash
{ printf 'docker'; printf ' %s' "$@"; printf ' DOCKER_CONFIG=%s holding=[%s]\n' "${DOCKER_CONFIG:-}" "$(ls -A "${DOCKER_CONFIG:-$HOME/.docker}" 2>/dev/null | tr '\n' ' ')"; } >> "$STUB/log"
[ "$1 $2" = "pull --quiet" ] && [ $# = 3 ] || { echo "stub docker: unexpected $*" >&2; exit 64; }
ref=$3; repo=${ref#*/}; repo=${repo%:*}
if [ -n "${DOCKER_CONFIG:-}" ] && [ -z "$(ls -A "$DOCKER_CONFIG" 2>/dev/null)" ] && [ -e "$STUB/private/$repo" ]; then
    echo "Error response from daemon: Head \"https://ghcr.io/v2/$repo/manifests/${ref##*:}\": denied" >&2
    exit 1
fi
if [ -e "$STUB/pull-fails/$repo" ]; then
    echo "Error response from daemon: received unexpected HTTP status: 503 Service Unavailable" >&2
    exit 1
fi
[ -f "$STUB/registry/${ref%:*}/${ref##*:}" ] || { echo "Error response from daemon: manifest unknown" >&2; exit 1; }
echo "$ref"
`
)

// mirrorRegistry is what the stubbed registries hold: each tag's digest, by its address, the
// repositories whose package is not public, the mirror packages a copy into is refused, the
// repositories whose manifest requests stall, the mirror packages whose copy upstream moves past,
// to an upstream address and its new digest, and the repositories an anonymous pull of fails with a
// registry error.
type mirrorRegistry struct {
	digests    map[string]string
	private    []string
	refuseCopy []string
	stall      []string
	moves      map[string][2]string
	pullFails  []string
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
// env added to the environment. HOME holds a Docker configuration logged in to ghcr.io, as a runner
// may, so a request made anonymously is one the script made so on purpose.
func runMirror(t *testing.T, command, versions string, registry mirrorRegistry, env ...string) mirrorRun {
	t.Helper()
	stub := t.TempDir()
	bin := filepath.Join(stub, "bin")
	require.NoError(t, os.MkdirAll(bin, 0o755))
	for name, body := range map[string]string{"curl": stubMirrorCurl, "skopeo": stubMirrorSkopeo, "docker": stubMirrorDocker} {
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
	for _, repo := range registry.pullFails {
		require.NoError(t, os.MkdirAll(filepath.Join(stub, "pull-fails", repo), 0o755))
	}
	for pkg, move := range registry.moves {
		require.NoError(t, os.MkdirAll(filepath.Join(stub, "moves"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(stub, "moves", pkg), []byte(move[0]+" "+move[1]+"\n"), 0o600))
	}
	require.NoError(t, os.MkdirAll(filepath.Join(stub, ".docker"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(stub, ".docker", "config.json"),
		[]byte(`{"auths":{"ghcr.io":{"auth":"c3R1YjpzdHVi"}}}`), 0o600))
	versionsFile := filepath.Join(stub, "versions.yaml")
	require.NoError(t, os.WriteFile(versionsFile, []byte(versions), 0o600))

	// A run that waits on a stalled request ends here rather than at the test binary's timeout.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", filepath.Join(filepath.Dir(SourceRoot(t)), mirrorScript), command)
	cmd.WaitDelay = time.Second
	cmd.Env = append([]string{
		"PATH=" + bin + ":" + os.Getenv("PATH"), "STUB=" + stub, "HOME=" + stub, "TMPDIR=" + t.TempDir(),
		"MIRROR_VERSIONS=" + versionsFile,
	}, env...)
	start := time.Now()
	out, err := cmd.CombinedOutput()
	run := mirrorRun{ok: err == nil, out: string(out), stub: stub, elapsed: time.Since(start)}
	if log, err := os.ReadFile(filepath.Join(stub, "log")); err == nil {
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

// Two refreshes of two branches can copy one tag at once. The one that read upstream first, at
// digest A, lands A after the other has copied upstream's newer B and checked it: asking both
// registries again after its copy, it finds upstream at B and the mirror at A, and copies B, so the
// mirror is left at upstream's digest whichever finishes last.
func TestMirrorCopy_ACopyOverlappingANewerOneLeavesUpstreamsDigest(t *testing.T) {
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
	assert.Equal(t, newer, run.digest(t, nginx[1]), "the mirror is left at the older digest the overlapping copy landed")
	assert.Equal(t, []string{
		"docker://docker.io/library/nginx@" + older + " docker://" + nginx[1],
		"docker://docker.io/library/nginx@" + newer + " docker://" + nginx[1],
	}, copiedRefs(run))
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
// pkg, as it would were another run's copy landing behind each of this run's.
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

func TestMirrorPublic_EveryTagPulledAnonymouslyPasses(t *testing.T) {
	digests := map[string]string{}
	for _, tag := range mirrorTags {
		digests[tag[1]] = mirrorDigest('a')
	}
	run := runMirror(t, "public", mirrorVersions, mirrorRegistry{digests: digests})
	assert.True(t, run.ok, "public failed with every package public:\n%s", run.out)
	assert.Empty(t, run.errors())
	assertAnonymousPulls(t, run)
}

// A package that is not public is named once, however many of its tags were refused, with where to
// make it public.
func TestMirrorPublic_APackageNotPublicIsNamedOnceWithHowToMakeItPublic(t *testing.T) {
	digests := map[string]string{}
	for _, tag := range mirrorTags {
		digests[tag[1]] = mirrorDigest('a')
	}
	run := runMirror(t, "public", mirrorVersions, mirrorRegistry{
		digests: digests, private: []string{"leodip/goiabada-ci/golang", "leodip/goiabada-ci/buildkit"},
	})
	assert.False(t, run.ok, "public passed with two packages private:\n%s", run.out)
	errs := run.errors()
	require.Len(t, errs, 2, "%s", run.out)
	assert.Contains(t, errs[0], "ghcr.io/leodip/goiabada-ci/golang ")
	assert.Contains(t, errs[0], "https://github.com/users/leodip/packages/container/goiabada-ci%2Fgolang/settings")
	assert.Contains(t, errs[1], "ghcr.io/leodip/goiabada-ci/buildkit ")
	assert.Contains(t, errs[1], "https://github.com/users/leodip/packages/container/goiabada-ci%2Fbuildkit/settings")
	for _, e := range errs {
		assert.Contains(t, e, "public", "%s", e)
	}
	assertAnonymousPulls(t, run)
}

// A pull that fails for another reason than access, here a registry error, says nothing of the
// package's visibility: it is reported with Docker's error, not as a package to make public.
func TestMirrorPublic_ARegistryErrorIsNotTakenForAPackageNotPublic(t *testing.T) {
	digests := map[string]string{}
	for _, tag := range mirrorTags {
		digests[tag[1]] = mirrorDigest('a')
	}
	run := runMirror(t, "public", mirrorVersions, mirrorRegistry{
		digests: digests, private: []string{"leodip/goiabada-ci/golang"}, pullFails: []string{"leodip/goiabada-ci/nginx"},
	})
	assert.False(t, run.ok, "public passed with a pull failed:\n%s", run.out)
	errs := run.errors()
	require.Len(t, errs, 2, "%s", run.out)
	assert.Contains(t, errs[0], "the anonymous pull of ghcr.io/leodip/goiabada-ci/nginx:alpine failed")
	assert.Contains(t, errs[0], "503 Service Unavailable", "the message should keep Docker's error")
	assert.NotContains(t, errs[0], "settings", "a registry error sent the maintainer to the package's visibility")
	assert.Contains(t, errs[1], "ghcr.io/leodip/goiabada-ci/golang ")
	assert.Contains(t, errs[1], "https://github.com/users/leodip/packages/container/goiabada-ci%2Fgolang/settings")
	assertAnonymousPulls(t, run)
}

// assertAnonymousPulls holds run to pulling every tag of the list once, each with a Docker
// configuration that holds no login.
func assertAnonymousPulls(t *testing.T, run mirrorRun) {
	t.Helper()
	var pulled []string
	for _, c := range run.calls {
		require.True(t, strings.HasPrefix(c, "docker pull --quiet "), "public ran %s", c)
		fields := strings.Fields(c)
		pulled = append(pulled, fields[3])
		assert.Regexp(t, `DOCKER_CONFIG=\S+ holding=\[\]$`, c, "a pull that may be logged in: %s", c)
	}
	var want []string
	for _, tag := range mirrorTags {
		want = append(want, tag[1])
	}
	assert.Equal(t, want, pulled)
}

// ---- the workflow ----------------------------------------------------------------------------

// The Mirror workflow runs on a push to any branch that changes what it mirrors, weekly and by
// hand, and never on a pull request: its copying job holds packages: write and Docker Hub's token,
// the one job that does, and the pull that proves the packages public runs after it.
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
	require.NotEmpty(t, public, "%s should end by pulling every image anonymously, %s public", mirrorWorkflow, mirrorScript)
	body := mirrorJobText(lines, jobs[public])
	assert.NotContains(t, body, "secrets.", "%s: the anonymous pull should hold no secret", mirrorWorkflow)
	assert.Regexp(t, `(?m)^    needs: \[?`+regexp.QuoteMeta(firstKey(holders))+`\]?$`, body,
		"%s: the anonymous pull should run after the copy", mirrorWorkflow)
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
