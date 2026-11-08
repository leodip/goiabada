package guard

// Build validation's gate on the release images' binaries (#808). The images hold no operating
// system package left for an image scanner, so what a release ships is each server's binary, on
// two platforms, and build validation scans exactly those: it builds both images for linux/amd64
// and linux/arm64, the platforms a release pushes, and src/build/scan-image-binaries.sh copies
// each binary out, checks it is the cross-compile the Dockerfiles ask for (the platform's
// architecture, statically linked, CGO_ENABLED=0 and the production tag in its build settings)
// and scans it with govulncheck -mode=binary in its default text output, the one output whose
// exit code reports a finding.
//
// The first half of this file reads check.yml and the script as the shell runs them, and holds
// the workflow to building each release image on both platforms and scanning every one of those
// builds under its platform, and the script to that govulncheck invocation. The second half runs
// the script itself with the tools it drives, docker, file, go and govulncheck, replaced by stubs
// answering as each tool does, their outputs recorded from images built from this tree, and holds
// it to failing on every check, on a binary it cannot copy out and on a scan that finds or errors.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildValidationWorkflow is the workflow whose build validation builds and scans the release
// images, relative to the repository root.
const buildValidationWorkflow = ".github/workflows/check.yml"

// binaryScanScript is the script build validation scans the binaries with, relative to the
// source root, and binaryScanCommand its name as a command.
const (
	binaryScanScript  = "build/scan-image-binaries.sh"
	binaryScanCommand = "scan-image-binaries.sh"
)

// releasePlatforms are the platforms a release pushes each image for, build-docker-images.sh's
// PLATFORMS.
var releasePlatforms = []string{"linux/amd64", "linux/arm64"}

// imageBuild is one build of a release image in a workflow: its Dockerfile, the platforms it
// builds for, the tags it gives the image and the file line it is on.
type imageBuild struct {
	dockerfile string
	platforms  []string
	tags       []string
	at         string
}

// binaryScanFindings reads a workflow's run scripts and returns every way its build validation
// leaves a release binary unscanned: a release image it builds for neither or only one of
// releasePlatforms, a build of one whose tag no scan-image-binaries.sh run scans under that
// platform, a build or a scan this check cannot read, and a workflow that runs no scan at all.
func binaryScanFindings(file string, scripts []shellSource) []string {
	var findings []string
	var builds []imageBuild
	scanned := map[string][]string{} // platform -> images
	scans := 0
	for _, src := range scripts {
		script := readShell(src.text)
		for _, p := range script.problems {
			findings = append(findings, fmt.Sprintf("binary scan: %s:%d %s, which this reader cannot read as the shell would", file, src.offset+p.line, p.what))
		}
		for _, c := range script.commands {
			at := fmt.Sprintf("binary scan: %s:%d", file, src.offset+c.line)
			if len(c.words) > 0 && path.Base(c.words[0].value) == binaryScanCommand {
				scans++
				platform := ""
				for i := 1; i < len(c.words); i++ {
					w := c.words[i]
					switch {
					case w.expands:
						findings = append(findings, fmt.Sprintf("%s passes %s through an expansion, so this check cannot tell what it scans", at, w.raw))
					case w.value == "--platform" && i+1 < len(c.words):
						platform = c.words[i+1].value
						if c.words[i+1].expands {
							findings = append(findings, fmt.Sprintf("%s passes --platform %s through an expansion, so this check cannot tell what it scans", at, c.words[i+1].raw))
						}
						i++
					case platform != "":
						scanned[platform] = append(scanned[platform], w.value)
					}
				}
				continue
			}
			args, ok := isDockerBuild(c)
			if !ok {
				continue
			}
			dockerfiles, dynamic := flagValues(args, "-f")
			long, longDynamic := flagValues(args, "--file")
			if dynamic || longDynamic {
				findings = append(findings, at+" names the Dockerfile it builds through an expansion, so this check cannot tell whether it builds a release image")
				continue
			}
			b := imageBuild{at: at}
			for _, f := range append(dockerfiles, long...) {
				if base := path.Base(f); slices.Contains(releaseDockerfileNames, base) {
					b.dockerfile = base
				}
			}
			if b.dockerfile == "" {
				continue
			}
			platforms, platformsDynamic := flagValues(args, "--platform")
			tags, tagsDynamic := flagValues(args, "-t")
			longTags, longTagsDynamic := flagValues(args, "--tag")
			if platformsDynamic || tagsDynamic || longTagsDynamic {
				findings = append(findings, fmt.Sprintf("%s builds %s for a platform or under a tag named through an expansion, so this check cannot tell which binary it scans", at, b.dockerfile))
				continue
			}
			for _, p := range platforms {
				b.platforms = append(b.platforms, strings.Split(p, ",")...)
			}
			b.tags = slices.Concat(tags, longTags)
			builds = append(builds, b)
		}
	}
	if scans == 0 {
		findings = append(findings, fmt.Sprintf("binary scan: %s runs no %s, so build validation scans no binary a release ships", file, binaryScanCommand))
	}
	for _, name := range releaseDockerfileNames {
		for _, platform := range releasePlatforms {
			built := false
			for _, b := range builds {
				if b.dockerfile != name || !slices.Contains(b.platforms, platform) {
					continue
				}
				built = true
				if !slices.ContainsFunc(b.tags, func(tag string) bool { return slices.Contains(scanned[platform], tag) }) {
					findings = append(findings, fmt.Sprintf("%s builds %s for %s as %s, which no %s run scans as %s", b.at, name, platform, strings.Join(b.tags, ", "), binaryScanCommand, platform))
				}
			}
			if !built {
				findings = append(findings, fmt.Sprintf("binary scan: %s builds %s for %s nowhere, where a release pushes it, so that binary goes unscanned", file, name, platform))
			}
		}
	}
	return findings
}

// govulncheckFindings reads the scan script and returns every govulncheck it runs that does not
// scan a binary in the text output, and a finding when it runs none. The text output is the one
// whose exit code reports a finding: govulncheck's JSON, SARIF and OpenVEX outputs exit 0 however
// many vulnerabilities they detect (govulncheck v1.9.0, Exit codes), so a gate on one passes
// everything.
func govulncheckFindings(file, text string) []string {
	var findings []string
	script := readShell(text)
	for _, p := range script.problems {
		findings = append(findings, fmt.Sprintf("binary scan: %s:%d %s, which this reader cannot read as the shell would", file, p.line, p.what))
	}
	runs := 0
	for _, c := range script.commands {
		if len(c.words) == 0 || c.words[0].value != "govulncheck" {
			continue
		}
		runs++
		at := fmt.Sprintf("binary scan: %s:%d", file, c.line)
		args := c.words[1:]
		modes, _ := flagValues(args, "-mode")
		if !slices.Equal(modes, []string{"binary"}) {
			findings = append(findings, at+" runs govulncheck without -mode=binary, so it scans no shipped binary")
		}
		formats, _ := flagValues(args, "-format")
		longFormats, _ := flagValues(args, "--format")
		for _, f := range append(formats, longFormats...) {
			if f != "text" {
				findings = append(findings, fmt.Sprintf("%s runs govulncheck with -format %s, which exits 0 whatever it finds", at, f))
			}
		}
		for _, w := range args {
			flag := w.value
			if strings.HasPrefix(flag, "--") {
				flag = flag[1:]
			}
			if rest, ok := strings.CutPrefix(flag, "-json"); ok && (rest == "" || rest[0] == '=') {
				findings = append(findings, at+" runs govulncheck with -json, which exits 0 whatever it finds")
			}
		}
	}
	if runs == 0 {
		findings = append(findings, fmt.Sprintf("binary scan: %s runs no govulncheck, so it gates on no advisory", file))
	}
	return findings
}

func TestBinaryScan_TheRealBuildValidationScansEveryReleaseBinary(t *testing.T) {
	root := SourceRoot(t)
	workflow, err := os.ReadFile(filepath.Join(filepath.Dir(root), filepath.FromSlash(buildValidationWorkflow)))
	require.NoError(t, err)
	assert.Empty(t, binaryScanFindings(buildValidationWorkflow, workflowRunScripts(string(workflow))))

	script, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(binaryScanScript)))
	require.NoError(t, err)
	assert.Empty(t, govulncheckFindings(binaryScanScript, string(script)))
}

func TestBinaryScan_Workflow(t *testing.T) {
	const workflow = "jobs:\n" + // 1
		"  build-validation:\n" + // 2
		"    steps:\n" + // 3
		"      - name: Build the docs image\n" + // 4
		"        run: docker build -f site/Dockerfile -t docs .\n" + // 5
		"      - name: Build both images\n" + // 6
		"        run: |\n" + // 7
		"          set -euo pipefail\n" + // 8
		"          docker buildx build --load --platform linux/amd64 -f Dockerfile-authserver -t a:amd64 ..\n" + // 9
		"          docker buildx build --load --platform linux/arm64 -f Dockerfile-authserver -t a:arm64 ..\n" + // 10
		"          docker buildx build --load --platform=linux/amd64 --file Dockerfile-adminconsole --tag c:amd64 ..\n" + // 11
		"          docker buildx build --load --platform=linux/arm64 --file Dockerfile-adminconsole --tag c:arm64 ..\n" + // 12
		"      - name: Scan\n" + // 13
		"        working-directory: src/build\n" + // 14
		"        run: ./scan-image-binaries.sh --platform linux/amd64 a:amd64 c:amd64 --platform linux/arm64 a:arm64 c:arm64\n" // 15
	findings := func(src string) []string {
		return binaryScanFindings("check.yml", workflowRunScripts(src))
	}
	replace := func(t *testing.T, src, old, with string) string {
		t.Helper()
		if strings.Count(src, old) != 1 {
			t.Fatalf("%q is not in the fixture exactly once", old)
		}
		return strings.Replace(src, old, with, 1)
	}

	t.Run("both images built for both platforms and each build scanned under its own passes", func(t *testing.T) {
		assertFindings(t, findings(workflow))
	})
	t.Run("one build for both platforms, scanned under each, passes", func(t *testing.T) {
		src := replace(t, workflow, "--platform linux/amd64 -f Dockerfile-authserver -t a:amd64 ..\n", "--platform linux/amd64,linux/arm64 -f Dockerfile-authserver -t a:arm64 ..\n")
		assertFindings(t, findings(replace(t, src, "linux/amd64 a:amd64 c:amd64", "linux/amd64 a:arm64 c:amd64")))
	})
	t.Run("an image built for the runner's platform alone, as before", func(t *testing.T) {
		src := replace(t, workflow, "          docker buildx build --load --platform linux/arm64 -f Dockerfile-authserver -t a:arm64 ..\n", "")
		assertFindings(t, findings(replace(t, src, "--platform linux/amd64 -f Dockerfile-authserver", "-f Dockerfile-authserver")),
			"binary scan: check.yml builds Dockerfile-authserver for linux/amd64 nowhere, where a release pushes it",
			"binary scan: check.yml builds Dockerfile-authserver for linux/arm64 nowhere, where a release pushes it")
	})
	t.Run("an arm64 build that is never scanned", func(t *testing.T) {
		assertFindings(t, findings(replace(t, workflow, " c:arm64\n", "\n")),
			"binary scan: check.yml:12 builds Dockerfile-adminconsole for linux/arm64 as c:arm64, which no scan-image-binaries.sh run scans as linux/arm64")
	})
	t.Run("a build scanned under the other platform", func(t *testing.T) {
		src := replace(t, workflow, "linux/amd64 a:amd64 c:amd64 --platform linux/arm64 a:arm64", "linux/amd64 a:arm64 c:amd64 --platform linux/arm64 a:amd64")
		assertFindings(t, findings(src),
			"binary scan: check.yml:9 builds Dockerfile-authserver for linux/amd64 as a:amd64, which no scan-image-binaries.sh run scans as linux/amd64",
			"binary scan: check.yml:10 builds Dockerfile-authserver for linux/arm64 as a:arm64, which no scan-image-binaries.sh run scans as linux/arm64")
	})
	t.Run("images named before any platform are scanned under none", func(t *testing.T) {
		assertFindings(t, findings(replace(t, workflow, "./scan-image-binaries.sh --platform linux/amd64 a:amd64", "./scan-image-binaries.sh a:amd64 --platform linux/amd64")),
			"check.yml:9 builds Dockerfile-authserver for linux/amd64 as a:amd64, which no scan-image-binaries.sh run scans as linux/amd64")
	})
	t.Run("a scan mentioned in a comment or echoed is not run", func(t *testing.T) {
		src := replace(t, workflow, "        run: ./scan-image-binaries.sh", "        run: echo ./scan-image-binaries.sh")
		got := findings(src)
		assert.Contains(t, strings.Join(got, "\n"), "binary scan: check.yml runs no scan-image-binaries.sh, so build validation scans no binary a release ships")
		assert.Len(t, got, 5, "the missing scan, and each of the four builds unscanned:\n%s", strings.Join(got, "\n"))
	})
	t.Run("a workflow with no scan and no builds", func(t *testing.T) {
		assertFindings(t, findings("jobs:\n  b:\n    steps:\n      - run: ./build.sh\n"),
			"runs no scan-image-binaries.sh",
			"builds Dockerfile-authserver for linux/amd64 nowhere",
			"builds Dockerfile-authserver for linux/arm64 nowhere",
			"builds Dockerfile-adminconsole for linux/amd64 nowhere",
			"builds Dockerfile-adminconsole for linux/arm64 nowhere")
	})
	t.Run("a platform or a tag through a variable", func(t *testing.T) {
		got := findings(replace(t, workflow, "--platform linux/arm64 -f Dockerfile-authserver -t a:arm64", "--platform \"$p\" -f Dockerfile-authserver -t a:arm64"))
		assert.Contains(t, strings.Join(got, "\n"), "binary scan: check.yml:10 builds Dockerfile-authserver for a platform or under a tag named through an expansion")
	})
	t.Run("a scan whose images come through a variable", func(t *testing.T) {
		got := findings(replace(t, workflow, "a:arm64 c:arm64\n", "\"${arm[@]}\"\n"))
		assert.Contains(t, strings.Join(got, "\n"), "binary scan: check.yml:15 passes \"${arm[@]}\" through an expansion")
	})
}

func TestBinaryScan_Govulncheck(t *testing.T) {
	const script = "#!/bin/bash\n" +
		"set -euo pipefail\n" +
		"echo \"govulncheck -format json is not used\"\n" +
		"if govulncheck -mode=binary \"$binary\"; then\n" +
		"  echo ok\n" +
		"fi\n"
	findings := func(src string) []string { return govulncheckFindings("scan.sh", src) }

	t.Run("a binary scan in text output passes, and a mention in a string is no run", func(t *testing.T) {
		assertFindings(t, findings(script))
	})
	t.Run("-mode binary as two words passes, and so does -format text", func(t *testing.T) {
		assertFindings(t, findings(strings.Replace(script, "-mode=binary", "-mode binary -format text", 1)))
	})
	for _, tc := range []struct{ flag, format string }{
		{"-format json", "json"}, {"-format=sarif", "sarif"}, {"--format openvex", "openvex"},
	} {
		t.Run(tc.flag+", which exits 0 on a finding", func(t *testing.T) {
			assertFindings(t, findings(strings.Replace(script, "-mode=binary", "-mode=binary "+tc.flag, 1)),
				"binary scan: scan.sh:4 runs govulncheck with -format "+tc.format+", which exits 0 whatever it finds")
		})
	}
	t.Run("-json, the legacy spelling of the JSON output", func(t *testing.T) {
		assertFindings(t, findings(strings.Replace(script, "-mode=binary", "-mode=binary -json", 1)),
			"binary scan: scan.sh:4 runs govulncheck with -json, which exits 0 whatever it finds")
	})
	t.Run("a source scan", func(t *testing.T) {
		assertFindings(t, findings(strings.Replace(script, "-mode=binary \"$binary\"", "./...", 1)),
			"binary scan: scan.sh:4 runs govulncheck without -mode=binary")
	})
	t.Run("a script that runs no govulncheck", func(t *testing.T) {
		assertFindings(t, findings("#!/bin/bash\necho govulncheck -mode=binary x\n"),
			"binary scan: scan.sh runs no govulncheck, so it gates on no advisory")
	})
}

// ---- the script, run with its tools stubbed ------------------------------------------------

// scanImage is an image the stubbed docker holds, and what the stubbed tools say of its binary:
// what file -b and go version -m print for it, and what govulncheck prints and exits with.
type scanImage struct {
	platform, entrypoint string
	file, buildSettings  string
	vulnOutput           string
	vulnExit             int
	copyFails, notGo     bool
}

// The descriptions file 5.46 printed for the binaries of images built from this tree, and for a
// dynamically linked executable.
const (
	fileAmd64     = "ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, Go BuildID=c5auujXv12S9XOkHuJJd/Jq02t2cNR6unVWonkA3G/v1qVWltpXluiYtXFksoe/OgOeZeO0fEi7tfs02u-t, BuildID[sha1]=d11cd46516238db4ba93a255a5d124a2ca69a28b, not stripped"
	fileArm64     = "ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, Go BuildID=BmI9ll4od0sEWQ2MUD6f/fn8H5OyWosmqdISpe8_T/4oLo0PYC1XjGV9mvT10Q/d_-l8001uI1dEVg1dV4s, BuildID[sha1]=2b70c92a8cb6c891d6d62a2d0f92267357a99338, not stripped"
	fileDynamic   = "ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=138e98f5729038720bcc110e9084b5db67215e2a, for GNU/Linux 3.2.0, stripped"
	noVulnsOutput = "=== Symbol Results ===\n\nNo vulnerabilities found.\n"
)

// buildSettingsFor is what go version -m printed for the auth server's arm64 binary, its
// dependency lines left out, for the platform's architecture.
func buildSettingsFor(binary, arch string) string {
	return binary + ": go1.27.3\n" +
		"\tpath\tgithub.com/leodip/goiabada/authserver/cmd/goiabada-authserver\n" +
		"\tmod\tgithub.com/leodip/goiabada/authserver\t(devel)\t\n" +
		"\t=>\t../core\t(devel)\t\n" +
		"\tbuild\t-buildmode=exe\n" +
		"\tbuild\t-compiler=gc\n" +
		"\tbuild\t-ldflags=\"-w -X 'github.com/leodip/goiabada/core/buildinfo.Version=0.0.0-slice6' -X 'github.com/leodip/goiabada/core/buildinfo.BuildDate=2026-11-08' -X 'github.com/leodip/goiabada/core/buildinfo.GitCommit=60aa14d34'\"\n" +
		"\tbuild\t-tags=production\n" +
		"\tbuild\tCGO_ENABLED=0\n" +
		"\tbuild\tGOARCH=" + arch + "\n" +
		"\tbuild\tGOOS=linux\n"
}

// releaseScanImages are the four images build validation scans, as their builds make them.
func releaseScanImages() map[string]scanImage {
	images := map[string]scanImage{}
	for _, server := range []string{"authserver", "adminconsole"} {
		binary := "/app/goiabada-" + server
		images["goiabada-"+server+":ci-amd64"] = scanImage{platform: "linux/amd64", entrypoint: binary, file: fileAmd64, buildSettings: buildSettingsFor(binary, "amd64"), vulnOutput: noVulnsOutput}
		images["goiabada-"+server+":ci-arm64"] = scanImage{platform: "linux/arm64", entrypoint: binary, file: fileArm64, buildSettings: buildSettingsFor(binary, "arm64"), vulnOutput: noVulnsOutput}
	}
	return images
}

// releaseScanArgs are the arguments build validation passes the script.
var releaseScanArgs = []string{
	"--platform", "linux/amd64", "goiabada-authserver:ci-amd64", "goiabada-adminconsole:ci-amd64",
	"--platform", "linux/arm64", "goiabada-authserver:ci-arm64", "goiabada-adminconsole:ci-arm64",
}

// The stubs keep each image in a directory named by its key, and docker cp writes the key into
// the file it copies out, so the other stubs know whose binary they were handed. Each logs what it
// was asked into the log file.
const (
	stubDocker = `#!/bin/bash
key() { printf '%s' "$1" | tr '/:' '__'; }
echo "docker $*" >> "$STUB/log"
case "$1 $2" in
"image inspect")
    [ "$3" = --format ] || { echo "stub docker: unexpected $*" >&2; exit 64; }
    d="$STUB/images/$(key "$5")"
    [ -d "$d" ] || { echo "Error: No such image: $5" >&2; exit 1; }
    case "$4" in
    '{{.Os}}/{{.Architecture}}') cat "$d/platform" ;;
    '{{index .Config.Entrypoint 0}}') cat "$d/entrypoint" ;;
    *) echo "stub docker: unexpected format $4" >&2; exit 64 ;;
    esac ;;
"create --platform")
    d="$STUB/images/$(key "$4")"
    [ -d "$d" ] || { echo "Unable to find image '$4' locally" >&2; exit 125; }
    [ "$(cat "$d/platform")" = "$3" ] || { echo "stub docker: created $4 as $3" >&2; exit 64; }
    echo "container-$(key "$4")" ;;
"cp -q")
    container=${3%%:*}
    file=${3#*:}
    k=${container#container-}
    d="$STUB/images/$k"
    if [ -e "$d/copy-fails" ] || [ "$(cat "$d/entrypoint")" != "$file" ]; then
        echo "Error response from daemon: Could not find the file $file in container $container" >&2
        exit 1
    fi
    printf '%s' "$k" > "$4" ;;
"rm "*)
    echo "$2" ;;
*)
    echo "stub docker: unexpected $*" >&2
    exit 64 ;;
esac
`
	stubFile = `#!/bin/bash
echo "file $*" >> "$STUB/log"
[ "$1" = -b ] || { echo "stub file: unexpected $*" >&2; exit 64; }
cat "$STUB/images/$(cat "$2")/file"
`
	stubGo = `#!/bin/bash
echo "go $*" >> "$STUB/log"
[ "$1 $2" = "version -m" ] || { echo "stub go: unexpected $*" >&2; exit 64; }
d="$STUB/images/$(cat "$3")"
if [ -e "$d/not-go" ]; then
    echo "$3: could not read Go build info from $3: not a Go executable"
    exit 1
fi
sed "s|^BINARY|$3|" "$d/build-settings"
`
	stubGovulncheck = `#!/bin/bash
binary=${!#}
k=$(cat "$binary")
echo "govulncheck $* ($k)" >> "$STUB/log"
d="$STUB/images/$k"
cat "$d/vuln-output"
exit "$(cat "$d/vuln-exit")"
`
)

// scanRun is what one run of the script did: its exit code, its output, and what it asked of
// each tool.
type scanRun struct {
	code           int
	stdout, stderr string
	log            []string
}

// runBinaryScan runs the scan script over images, with docker, file, go and govulncheck the stubs
// above, and the arguments given.
func runBinaryScan(t *testing.T, images map[string]scanImage, args ...string) scanRun {
	t.Helper()
	stub := t.TempDir()
	bin := filepath.Join(stub, "bin")
	require.NoError(t, os.MkdirAll(bin, 0o755))
	for name, body := range map[string]string{"docker": stubDocker, "file": stubFile, "go": stubGo, "govulncheck": stubGovulncheck} {
		require.NoError(t, os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755))
	}
	for name, img := range images {
		d := filepath.Join(stub, "images", strings.NewReplacer("/", "_", ":", "_").Replace(name))
		require.NoError(t, os.MkdirAll(d, 0o755))
		settings := strings.Replace(img.buildSettings, img.entrypoint+":", "BINARY:", 1)
		for file, content := range map[string]string{
			"platform": img.platform, "entrypoint": img.entrypoint, "file": img.file,
			"build-settings": settings, "vuln-output": img.vulnOutput, "vuln-exit": fmt.Sprint(img.vulnExit),
		} {
			require.NoError(t, os.WriteFile(filepath.Join(d, file), []byte(content), 0o644))
		}
		if img.copyFails {
			require.NoError(t, os.WriteFile(filepath.Join(d, "copy-fails"), nil, 0o644))
		}
		if img.notGo {
			require.NoError(t, os.WriteFile(filepath.Join(d, "not-go"), nil, 0o644))
		}
	}
	cmd := exec.Command("bash", append([]string{filepath.Join(SourceRoot(t), filepath.FromSlash(binaryScanScript))}, args...)...)
	cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "STUB=" + stub, "TMPDIR=" + t.TempDir(), "HOME=" + stub}
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	} else {
		require.NoError(t, err)
	}
	logText, err := os.ReadFile(filepath.Join(stub, "log"))
	if err != nil && !os.IsNotExist(err) {
		require.NoError(t, err)
	}
	var log []string
	if s := strings.TrimSpace(string(logText)); s != "" {
		log = strings.Split(s, "\n")
	}
	return scanRun{code: code, stdout: stdout.String(), stderr: stderr.String(), log: log}
}

// scanned returns the images govulncheck was run on, in order, and fails unless each run was
// govulncheck -mode=binary on one file and nothing else.
func (r scanRun) scanned(t *testing.T) []string {
	t.Helper()
	invocation := regexp.MustCompile(`^govulncheck -mode=binary (\S+) \((\S+)\)$`)
	var keys []string
	for _, line := range r.log {
		if !strings.HasPrefix(line, "govulncheck ") {
			continue
		}
		m := invocation.FindStringSubmatch(line)
		if assert.NotNil(t, m, "govulncheck was run as %q", line) {
			keys = append(keys, m[2])
		}
	}
	return keys
}

// errors returns the ::error:: lines the script printed, on either stream.
func (r scanRun) errors() []string {
	var out []string
	for _, line := range strings.Split(r.stdout+"\n"+r.stderr, "\n") {
		if strings.HasPrefix(line, "::error::") {
			out = append(out, line)
		}
	}
	return out
}

// allScanned is every image of releaseScanImages, as the stubs key them, in releaseScanArgs' order.
var allScanned = []string{
	"goiabada-authserver_ci-amd64", "goiabada-adminconsole_ci-amd64",
	"goiabada-authserver_ci-arm64", "goiabada-adminconsole_ci-arm64",
}

func TestBinaryScan_Script(t *testing.T) {
	with := func(name string, change func(*scanImage)) map[string]scanImage {
		images := releaseScanImages()
		img := images[name]
		change(&img)
		images[name] = img
		return images
	}

	t.Run("the four release binaries pass, each checked and scanned", func(t *testing.T) {
		r := runBinaryScan(t, releaseScanImages(), releaseScanArgs...)
		assert.Equal(t, 0, r.code, "stdout:\n%s\nstderr:\n%s", r.stdout, r.stderr)
		assert.Empty(t, r.errors())
		assert.Equal(t, allScanned, r.scanned(t))
		assert.Equal(t, 4, strings.Count(r.stdout, "No vulnerabilities found."), "govulncheck's output is the step's:\n%s", r.stdout)
		for _, line := range r.log {
			if strings.HasPrefix(line, "docker create ") {
				assert.Contains(t, r.log, "docker rm "+"container-"+strings.NewReplacer("/", "_", ":", "_").Replace(strings.Fields(line)[4]), "each container created is removed")
			}
		}
	})
	t.Run("an image of another platform than the one it was built for", func(t *testing.T) {
		r := runBinaryScan(t, with("goiabada-authserver:ci-arm64", func(i *scanImage) { i.platform = "linux/amd64" }), releaseScanArgs...)
		assert.Equal(t, 1, r.code)
		assert.Equal(t, []string{"::error::goiabada-authserver:ci-arm64 is linux/amd64, where it must be linux/arm64"}, r.errors())
	})
	t.Run("an image that cannot be inspected", func(t *testing.T) {
		images := releaseScanImages()
		delete(images, "goiabada-adminconsole:ci-arm64")
		r := runBinaryScan(t, images, releaseScanArgs...)
		assert.Equal(t, 1, r.code)
		assert.Equal(t, []string{"::error::goiabada-adminconsole:ci-arm64: unable to inspect it: Error: No such image: goiabada-adminconsole:ci-arm64"}, r.errors())
		assert.Equal(t, allScanned[:3], r.scanned(t), "the other images are still scanned")
	})
	t.Run("a binary that cannot be copied out", func(t *testing.T) {
		r := runBinaryScan(t, with("goiabada-authserver:ci-amd64", func(i *scanImage) { i.copyFails = true }), releaseScanArgs...)
		assert.Equal(t, 1, r.code)
		assert.Equal(t, []string{"::error::goiabada-authserver:ci-amd64: unable to copy /app/goiabada-authserver out of it: Error response from daemon: Could not find the file /app/goiabada-authserver in container container-goiabada-authserver_ci-amd64"}, r.errors())
		assert.Equal(t, allScanned[1:], r.scanned(t), "a binary not copied out is not scanned, and the others are")
		assert.Contains(t, r.log, "docker rm container-goiabada-authserver_ci-amd64", "the container is removed all the same")
	})
	t.Run("a binary of another architecture than its image's", func(t *testing.T) {
		r := runBinaryScan(t, with("goiabada-adminconsole:ci-arm64", func(i *scanImage) { i.file = fileAmd64 }), releaseScanArgs...)
		assert.Equal(t, 1, r.code)
		assert.Equal(t, []string{"::error::goiabada-adminconsole:ci-arm64: /app/goiabada-adminconsole is not an ARM aarch64 executable: " + fileAmd64}, r.errors())
	})
	t.Run("an amd64 image holding an arm64 binary", func(t *testing.T) {
		r := runBinaryScan(t, with("goiabada-authserver:ci-amd64", func(i *scanImage) { i.file = fileArm64 }), releaseScanArgs...)
		assert.Equal(t, 1, r.code)
		assert.Equal(t, []string{"::error::goiabada-authserver:ci-amd64: /app/goiabada-authserver is not an x86-64 executable: " + fileArm64}, r.errors())
	})
	t.Run("a dynamically linked binary", func(t *testing.T) {
		r := runBinaryScan(t, with("goiabada-authserver:ci-amd64", func(i *scanImage) { i.file = fileDynamic }), releaseScanArgs...)
		assert.Equal(t, 1, r.code)
		assert.Equal(t, []string{"::error::goiabada-authserver:ci-amd64: /app/goiabada-authserver is not statically linked: " + fileDynamic}, r.errors())
	})
	t.Run("a binary built with cgo", func(t *testing.T) {
		r := runBinaryScan(t, with("goiabada-adminconsole:ci-amd64", func(i *scanImage) {
			i.buildSettings = strings.Replace(i.buildSettings, "CGO_ENABLED=0", "CGO_ENABLED=1", 1)
		}), releaseScanArgs...)
		assert.Equal(t, 1, r.code)
		assert.Equal(t, []string{"::error::goiabada-adminconsole:ci-amd64: /app/goiabada-adminconsole was built with CGO_ENABLED=1, where it must be 0"}, r.errors())
	})
	t.Run("a binary whose build settings record no CGO_ENABLED", func(t *testing.T) {
		r := runBinaryScan(t, with("goiabada-adminconsole:ci-amd64", func(i *scanImage) {
			i.buildSettings = strings.Replace(i.buildSettings, "\tbuild\tCGO_ENABLED=0\n", "", 1)
		}), releaseScanArgs...)
		assert.Equal(t, 1, r.code)
		assert.Equal(t, []string{"::error::goiabada-adminconsole:ci-amd64: /app/goiabada-adminconsole was built with CGO_ENABLED=, where it must be 0"}, r.errors())
	})
	t.Run("a binary built without the production tag", func(t *testing.T) {
		r := runBinaryScan(t, with("goiabada-authserver:ci-arm64", func(i *scanImage) {
			i.buildSettings = strings.Replace(i.buildSettings, "\tbuild\t-tags=production\n", "", 1)
		}), releaseScanArgs...)
		assert.Equal(t, 1, r.code)
		assert.Equal(t, []string{"::error::goiabada-authserver:ci-arm64: /app/goiabada-authserver was built without the production tag (-tags=)"}, r.errors())
	})
	t.Run("the production tag among others passes, and a tag merely containing it does not", func(t *testing.T) {
		r := runBinaryScan(t, with("goiabada-authserver:ci-arm64", func(i *scanImage) {
			i.buildSettings = strings.Replace(i.buildSettings, "-tags=production", "-tags=netgo,production", 1)
		}), releaseScanArgs...)
		assert.Equal(t, 0, r.code, "stdout:\n%s\nstderr:\n%s", r.stdout, r.stderr)

		r = runBinaryScan(t, with("goiabada-authserver:ci-arm64", func(i *scanImage) {
			i.buildSettings = strings.Replace(i.buildSettings, "-tags=production", "-tags=nonproduction", 1)
		}), releaseScanArgs...)
		assert.Equal(t, 1, r.code)
		assert.Equal(t, []string{"::error::goiabada-authserver:ci-arm64: /app/goiabada-authserver was built without the production tag (-tags=nonproduction)"}, r.errors())
	})
	t.Run("a binary whose build settings cannot be read", func(t *testing.T) {
		r := runBinaryScan(t, with("goiabada-authserver:ci-arm64", func(i *scanImage) { i.notGo = true }), releaseScanArgs...)
		assert.Equal(t, 1, r.code)
		require.Len(t, r.errors(), 1, "stdout:\n%s\nstderr:\n%s", r.stdout, r.stderr)
		assert.Contains(t, r.errors()[0], "::error::goiabada-authserver:ci-arm64: unable to read the build settings of /app/goiabada-authserver: ")
		assert.Contains(t, r.errors()[0], "not a Go executable")
	})
	t.Run("govulncheck finding a vulnerable symbol", func(t *testing.T) {
		const found = "=== Symbol Results ===\n\nVulnerability #1: GO-2026-0001\n    Found in: example.com/x@v1.0.0\n\nYour code is affected by 1 vulnerability from 1 module.\n"
		r := runBinaryScan(t, with("goiabada-adminconsole:ci-arm64", func(i *scanImage) { i.vulnOutput, i.vulnExit = found, 3 }), releaseScanArgs...)
		assert.Equal(t, 1, r.code)
		assert.Equal(t, []string{"::error::goiabada-adminconsole:ci-arm64: govulncheck found vulnerable symbols present in /app/goiabada-adminconsole; their presence does not show the code reaches them"}, r.errors())
		assert.Contains(t, r.stdout, "Vulnerability #1: GO-2026-0001", "the finding is printed")
		assert.Equal(t, allScanned, r.scanned(t))
	})
	t.Run("govulncheck failing to scan", func(t *testing.T) {
		r := runBinaryScan(t, with("goiabada-authserver:ci-amd64", func(i *scanImage) { i.vulnOutput, i.vulnExit = "govulncheck: fetching vulnerabilities: 503\n", 1 }), releaseScanArgs...)
		assert.Equal(t, 1, r.code)
		assert.Equal(t, []string{"::error::goiabada-authserver:ci-amd64: govulncheck could not scan /app/goiabada-authserver, exit code 1"}, r.errors())
		assert.Equal(t, allScanned, r.scanned(t), "the other images are still scanned")
	})
	t.Run("usage errors exit 2 and scan nothing", func(t *testing.T) {
		for _, tc := range []struct {
			args []string
			want string
		}{
			{nil, "usage: scan-image-binaries.sh --platform <os/arch> <image>... [--platform <os/arch> <image>...]"},
			{[]string{"goiabada-authserver:ci-amd64", "--platform", "linux/amd64", "goiabada-adminconsole:ci-amd64"}, "goiabada-authserver:ci-amd64 is named before any --platform"},
			{[]string{"--platform", "linux/amd64", "goiabada-authserver:ci-amd64", "--platform", "linux/arm64"}, "--platform linux/arm64 names no image"},
			{[]string{"--platform"}, "--platform needs a value"},
			{[]string{"--platform", "linux/s390x", "goiabada-authserver:ci-amd64"}, "linux/s390x is not a platform a release pushes: linux/amd64 or linux/arm64"},
			{[]string{"--json", "--platform", "linux/amd64", "goiabada-authserver:ci-amd64"}, "unknown argument: --json"},
		} {
			r := runBinaryScan(t, releaseScanImages(), tc.args...)
			assert.Equal(t, 2, r.code, "%q", tc.args)
			assert.Contains(t, r.stderr, tc.want, "%q", tc.args)
			assert.Empty(t, r.log, "%q asked a tool something", tc.args)
		}
	})
}
