package guard

// The e2e server builds from CI's mirror (#867 decision 8). Every image it builds from the checkout,
// the two servers and the setup wizard in a run from source and the test app in every run, is built
// with --build-arg baseRegistry=ghcr.io/leodip/goiabada-ci, written out, so no build there asks
// Docker Hub for a base. The wizard's Dockerfile, written in remote-prepare.sh, takes baseRegistry
// as the release Dockerfiles do and names its Go image at the pin version-manager.sh update writes
// there, so the script reads no FROM line of another Dockerfile, which baseRegistry changes. The
// test app's Dockerfile takes baseRegistry with the release Dockerfiles' default, Docker Hub's
// library. The e2e server's Mailpit default is tools.mailpit at the mirror.
//
// Every mirror address this gives, each base of a Dockerfile the e2e server builds and the Mailpit
// default, is one the mirror's list, .github/mirror/images, holds at the committed pins, so the
// Mirror workflow copies it. The database image stays the one the wizard writes for the chosen
// engine, and a run against a release pulls the release's two images from Docker Hub: neither is
// the e2e scripts' to name.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// e2eLib holds the e2e server's settings and their defaults, Mailpit's image among them.
	e2eLib = "e2e/infra/lib.sh"
	// e2ePrepare builds the servers and the wizard on the e2e server, and e2eTestapp the test app.
	e2ePrepare = "e2e/infra/remote-prepare.sh"
	e2eTestapp = "e2e/infra/remote-testapp.sh"
	// testappDockerfile is the test app's Dockerfile, which remote-testapp.sh builds.
	testappDockerfile = "e2e/testapp/Dockerfile"
	// heredocWord stands in a script for the heredoc it opened, numbered, so the command it feeds
	// can be told.
	heredocWord = "__heredoc_"
)

// e2eBuildScripts are the scripts that build images on the e2e server, relative to the repository
// root.
var e2eBuildScripts = []string{e2ePrepare, e2eTestapp}

// e2eDockerfiles are the Dockerfiles of the checkout the e2e server builds, relative to the
// repository root; the wizard's is written in e2ePrepare and read there.
var e2eDockerfiles = []string{"src/build/Dockerfile-authserver", "src/build/Dockerfile-adminconsole", testappDockerfile}

var (
	// heredocOpener is a heredoc's operator and its delimiter, quoted or not; a here-string, <<<, is
	// none.
	heredocOpener = regexp.MustCompile(`(^|[^<])<<(-?)\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)['"]?`)
	// mailpitDefault is lib.sh's default for E2E_MAILPIT_IMAGE.
	mailpitDefault = regexp.MustCompile(`(?m)^E2E_MAILPIT_IMAGE="\$\{E2E_MAILPIT_IMAGE:-([^}"]*)\}"$`)
	// fromWord is a mention of a Dockerfile's FROM in a script, outside its comments and heredocs.
	fromWord = regexp.MustCompile(`\bFROM\b`)
)

// shellHeredoc is one heredoc of a script: its body as the shell hands it on, and the line its body
// begins on.
type shellHeredoc struct {
	body string
	line int
}

// splitHeredocs returns a script with each heredoc's operator replaced by heredocWord and its
// number, and its body and closing line emptied, so readShell reads its commands and they keep
// their lines, and the heredocs. An unquoted delimiter leaves the body to the shell's expansions,
// so its escapes are undone as the shell does; its expansions stay as written. It reports a heredoc
// that never closes.
func splitHeredocs(src string) (string, []shellHeredoc, []shellProblem) {
	lines := strings.Split(src, "\n")
	var heredocs []shellHeredoc
	for i := 0; i < len(lines); i++ {
		m := heredocOpener.FindStringSubmatchIndex(lines[i])
		if m == nil {
			continue
		}
		strip, quoted, delimiter := lines[i][m[4]:m[5]] == "-", m[6] != m[7], lines[i][m[8]:m[9]]
		lines[i] = lines[i][:m[3]] + heredocWord + fmt.Sprint(len(heredocs)) + lines[i][m[1]:]
		start, end := i+1, -1
		for j := start; j < len(lines); j++ {
			line := lines[j]
			if strip {
				line = strings.TrimLeft(line, "\t")
			}
			if line == delimiter {
				end = j
				break
			}
		}
		if end < 0 {
			return "", nil, []shellProblem{{i + 1, fmt.Sprintf("opens a heredoc ending at %s that never ends", delimiter)}}
		}
		body := strings.Join(lines[start:end], "\n") + "\n"
		if !quoted {
			body = unquotedHeredocEscapes.Replace(body)
		}
		heredocs = append(heredocs, shellHeredoc{body: body, line: start + 1})
		for j := start; j <= end; j++ {
			lines[j] = ""
		}
		i = end
	}
	return strings.Join(lines, "\n"), heredocs, nil
}

// unquotedHeredocEscapes are the escapes the shell undoes in an unquoted heredoc: a backslash before
// $, ` or a backslash, and before a newline, which joins the lines.
var unquotedHeredocEscapes = strings.NewReplacer(`\$`, `$`, "\\`", "`", `\\`, `\`, "\\\n", "")

// passedBaseRegistries returns the values a docker build's arguments give baseRegistry with
// --build-arg, as written, expansions left in them.
func passedBaseRegistries(args []shellWord) []string {
	var passed []string
	for i := 0; i < len(args); i++ {
		word := args[i]
		if v, ok := strings.CutPrefix(word.value, "--build-arg="); ok {
			word.value = v
		} else if word.value == "--build-arg" && i+1 < len(args) {
			i++
			word = args[i]
		} else {
			continue
		}
		if value, ok := strings.CutPrefix(word.value, baseRegistryArg+"="); ok {
			passed = append(passed, value)
		}
	}
	return passed
}

// mirrorBaseFindings holds each base a Dockerfile builds on to one the mirror holds, when it is
// built with baseRegistry set to the mirror, as Check and the e2e server build: a base under
// ${baseRegistry}/ is read at the mirror, and must be an address of mirrored. A base written
// otherwise is baseRegistryDockerfileFindings' to report. guard begins each finding.
func mirrorBaseFindings(guard, rel, src string, mirrored map[string]bool) []string {
	instructions, unparseable := dockerInstructions(src)
	if unparseable != "" {
		return nil
	}
	var findings []string
	stages := map[string]bool{}
	for _, st := range dockerStages(instructions) {
		image := st.image
		external := image != "scratch" && !stages[strings.ToLower(image)]
		if st.name != "" {
			stages[st.name] = true
		}
		rest, under := strings.CutPrefix(image, "${"+baseRegistryArg+"}/")
		if !under {
			rest, under = strings.CutPrefix(image, "$"+baseRegistryArg+"/")
		}
		if !external || !under {
			continue
		}
		at := fmt.Sprintf("%s: %s:%d", guard, rel, st.from.line)
		resolved := ciMirror + "/" + rest
		switch {
		case strings.Contains(rest, "$"):
			findings = append(findings, fmt.Sprintf("%s builds on %s, whose tag comes from a variable, so this check cannot tell whether the mirror holds it: write the tag out, as version-manager.sh update writes it",
				at, image))
		case !mirrored[resolved]:
			findings = append(findings, fmt.Sprintf("%s builds on %s, which a build passing the mirror pulls as %s, and %s does not hold it at versions.yaml's pins: build on the pinned tag (run ./version-manager.sh update), or add the image to %s",
				at, image, resolved, mirrorList, mirrorList))
		}
	}
	return findings
}

// e2eScriptFindings reads one script that builds on the e2e server, and holds each of its docker
// builds to passing the mirror as baseRegistry, written out and once, and each Dockerfile it hands a
// build in a heredoc to the rules of baseRegistryDockerfileFindings and to bases the mirror holds.
// It reports a mention of FROM outside the script's comments and heredocs, a read of another
// Dockerfile's base, and a script with no build, since a check that read nothing would pass on any
// file.
func e2eScriptFindings(file, src string, mirrored map[string]bool) []string {
	stripped, heredocs, problems := splitHeredocs(src)
	script := readShell(stripped)
	problems = append(problems, script.problems...)
	if len(problems) > 0 {
		var findings []string
		for _, p := range problems {
			findings = append(findings, fmt.Sprintf("e2e mirror: %s:%d %s, which this reader cannot read as the shell would", file, p.line, p.what))
		}
		return findings
	}
	var findings []string
	for i, line := range strings.Split(script.bare, "\n") {
		if fromWord.MatchString(line) {
			findings = append(findings, fmt.Sprintf("e2e mirror: %s:%d names FROM outside a Dockerfile: a script that reads another Dockerfile's base reads the ${%s} that Dockerfile writes, not an image; name the image in the Dockerfile the build reads",
				file, i+1, baseRegistryArg))
		}
	}
	builds := 0
	want := "--build-arg " + baseRegistryArg + "=" + ciMirror
	for _, c := range script.commands {
		args, ok := isDockerBuild(c)
		if !ok {
			continue
		}
		builds++
		at := fmt.Sprintf("e2e mirror: %s:%d", file, c.line)
		switch passed := passedBaseRegistries(args); {
		case len(passed) == 0:
			findings = append(findings, fmt.Sprintf("%s builds without %s, so the e2e server pulls its bases from Docker Hub", at, want))
		case len(passed) > 1 || passed[0] != ciMirror:
			findings = append(findings, fmt.Sprintf("%s builds with %s=%s, where the e2e server's builds pass %s, written out",
				at, baseRegistryArg, strings.Join(passed, " and "), want))
		}
		for _, a := range args {
			n, ok := strings.CutPrefix(a.value, heredocWord)
			h, err := strconv.Atoi(n)
			if !ok || err != nil || h < 0 || h >= len(heredocs) {
				continue
			}
			// The body at its own lines, so a finding names the script's line.
			dockerfile := strings.Repeat("\n", heredocs[h].line-1) + heredocs[h].body
			findings = append(findings, baseRegistryDockerfileFindings(file, dockerfile)...)
			findings = append(findings, mirrorBaseFindings("e2e mirror", file, dockerfile, mirrored)...)
		}
	}
	if builds == 0 {
		findings = append(findings, fmt.Sprintf("e2e mirror: %s holds no docker build this check can read", file))
	}
	return findings
}

// e2eMailpitFindings holds lib.sh's Mailpit default to a mirror address the mirror's list holds.
func e2eMailpitFindings(file, src string, mirrored map[string]bool) []string {
	m := mailpitDefault.FindStringSubmatchIndex(src)
	if m == nil {
		return []string{fmt.Sprintf("e2e mirror: %s sets no E2E_MAILPIT_IMAGE default this check can read, written E2E_MAILPIT_IMAGE=\"${E2E_MAILPIT_IMAGE:-<image>}\"", file)}
	}
	image := src[m[2]:m[3]]
	at := fmt.Sprintf("e2e mirror: %s:%d", file, 1+strings.Count(src[:m[0]], "\n"))
	switch {
	case !strings.HasPrefix(image, ciMirror+"/"):
		return []string{fmt.Sprintf("%s runs Mailpit from %s, where the e2e server pulls it from the mirror, %s/mailpit:v<tools.mailpit>, as ./version-manager.sh update writes it",
			at, imageRegistry(image), ciMirror)}
	case !mirrored[image]:
		return []string{fmt.Sprintf("%s runs Mailpit as %s, which %s does not hold at versions.yaml's pins: run ./version-manager.sh update", at, image, mirrorList)}
	}
	return nil
}

// e2eFiles are the files the e2e server's guard reads, relative to the repository root.
var e2eFiles = append(append([]string{e2eLib}, e2eBuildScripts...), e2eDockerfiles...)

// checkE2EMirror reads the e2e server's scripts and Dockerfiles under the repository root and
// returns their findings and how many of them it read, mirrored being the mirror addresses the list
// holds.
func checkE2EMirror(repoRoot string, mirrored map[string]bool) ([]string, int) {
	var findings []string
	files := 0
	read := func(rel string) (string, bool) {
		content, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(rel)))
		if err != nil {
			findings = append(findings, fmt.Sprintf("e2e mirror: %s cannot be read: %v", rel, err))
			return "", false
		}
		files++
		return string(content), true
	}
	if src, ok := read(e2eLib); ok {
		findings = append(findings, e2eMailpitFindings(e2eLib, src, mirrored)...)
	}
	for _, rel := range e2eBuildScripts {
		if src, ok := read(rel); ok {
			findings = append(findings, e2eScriptFindings(rel, src, mirrored)...)
		}
	}
	for _, rel := range e2eDockerfiles {
		if src, ok := read(rel); ok {
			findings = append(findings, baseRegistryDockerfileFindings(rel, src)...)
			findings = append(findings, mirrorBaseFindings("e2e mirror", rel, src, mirrored)...)
		}
	}
	return findings, files
}

// assertE2EMirror is the e2e server's guard's reporting half: each finding of checkE2EMirror an
// error, and a check that read none of its files under repoRoot, or has no mirror address to hold
// them to, fatal.
func assertE2EMirror(r Reporter, repoRoot string, mirrored map[string]bool) {
	r.Helper()
	if len(mirrored) == 0 {
		r.Fatalf("e2e mirror: the mirror's list gave no address, so this check has nothing to hold the e2e server's images to")
	}
	findings, read := checkE2EMirror(repoRoot, mirrored)
	reportBuildFileFindings(r, "e2e mirror", repoRoot, read, findings)
}

// The e2e server's addresses are read at the committed pins: its files write them out.
func TestE2EServer_BuildsFromTheMirrorAndPullsMailpitFromIt(t *testing.T) {
	assertE2EMirror(t, filepath.Dir(SourceRoot(t)), committedMirrored(t))
}

// The reporting half passes the files as they are committed, reports Mailpit pulled from Docker
// Hub, and is fatal on a tree it read nothing of and on a list that gave no address.
func TestE2EServer_Reporting(t *testing.T) {
	mirrored := committedMirrored(t)
	assertTree := func(root string, m map[string]bool) Report {
		return Run(func(r Reporter) { assertE2EMirror(r, root, m) })
	}
	t.Run("the committed files pass", func(t *testing.T) {
		report := assertTree(repositoryTree(t, e2eFiles, nil), mirrored)
		assert.False(t, report.Failed(), "%s", report.Text())
	})
	t.Run("Mailpit from Docker Hub fails", func(t *testing.T) {
		root := repositoryTree(t, e2eFiles, map[string][2]string{e2eLib: {ciMirror + "/mailpit:", "axllent/mailpit:"}})
		report := assertTree(root, mirrored)
		assert.False(t, report.Stopped, "a finding is an error, not a fatal: %s", report.Text())
		require.Len(t, report.Errors, 1, "%s", report.Text())
		assert.Contains(t, report.Errors[0], "e2e mirror: "+e2eLib+":")
		assert.Contains(t, report.Errors[0], "runs Mailpit from docker.io")
	})
	t.Run("a tree holding none of the files is fatal", func(t *testing.T) {
		report := assertTree(t.TempDir(), mirrored)
		require.True(t, report.Stopped, "an empty walk passed: %s", report.Text())
		assert.Contains(t, report.Fatal, "e2e mirror: read none of its files under")
	})
	t.Run("a list that gave no address is fatal", func(t *testing.T) {
		report := assertTree(repositoryTree(t, e2eFiles, nil), map[string]bool{})
		require.True(t, report.Stopped, "%s", report.Text())
		assert.Contains(t, report.Fatal, "the mirror's list gave no address")
	})
}

// update writes tools.go into the FROM line of the wizard's Dockerfile in remote-prepare.sh, and
// tools.node into the test app's, both under ${baseRegistry}, as they are committed, and changes no
// other line of either.
func TestVersionManagerUpdate_WritesThePinsIntoTheE2EServersBuilds(t *testing.T) {
	assertUpdateWritesFromLines(t, map[string][]string{
		e2ePrepare:        {"FROM \\${baseRegistry}/golang:1.28.0-alpine AS build"},
		testappDockerfile: {"FROM ${baseRegistry}/node:27.0.1-alpine AS build", "FROM ${baseRegistry}/node:27.0.1-alpine"},
	})
}

// fixtureMirrored are the mirror addresses mirrorVersions gives the committed list.
func fixtureMirrored() map[string]bool {
	mirrored := map[string]bool{}
	for _, tag := range mirrorTags {
		mirrored[tag[1]] = true
	}
	return mirrored
}

func TestE2EServer_ScriptFindings(t *testing.T) {
	const prepare = "#!/usr/bin/env bash\n" + // 1
		"for server in authserver adminconsole; do\n" + // 2
		"  if ! docker build --label goiabada-e2e=server -f \"$src/build/Dockerfile-$server\" \\\n" + // 3
		"    --build-arg \"version=$version\" --build-arg baseRegistry=ghcr.io/leodip/goiabada-ci \"$src\" \\\n" + // 4
		"    >\"$stage/build-$server.log\" 2>&1; then\n" + // 5
		"    fail \"the $server image did not build\"\n" + // 6
		"  fi\n" + // 7
		"done\n" + // 8
		"# The wizard's Go image, FROM below, is tools.go, which version-manager.sh update writes.\n" + // 9
		"if ! docker build --output \"type=local,dest=$dir\" --build-arg \"baseRegistry=ghcr.io/leodip/goiabada-ci\" \\\n" + // 10
		"  -f - \"$src\" >\"$stage/build-wizard.log\" 2>&1 <<EOF\n" + // 11
		"ARG baseRegistry=docker.io/library\n" + // 12
		"FROM \\${baseRegistry}/golang:1.28.0-alpine AS build\n" + // 13
		"ARG version\n" + // 14
		"RUN --mount=type=cache,target=/go/pkg/mod \\\\\n" + // 15
		"  go build -ldflags \"-X main.version=\\${version}\" -o /out/$wizard .\n" + // 16
		"FROM scratch\n" + // 17
		"COPY --from=build /out/$wizard /\n" + // 18
		"EOF\n" + // 19
		"then\n" + // 20
		"  fail \"the setup wizard did not build\"\n" + // 21
		"fi\n" + // 22
		"cat >mailpit.yml <<'EOF'\n" + // 23
		"services:\n" + // 24
		"  mailpit:\n" + // 25
		"    image: $E2E_MAILPIT_IMAGE\n" + // 26
		"EOF\n" + // 27
		"docker compose up -d <<<\"no heredoc\"\n" // 28
	const testapp = "#!/usr/bin/env bash\n" + // 1
		"if ! docker build --build-arg baseRegistry=ghcr.io/leodip/goiabada-ci --label goiabada-e2e=testapp \\\n" + // 2
		"  -t \"$E2E_TESTAPP_IMAGE\" testapp-src >testapp-build.log 2>&1; then\n" + // 3
		"  fail \"the test app's image did not build\"\n" + // 4
		"fi\n" // 5
	mirrored := fixtureMirrored()
	findings := func(file, src string) []string { return e2eScriptFindings(file, src, mirrored) }
	edit := func(t *testing.T, src, old, with string) string {
		t.Helper()
		require.Equal(t, 1, strings.Count(src, old), old)
		return strings.Replace(src, old, with, 1)
	}

	t.Run("builds passing the mirror, and the wizard's Dockerfile on a base the mirror holds, pass", func(t *testing.T) {
		assertFindings(t, findings("prepare.sh", prepare))
		assertFindings(t, findings("testapp.sh", testapp))
	})
	t.Run("a server build passing no baseRegistry", func(t *testing.T) {
		assertFindings(t, findings("prepare.sh", edit(t, prepare, " --build-arg baseRegistry=ghcr.io/leodip/goiabada-ci \"$src\"", " \"$src\"")),
			"e2e mirror: prepare.sh:3 builds without --build-arg baseRegistry=ghcr.io/leodip/goiabada-ci, so the e2e server pulls its bases from Docker Hub")
	})
	t.Run("the test app built with no baseRegistry", func(t *testing.T) {
		assertFindings(t, findings("testapp.sh", edit(t, testapp, "--build-arg baseRegistry=ghcr.io/leodip/goiabada-ci ", "")),
			"e2e mirror: testapp.sh:2 builds without --build-arg baseRegistry=ghcr.io/leodip/goiabada-ci")
	})
	t.Run("the wizard built from Docker Hub", func(t *testing.T) {
		assertFindings(t, findings("prepare.sh", edit(t, prepare, "\"baseRegistry=ghcr.io/leodip/goiabada-ci\"", "baseRegistry=docker.io/library")),
			"e2e mirror: prepare.sh:10 builds with baseRegistry=docker.io/library, where the e2e server's builds pass --build-arg baseRegistry=ghcr.io/leodip/goiabada-ci, written out")
	})
	t.Run("the mirror passed through a variable", func(t *testing.T) {
		assertFindings(t, findings("testapp.sh", edit(t, testapp, "baseRegistry=ghcr.io/leodip/goiabada-ci", "\"baseRegistry=$MIRROR\"")),
			"e2e mirror: testapp.sh:2 builds with baseRegistry=$MIRROR, where the e2e server's builds pass --build-arg baseRegistry=ghcr.io/leodip/goiabada-ci, written out")
	})
	t.Run("the mirror passed and then another registry", func(t *testing.T) {
		assertFindings(t, findings("testapp.sh", edit(t, testapp, "-t ", "--build-arg=baseRegistry=docker.io/library -t ")),
			"e2e mirror: testapp.sh:2 builds with baseRegistry=ghcr.io/leodip/goiabada-ci and docker.io/library")
	})
	t.Run("the wizard's Go image read out of a release Dockerfile's FROM line", func(t *testing.T) {
		src := edit(t, prepare, "done\n", "done\ngolang=\"$(sed -n 's/^FROM \\(golang:[^ ]*\\) AS build$/\\1/p' \"$src/build/Dockerfile-authserver\")\"\n")
		assertFindings(t, findings("prepare.sh", src),
			"e2e mirror: prepare.sh:9 names FROM outside a Dockerfile: a script that reads another Dockerfile's base reads the ${baseRegistry} that Dockerfile writes")
	})
	t.Run("the wizard's Dockerfile naming its Go image without baseRegistry", func(t *testing.T) {
		assertFindings(t, findings("prepare.sh", edit(t, prepare, "FROM \\${baseRegistry}/golang:", "FROM golang:")),
			"base registry: prepare.sh:13 builds on golang:1.28.0-alpine, which bypasses ${baseRegistry}, so a build passing baseRegistry pulls it from docker.io all the same: write FROM ${baseRegistry}/golang:1.28.0-alpine")
	})
	t.Run("the wizard's Dockerfile with no baseRegistry declared", func(t *testing.T) {
		assertFindings(t, findings("prepare.sh", edit(t, prepare, "ARG baseRegistry=docker.io/library\n", "")),
			"base registry: prepare.sh declares no ARG baseRegistry=docker.io/library before its first FROM")
	})
	t.Run("the wizard's Go image at a tag the mirror lacks", func(t *testing.T) {
		assertFindings(t, findings("prepare.sh", edit(t, prepare, "golang:1.28.0-alpine", "golang:1.27.4-alpine")),
			"e2e mirror: prepare.sh:13 builds on ${baseRegistry}/golang:1.27.4-alpine, which a build passing the mirror pulls as ghcr.io/leodip/goiabada-ci/golang:1.27.4-alpine, and .github/mirror/images does not hold it at versions.yaml's pins")
	})
	t.Run("the wizard's Go image tagged through a variable", func(t *testing.T) {
		assertFindings(t, findings("prepare.sh", edit(t, prepare, "golang:1.28.0-alpine", "golang:\\${goVersion}-alpine")),
			"e2e mirror: prepare.sh:13 builds on ${baseRegistry}/golang:${goVersion}-alpine, whose tag comes from a variable")
	})
	t.Run("a heredoc that never ends", func(t *testing.T) {
		assertFindings(t, findings("prepare.sh", strings.TrimSuffix(prepare, "EOF\ndocker compose up -d <<<\"no heredoc\"\n")),
			"e2e mirror: prepare.sh:23 opens a heredoc ending at EOF that never ends, which this reader cannot read as the shell would")
	})
	t.Run("a script with no build read nothing", func(t *testing.T) {
		assertFindings(t, findings("testapp.sh", "#!/usr/bin/env bash\ndocker compose up -d testapp1\n"),
			"e2e mirror: testapp.sh holds no docker build this check can read")
	})
}

func TestE2EServer_DockerfileAndMailpitFindings(t *testing.T) {
	mirrored := fixtureMirrored()
	const dockerfile = "# The test app.\n" + // 1
		"ARG baseRegistry=docker.io/library\n" + // 2
		"FROM ${baseRegistry}/node:27.0.1-alpine AS build\n" + // 3
		"RUN npm ci\n" + // 4
		"FROM ${baseRegistry}/node:27.0.1-alpine\n" + // 5
		"COPY --from=build /app /app\n" // 6
	const lib = "E2E_DB=\"${E2E_DB:-postgres}\"\n" + // 1
		"# Mailpit, at tools.mailpit.\n" + // 2
		"E2E_MAILPIT_IMAGE=\"${E2E_MAILPIT_IMAGE:-ghcr.io/leodip/goiabada-ci/mailpit:v1.40.2}\"\n" + // 3
		"E2E_MAILPIT_PORT=\"${E2E_MAILPIT_PORT:-18025}\"\n" // 4
	dockerfileFindings := func(src string) []string {
		return append(baseRegistryDockerfileFindings("testapp/Dockerfile", src), mirrorBaseFindings("e2e mirror", "testapp/Dockerfile", src, mirrored)...)
	}
	edit := func(t *testing.T, src, old, with string) string {
		t.Helper()
		require.Equal(t, 1, strings.Count(src, old), old)
		return strings.Replace(src, old, with, 1)
	}

	t.Run("a test app on Node the mirror holds, under baseRegistry, passes", func(t *testing.T) {
		assertFindings(t, dockerfileFindings(dockerfile))
	})
	t.Run("a test app on Node the mirror lacks", func(t *testing.T) {
		assertFindings(t, dockerfileFindings(strings.Replace(dockerfile, "27.0.1", "26.13.1", 2)),
			"e2e mirror: testapp/Dockerfile:3 builds on ${baseRegistry}/node:26.13.1-alpine, which a build passing the mirror pulls as ghcr.io/leodip/goiabada-ci/node:26.13.1-alpine",
			"e2e mirror: testapp/Dockerfile:5 builds on ${baseRegistry}/node:26.13.1-alpine")
	})
	t.Run("a test app on Docker Hub's Node", func(t *testing.T) {
		assertFindings(t, dockerfileFindings(edit(t, dockerfile, "FROM ${baseRegistry}/node:27.0.1-alpine\n", "FROM node:27.0.1-alpine\n")),
			"base registry: testapp/Dockerfile:5 builds on node:27.0.1-alpine, which bypasses ${baseRegistry}")
	})
	t.Run("a test app that declares no baseRegistry", func(t *testing.T) {
		assertFindings(t, dockerfileFindings(edit(t, dockerfile, "ARG baseRegistry=docker.io/library\n", "")),
			"base registry: testapp/Dockerfile declares no ARG baseRegistry=docker.io/library before its first FROM")
	})

	t.Run("Mailpit at the pin at the mirror passes", func(t *testing.T) {
		assertFindings(t, e2eMailpitFindings("lib.sh", lib, mirrored))
	})
	t.Run("Mailpit from Docker Hub", func(t *testing.T) {
		assertFindings(t, e2eMailpitFindings("lib.sh", edit(t, lib, "ghcr.io/leodip/goiabada-ci/mailpit", "axllent/mailpit"), mirrored),
			"e2e mirror: lib.sh:3 runs Mailpit from docker.io, where the e2e server pulls it from the mirror, ghcr.io/leodip/goiabada-ci/mailpit:v<tools.mailpit>")
	})
	t.Run("Mailpit at a tag the mirror lacks", func(t *testing.T) {
		assertFindings(t, e2eMailpitFindings("lib.sh", edit(t, lib, "v1.40.2", "1.40.2"), mirrored),
			"e2e mirror: lib.sh:3 runs Mailpit as ghcr.io/leodip/goiabada-ci/mailpit:1.40.2, which .github/mirror/images does not hold at versions.yaml's pins")
	})
	t.Run("no Mailpit default read nothing", func(t *testing.T) {
		assertFindings(t, e2eMailpitFindings("lib.sh", "E2E_MAILPIT_IMAGE=ghcr.io/leodip/goiabada-ci/mailpit:v1.40.2\n", mirrored),
			"e2e mirror: lib.sh sets no E2E_MAILPIT_IMAGE default this check can read")
	})
	t.Run("files that cannot be read", func(t *testing.T) {
		got, read := checkE2EMirror(t.TempDir(), mirrored)
		assert.Zero(t, read)
		sort.Strings(got)
		want := slices.Clone(e2eFiles)
		sort.Strings(want)
		require.Len(t, got, len(want), "findings:\n\t%s", strings.Join(got, "\n\t"))
		for i, rel := range want {
			assert.Contains(t, got[i], "e2e mirror: "+rel+" cannot be read")
		}
	})
}
