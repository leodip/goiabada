package testutil

// Rule 9 reads every shipped main the way its release build compiles it: the production tag set and
// every other tag free, on each of releaseTargets. Both halves of that are a premise about files the
// guard never opens, the scripts and Dockerfiles a release builds with, so this test opens them: every
// go build in them sets production, and each cross-compile script builds for exactly the platforms
// releaseTargets lists (#463).
//
// It is a test rather than a finding inside AssertArchitecture, so core's tier is the one that runs
// it; CI's Unit job runs that tier on every pull request. The reader is driven over fixture text in
// both directions and through a file holding no go build before the real tree is trusted to it,
// because the real tree satisfies it by construction and passing proves nothing on its own.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// releaseBuild is one file a release builds with, relative to the source root: the shipped mains its
// go build commands compile, and whether it is a cross-compile script, whose build_platform calls are
// held to releaseTargets.
type releaseBuild struct {
	file      string
	mains     []string
	platforms bool
}

// releaseBuilds are the files release.yml builds every shipped binary with: the servers'
// cross-compile script and the two Dockerfiles the published images are built from, and the setup
// wizard's cross-compile script. The mains are spelled out rather than read from shippedMains, so
// that a fourth shipped main fails this test until its release build is listed here.
var releaseBuilds = []releaseBuild{
	{file: "build/build-binaries.sh", mains: []string{authserverMain, adminconsoleMain}, platforms: true},
	{file: "build/Dockerfile-authserver", mains: []string{authserverMain}},
	{file: "build/Dockerfile-adminconsole", mains: []string{adminconsoleMain}},
	{file: "cmd/goiabada-setup/build-binaries.sh", mains: []string{setupMain}, platforms: true},
}

// goBuild is one go build command found in a release-build file: the line it starts on, and whether
// it sets the production tag.
type goBuild struct {
	line       int
	production bool
}

// logicalLine is a command line as the shell reads it: physical lines joined at a trailing
// backslash, with comments removed, split into words.
type logicalLine struct {
	line  int
	words []string
}

// logicalLines splits a script or Dockerfile into logical lines. A Dockerfile's RUN hands its line to
// the shell, so the one reading serves both.
func logicalLines(text string) []logicalLine {
	var out []logicalLine
	var words []string
	open := false
	start := 0
	for i, raw := range strings.Split(text, "\n") {
		content := strings.TrimRight(stripShellComment(raw), " \t\r")
		continued := strings.HasSuffix(content, `\`)
		content = strings.TrimSuffix(content, `\`)
		if !open {
			start = i + 1
			open = true
		}
		words = append(words, strings.Fields(content)...)
		if continued {
			continue
		}
		if len(words) > 0 {
			out = append(out, logicalLine{line: start, words: words})
		}
		words = nil
		open = false
	}
	if len(words) > 0 {
		out = append(out, logicalLine{line: start, words: words})
	}
	return out
}

// stripShellComment drops a comment from one physical line: a # beginning a word starts one, and it
// runs to the end of the line. Both cross-compile scripts mention go build in their comments, which a
// reader matching them would report as builds.
func stripShellComment(line string) string {
	wordStart := true
	for i, r := range line {
		if r == '#' && wordStart {
			return line[:i]
		}
		wordStart = r == ' ' || r == '\t'
	}
	return line
}

// commandSeparators end the words of one command on a logical line.
var commandSeparators = map[string]bool{"&&": true, "||": true, ";": true, "|": true, "&": true, ")": true}

// goBuilds returns every go build command in a release-build file, in order.
func goBuilds(text string) []goBuild {
	var out []goBuild
	for _, l := range logicalLines(text) {
		for i := 0; i+1 < len(l.words); i++ {
			if l.words[i] != "go" || l.words[i+1] != "build" {
				continue
			}
			var args []string
			for _, w := range l.words[i+2:] {
				if commandSeparators[w] {
					break
				}
				if trimmed := strings.TrimRight(w, ";)"); trimmed != w {
					args = append(args, trimmed)
					break
				}
				args = append(args, w)
			}
			out = append(out, goBuild{line: l.line, production: setsProductionTag(args)})
		}
	}
	return out
}

// setsProductionTag reports whether a go build's arguments set the production tag. The go command
// keeps the last -tags it is given, so the last one is the one read.
func setsProductionTag(args []string) bool {
	value := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-tags" || a == "--tags":
			if i+1 < len(args) {
				value = args[i+1]
				i++
			}
		case strings.HasPrefix(a, "-tags="):
			value = strings.TrimPrefix(a, "-tags=")
		case strings.HasPrefix(a, "--tags="):
			value = strings.TrimPrefix(a, "--tags=")
		}
	}
	for _, tag := range strings.Split(strings.Trim(value, `"'`), ",") {
		if tag == "production" {
			return true
		}
	}
	return false
}

// buildPlatforms returns the "goos/goarch" pairs a cross-compile script's build_platform calls name,
// sorted and without repeats. The function's own definition is not a call, however it is spaced:
// build_platform() is not the name, and in build_platform () the parentheses are not a platform.
func buildPlatforms(text string) []string {
	seen := map[string]bool{}
	for _, l := range logicalLines(text) {
		if len(l.words) < 3 || l.words[0] != "build_platform" || strings.HasPrefix(l.words[1], "(") {
			continue
		}
		seen[strings.Trim(l.words[1], `"'`)+"/"+strings.Trim(l.words[2], `"'`)] = true
	}
	return sortedKeys(seen)
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// checkReleaseBuilds holds the release-build files under root to the shipped mains and release
// targets rule 9 reads, and returns what does not hold, sorted.
func checkReleaseBuilds(root string, builds []releaseBuild, mains []string, targets []struct{ goos, goarch string }) []string {
	var findings []string

	shipped := map[string]bool{}
	for _, m := range mains {
		shipped[m] = true
	}
	built := map[string]bool{}
	for _, b := range builds {
		for _, m := range b.mains {
			built[m] = true
			if !shipped[m] {
				findings = append(findings, fmt.Sprintf("release builds: %s is listed as building %s, which is not a shipped main", b.file, m))
			}
		}
	}
	for _, m := range mains {
		if !built[m] {
			findings = append(findings, fmt.Sprintf("release builds: no release build is listed for the shipped main %s", m))
		}
	}

	want := map[string]bool{}
	for _, t := range targets {
		want[t.goos+"/"+t.goarch] = true
	}

	for _, b := range builds {
		src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(b.file)))
		if err != nil {
			findings = append(findings, fmt.Sprintf("release builds: %s cannot be read: %v", b.file, err))
			continue
		}
		text := string(src)

		cmds := goBuilds(text)
		if len(cmds) == 0 {
			findings = append(findings, fmt.Sprintf("release builds: %s holds no go build", b.file))
		}
		for _, c := range cmds {
			if !c.production {
				findings = append(findings, fmt.Sprintf("release builds: %s:%d runs go build without the production tag", b.file, c.line))
			}
		}

		if !b.platforms {
			continue
		}
		got := map[string]bool{}
		for _, p := range buildPlatforms(text) {
			got[p] = true
			if !want[p] {
				findings = append(findings, fmt.Sprintf("release builds: %s builds for %s, which releaseTargets does not list", b.file, p))
			}
		}
		for _, p := range sortedKeys(want) {
			if !got[p] {
				findings = append(findings, fmt.Sprintf("release builds: %s never builds for %s, which releaseTargets lists", b.file, p))
			}
		}
	}

	sort.Strings(findings)
	return findings
}

// ---- the reader, over fixture text ----------------------------------------------------------

func TestReleaseBuilds_GoBuildCommands(t *testing.T) {
	cases := []struct {
		name string
		text string
		want []goBuild
	}{
		{"a go build without the tag is reported", "GOOS=linux go build -o x ./cmd/a\n", []goBuild{{1, false}}},
		{"one with -tags=production passes", "GOOS=linux go build -tags=production -o x ./cmd/a\n", []goBuild{{1, true}}},
		{"the tag may be its own word", "go build -tags production .\n", []goBuild{{1, true}}},
		{"the tag may be one of a list", "go build -tags=netgo,production .\n", []goBuild{{1, true}}},
		{"a tag that only begins with production is not it", "go build -tags=productionish .\n", []goBuild{{1, false}}},
		{"the last -tags is the one the go command keeps", "go build -tags=production -tags=dev .\n", []goBuild{{1, false}}},
		{"a Dockerfile's RUN is read like a script line", "FROM golang AS build\nRUN go build -buildvcs=false -tags=production -o ../../bin/a ./cmd/a\n", []goBuild{{2, true}}},
		{
			"a command split across backslash-continued lines is read whole",
			"    GOOS=$os go build -v \\\n        -tags=production \\\n        -o out \\\n        .\n",
			[]goBuild{{1, true}},
		},
		{
			"the continued lines without the tag are reported at the line the command starts",
			"echo building\n    GOOS=$os go build -v \\\n        -o out \\\n        .\n",
			[]goBuild{{2, false}},
		},
		{
			"a go build mentioned in a comment is not a command",
			"# without set -e, a failed go build exited 0\n    # catches a failing go build\ngo build -tags=production .\n",
			[]goBuild{{3, true}},
		},
		{"a comment after the command is not part of it", "go build . # -tags=production\n", []goBuild{{1, false}}},
		{
			"a separator ends one command and the next is read on its own",
			"( cd a && go build -tags=production ./x ) && go build ./y\n",
			[]goBuild{{1, true}, {1, false}},
		},
		{"a file holding no go build yields nothing", "#!/bin/bash\n# go build\necho go-build\n", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, goBuilds(c.text))
		})
	}
}

func TestReleaseBuilds_BuildPlatforms(t *testing.T) {
	script := `build_platform() {
    local os=$1
}
build_platform() { echo "$1"; }
build_platform () {
    local os=$1
}
# build_platform "plan9" "386" ""
build_platform "linux" "amd64" ""
build_platform darwin arm64 ""
build_platform "linux" "amd64" ""
`
	assert.Equal(t, []string{"darwin/arm64", "linux/amd64"}, buildPlatforms(script))
}

// ---- the check, over fixture trees ----------------------------------------------------------

// releaseFixtureTargets is the release-target list the fixture scripts are held to.
var releaseFixtureTargets = []struct{ goos, goarch string }{{"linux", "amd64"}, {"windows", "amd64"}}

// releaseFixtureMains is the shipped-mains list the fixture builds are held to.
var releaseFixtureMains = []string{"one/cmd/one", "two/cmd/two"}

// releaseFixtureBuilds lists a cross-compile script building both fixture mains and a Dockerfile
// building the first.
var releaseFixtureBuilds = []releaseBuild{
	{file: "build/build.sh", mains: []string{"one/cmd/one", "two/cmd/two"}, platforms: true},
	{file: "build/Dockerfile-one", mains: []string{"one/cmd/one"}},
}

const (
	cleanReleaseScript = `#!/bin/bash
# go build in a comment is not a command.
build_platform() {
    ( cd one && GOOS=$1 GOARCH=$2 go build -v \
        -tags=production \
        -o out ./cmd/one )
    ( cd two && GOOS=$1 GOARCH=$2 go build -tags=production -o out ./cmd/two )
}
build_platform "linux" "amd64" ""
build_platform "windows" "amd64" ".exe"
`
	cleanReleaseDockerfile = "FROM golang AS build\nRUN go build -tags=production -o bin/one ./cmd/one\n"
)

// writeReleaseFixture writes the given files under a temp source root, starting from the clean
// script and Dockerfile, and returns the root.
func writeReleaseFixture(t *testing.T, files map[string]string) string {
	t.Helper()

	root := t.TempDir()
	all := map[string]string{
		"build/build.sh":       cleanReleaseScript,
		"build/Dockerfile-one": cleanReleaseDockerfile,
	}
	for rel, src := range files {
		all[rel] = src
	}
	for rel, src := range all {
		if src == "" {
			continue
		}
		path := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(src), 0o644))
	}
	return root
}

func TestReleaseBuilds_Check(t *testing.T) {
	t.Run("release builds that set the tag and build for every target pass", func(t *testing.T) {
		root := writeReleaseFixture(t, nil)
		assert.Empty(t, checkReleaseBuilds(root, releaseFixtureBuilds, releaseFixtureMains, releaseFixtureTargets))
	})

	t.Run("a go build without the tag fails, naming its file and line", func(t *testing.T) {
		root := writeReleaseFixture(t, map[string]string{
			"build/build.sh": strings.Replace(cleanReleaseScript, "go build -tags=production -o out ./cmd/two", "go build -o out ./cmd/two", 1),
		})
		assertFindings(t, checkReleaseBuilds(root, releaseFixtureBuilds, releaseFixtureMains, releaseFixtureTargets),
			"release builds: build/build.sh:7 runs go build without the production tag")
	})

	t.Run("a Dockerfile losing the tag fails", func(t *testing.T) {
		root := writeReleaseFixture(t, map[string]string{
			"build/Dockerfile-one": "FROM golang AS build\nRUN go build -o bin/one ./cmd/one\n",
		})
		assertFindings(t, checkReleaseBuilds(root, releaseFixtureBuilds, releaseFixtureMains, releaseFixtureTargets),
			"release builds: build/Dockerfile-one:2 runs go build without the production tag")
	})

	t.Run("a listed file that is missing fails", func(t *testing.T) {
		root := writeReleaseFixture(t, map[string]string{"build/Dockerfile-one": ""})
		assertFindings(t, checkReleaseBuilds(root, releaseFixtureBuilds, releaseFixtureMains, releaseFixtureTargets),
			"release builds: build/Dockerfile-one cannot be read")
	})

	t.Run("a listed file holding no go build fails", func(t *testing.T) {
		root := writeReleaseFixture(t, map[string]string{
			"build/Dockerfile-one": "FROM golang AS build\n# RUN go build -tags=production ./cmd/one\nRUN go-build ./cmd/one\n",
		})
		assertFindings(t, checkReleaseBuilds(root, releaseFixtureBuilds, releaseFixtureMains, releaseFixtureTargets),
			"release builds: build/Dockerfile-one holds no go build")
	})

	t.Run("a script building for a platform the release targets lack fails", func(t *testing.T) {
		root := writeReleaseFixture(t, map[string]string{
			"build/build.sh": cleanReleaseScript + "build_platform \"freebsd\" \"amd64\" \"\"\n",
		})
		assertFindings(t, checkReleaseBuilds(root, releaseFixtureBuilds, releaseFixtureMains, releaseFixtureTargets),
			"release builds: build/build.sh builds for freebsd/amd64, which releaseTargets does not list")
	})

	t.Run("release targets naming a platform the script never builds for fail", func(t *testing.T) {
		root := writeReleaseFixture(t, nil)
		targets := append(append([]struct{ goos, goarch string }{}, releaseFixtureTargets...), struct{ goos, goarch string }{"darwin", "arm64"})
		assertFindings(t, checkReleaseBuilds(root, releaseFixtureBuilds, releaseFixtureMains, targets),
			"release builds: build/build.sh never builds for darwin/arm64, which releaseTargets lists")
	})

	t.Run("a shipped main no release build is listed for fails", func(t *testing.T) {
		root := writeReleaseFixture(t, nil)
		mains := append(append([]string{}, releaseFixtureMains...), "three/cmd/three")
		assertFindings(t, checkReleaseBuilds(root, releaseFixtureBuilds, mains, releaseFixtureTargets),
			"release builds: no release build is listed for the shipped main three/cmd/three")
	})

	t.Run("a release build of a main that does not ship fails", func(t *testing.T) {
		root := writeReleaseFixture(t, nil)
		assertFindings(t, checkReleaseBuilds(root, releaseFixtureBuilds, releaseFixtureMains[:1], releaseFixtureTargets),
			"release builds: build/build.sh is listed as building two/cmd/two, which is not a shipped main")
	})
}

// ---- the real tree --------------------------------------------------------------------------

// TestReleaseBuilds_TheRealReleaseBuildsSetProduction holds this repository's release builds to the
// premise rule 9 rests on: every go build a release runs sets production, the release builds listed
// name exactly the guard's shippedMains, and both cross-compile scripts build for exactly its
// releaseTargets.
func TestReleaseBuilds_TheRealReleaseBuildsSetProduction(t *testing.T) {
	assert.Empty(t, checkReleaseBuilds(SourceRoot(t), releaseBuilds, shippedMains, releaseTargets))
}
