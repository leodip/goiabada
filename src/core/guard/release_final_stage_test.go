package guard

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// releaseDockerfiles are the release images' Dockerfiles, relative to the source root.
var releaseDockerfiles = []string{"build/Dockerfile-authserver", "build/Dockerfile-adminconsole"}

// imageSmokeTest is the script CI runs on the images it builds, relative to the source root. It
// holds the same list of packages in FINAL_STAGE_PACKAGES, which it compares with each image's
// package database.
const imageSmokeTest = "build/smoke-test-images.sh"

// finalStagePackages is every Alpine package the release images' final stage holds, and the one
// list of them (#520): the base layout, keys and release files, BusyBox for the shell and the wget
// the healthchecks use, the CA bundle the servers' TLS reads, and musl. Sorted, as the package-set
// check compares it with the package database's names through sort.
var finalStagePackages = []string{
	"alpine-baselayout", "alpine-baselayout-data", "alpine-keys", "alpine-release",
	"busybox", "busybox-binsh", "ca-certificates-bundle", "musl",
}

const (
	// stripCommand is the one instruction that leaves the final stage with finalStagePackages: it
	// upgrades Alpine's packages, adds the CA bundle, which --purge would otherwise remove as an
	// orphaned dependency of apk-tools, and deletes the package manager, the OpenSSL and zlib it
	// links, and the helpers nothing runs.
	stripCommand = "RUN apk upgrade --no-cache && apk add --no-cache ca-certificates-bundle && " +
		"apk --no-cache --purge del apk-tools ssl_client scanelf musl-utils"
	// smokeTestPackagesPrefix opens the smoke test's line declaring its list.
	smokeTestPackagesPrefix = "FINAL_STAGE_PACKAGES=("
)

// packageSetCheck is the instruction directly after the strip that fails each platform's build of
// the final stage whose package database cannot be read, lists any package but finalStagePackages
// or lacks one, or that has no CA bundle: the release builds amd64 and arm64 from one Dockerfile,
// and the smoke test runs on CI's amd64 images alone.
var packageSetCheck = `RUN [ -r /lib/apk/db/installed ] || { echo "unable to read the package database" >&2; exit 1; }; ` +
	`packages="$(awk '/^P:/ { print substr($0, 3) }' /lib/apk/db/installed | sort | xargs)"; ` +
	`expected="` + strings.Join(finalStagePackages, " ") + `"; ` +
	`[ "$packages" = "$expected" ] || { echo "the final stage holds $packages, where it must hold exactly $expected" >&2; exit 1; }; ` +
	`[ -f /etc/ssl/certs/ca-certificates.crt ] || { echo "the final stage has no /etc/ssl/certs/ca-certificates.crt" >&2; exit 1; }`

// dockerInstruction is one instruction of a Dockerfile as Docker reads it: the text with its
// continuation lines joined and the comment lines inside a continuation dropped, and the comment
// lines directly above it, with no blank line between.
type dockerInstruction struct {
	text     string
	comments []string
}

var (
	// escapeDirective is the parser directive that changes the continuation character.
	escapeDirective = regexp.MustCompile(`(?i)^#\s*escape\s*=`)
	// checkedList is the list an altered package-set check compares the package database with.
	checkedList = regexp.MustCompile(`expected="([^"]*)"`)
)

// dockerInstructions splits a Dockerfile into its instructions as Docker does without heredocs and
// with the default escape character: a line ending in a backslash continues the instruction, and a
// comment line or an empty line inside a continuation is dropped. What it cannot read as Docker
// does, a heredoc or an escape directive, it reports as unparseable rather than guess at: BuildKit
// keeps a heredoc's terminator untrimmed and an escape directive can turn a backtick into the
// continuation, and either can make an "apk" line read as an instruction here while Docker reads
// it as file content or an argument (#542).
func dockerInstructions(src string) ([]dockerInstruction, string) {
	var out []dockerInstruction
	var comments []string
	continuing := false
	for _, raw := range strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(raw)
		if strings.HasPrefix(trimmed, "#") && escapeDirective.MatchString(trimmed) {
			return nil, "sets the escape directive"
		}
		switch {
		case continuing:
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			current := &out[len(out)-1]
			current.text += " " + strings.TrimSpace(strings.TrimSuffix(trimmed, "\\"))
		case trimmed == "":
			comments = nil
			continue
		case strings.HasPrefix(trimmed, "#"):
			comments = append(comments, trimmed)
			continue
		default:
			out = append(out, dockerInstruction{text: strings.TrimSpace(strings.TrimSuffix(trimmed, "\\")), comments: comments})
			comments = nil
		}
		continuing = strings.HasSuffix(trimmed, "\\")
		// Any "<<" is refused, a heredoc of whatever delimiter BuildKit accepts, digits included,
		// and a here-string with it.
		if strings.Contains(trimmed, "<<") {
			return nil, "uses a heredoc, or << in some other form"
		}
	}
	return out, ""
}

// finalStageFindings is every way the release Dockerfiles under root, and the smoke test beside
// them, disagree with the final stage #520 holds them to: the strip, then directly the package-set
// check, both in the final stage, and finalStagePackages the one list of what it keeps. It reads
// instructions as Docker does, so what counts is an instruction of the final stage, not a line that
// looks like one.
func finalStageFindings(root string) ([]string, error) {
	var findings []string
	smokeList, err := smokeTestPackages(filepath.Join(root, imageSmokeTest))
	if err != nil {
		return nil, err
	}
	switch {
	case smokeList == nil:
		findings = append(findings, imageSmokeTest+" declares no "+smokeTestPackagesPrefix+"...) line, so it "+
			"cannot hold CI's images to the packages the Dockerfiles keep: it must list exactly "+strings.Join(finalStagePackages, " "))
	case !slices.Equal(smokeList, finalStagePackages):
		findings = append(findings, imageSmokeTest+" lists "+strings.Join(smokeList, " ")+", where the release "+
			"Dockerfiles keep exactly "+strings.Join(finalStagePackages, " ")+": the list is one, the same in both "+
			"Dockerfiles and the smoke test")
	}

	for _, rel := range releaseDockerfiles {
		src, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			return nil, errs.Wrapf(err, "reading %s", rel)
		}
		instructions, unparseable := dockerInstructions(string(src))
		if unparseable != "" {
			findings = append(findings, rel+" "+unparseable+", which this test does not parse the way Docker does, "+
				"so it cannot tell whether the final stage really strips its packages: write the release Dockerfiles without it")
			continue
		}
		finalFrom := -1
		for i, in := range instructions {
			if strings.HasPrefix(strings.ToUpper(in.text), "FROM ") {
				finalFrom = i
			}
		}
		if finalFrom < 0 {
			return nil, errs.Errorf("%s has no FROM instruction", rel)
		}
		var apkRuns, checks, alteredChecks []int
		strippedBuildStage := false
		for i, in := range instructions {
			switch {
			case in.text == packageSetCheck:
				checks = append(checks, i)
			case strings.Contains(in.text, "/lib/apk/db/installed"):
				alteredChecks = append(alteredChecks, i)
			case strings.Contains(in.text, "apk "):
				if i > finalFrom {
					apkRuns = append(apkRuns, i)
				} else if in.text == stripCommand {
					strippedBuildStage = true
				}
			}
		}

		// The strip: exactly one apk instruction in the final stage, and that one exactly stripCommand.
		strip := -1
		switch {
		case len(apkRuns) == 0 && strippedBuildStage:
			findings = append(findings, rel+" strips a build stage, which never reaches the image: move "+
				stripCommand+" to the final stage")
		case len(apkRuns) == 0:
			findings = append(findings, rel+" does not strip its final stage: it must run "+stripCommand)
		case len(apkRuns) > 1:
			findings = append(findings, rel+" runs apk in more than one instruction of its final stage, where the "+
				"strip must be the only one: "+stripCommand)
		default:
			strip = apkRuns[0]
			if text := instructions[strip].text; text != stripCommand {
				findings = append(findings, rel+" "+stripDiagnosis(text)+": the instruction must be exactly "+stripCommand)
			}
		}

		// The package-set check: exactly once, in the final stage, directly after the strip.
		switch {
		case len(checks) == 0 && len(alteredChecks) > 0:
			if m := checkedList.FindStringSubmatch(instructions[alteredChecks[0]].text); m != nil &&
				!slices.Equal(strings.Fields(m[1]), finalStagePackages) {
				findings = append(findings, rel+"'s package-set check lists "+m[1]+", where the final stage keeps "+
					"exactly "+strings.Join(finalStagePackages, " ")+": the list is one, the same in both "+
					"Dockerfiles and the smoke test")
			} else {
				findings = append(findings, rel+" runs an altered package-set check: it must be exactly the "+
					"instruction packageSetCheck names")
			}
		case len(checks) == 0:
			findings = append(findings, rel+" does not check its package set and CA bundle in its final stage: it "+
				"must run the check packageSetCheck names, which fails each platform's build that holds any other "+
				"package or no CA bundle")
		case len(checks) > 1:
			findings = append(findings, rel+" checks its package set more than once: keep the one in the final stage")
		case checks[0] < finalFrom:
			findings = append(findings, rel+" checks its package set in a build stage, which never reaches the image: "+
				"move the check to the final stage")
		case strip >= 0 && checks[0] != strip+1:
			findings = append(findings, rel+" does not check its package set directly after the strip, where the "+
				"check sees what the strip left")
		}
	}
	return findings, nil
}

// stripDiagnosis says how an apk instruction differs from stripCommand, as precisely as its shape
// allows: the CA bundle not added before the delete, a package added beside it, a package left
// undeleted or deleted beyond the four.
func stripDiagnosis(text string) string {
	steps := strings.Split(strings.TrimPrefix(text, "RUN "), "&&")
	for i := range steps {
		steps[i] = strings.TrimSpace(steps[i])
	}
	if steps[0] != "apk upgrade --no-cache" {
		return "runs " + text
	}
	added, deleted := "", ""
	addAt, deleteAt := -1, -1
	for i, step := range steps {
		if rest, ok := strings.CutPrefix(step, "apk add --no-cache "); ok && addAt < 0 {
			added, addAt = rest, i
		}
		if rest, ok := strings.CutPrefix(step, "apk --no-cache --purge del "); ok && deleteAt < 0 {
			deleted, deleteAt = rest, i
		}
	}
	if deleteAt >= 0 && (addAt < 0 || addAt > deleteAt || !slices.Contains(strings.Fields(added), "ca-certificates-bundle")) {
		return "does not add ca-certificates-bundle before the delete, so --purge removes the CA bundle the servers' TLS reads"
	}
	if len(steps) != 3 || addAt != 1 || deleteAt != 2 {
		return "runs " + text
	}
	if extra := slices.DeleteFunc(strings.Fields(added), func(p string) bool { return p == "ca-certificates-bundle" }); len(extra) > 0 {
		return "adds " + strings.Join(extra, " ") + ", which the final stage must not hold"
	}
	want := []string{"apk-tools", "ssl_client", "scanelf", "musl-utils"}
	var left, beyond []string
	for _, p := range want {
		if !slices.Contains(strings.Fields(deleted), p) {
			left = append(left, p)
		}
	}
	for _, p := range strings.Fields(deleted) {
		if !slices.Contains(want, p) {
			beyond = append(beyond, p)
		}
	}
	switch {
	case len(left) > 0:
		return "leaves " + strings.Join(left, " ") + " installed"
	case len(beyond) > 0:
		return "also deletes " + strings.Join(beyond, " ")
	}
	return "runs " + text
}

// smokeTestPackages reads the list the smoke test declares, nil when it declares none.
func smokeTestPackages(path string) ([]string, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, errs.Wrapf(err, "reading %s", path)
	}
	for _, line := range strings.Split(strings.ReplaceAll(string(src), "\r\n", "\n"), "\n") {
		if list, ok := strings.CutPrefix(line, smokeTestPackagesPrefix); ok {
			if list, ok = strings.CutSuffix(strings.TrimRight(list, " \t"), ")"); ok {
				return strings.Fields(list), nil
			}
		}
	}
	return nil, nil
}

func TestReleaseDockerfiles_TheFinalStageHoldsTheEightPackages(t *testing.T) {
	findings, err := finalStageFindings(SourceRoot(t))
	require.NoError(t, err)
	for _, f := range findings {
		t.Error(f)
	}
}

// The finder over fixture trees, one case per way a final stage can be wrong, and the ways it is
// right. joined is what each case's findings say, together, since several can come from one mistake.
func TestFinalStageFindings(t *testing.T) {
	const build = "FROM golang:1.27.3-alpine AS build\nRUN go build ./...\n\n"
	const final = "FROM alpine:3.24 AS final\nWORKDIR /app\n"
	// The strip and the check as the release Dockerfiles write them, over several lines each.
	const strip = "RUN apk upgrade --no-cache \\\n" +
		"    && apk add --no-cache ca-certificates-bundle \\\n" +
		"    && apk --no-cache --purge del apk-tools ssl_client scanelf musl-utils\n"
	const check = `RUN [ -r /lib/apk/db/installed ] || { echo "unable to read the package database" >&2; exit 1; }; \` + "\n" +
		`    packages="$(awk '/^P:/ { print substr($0, 3) }' /lib/apk/db/installed | sort | xargs)"; \` + "\n" +
		`    expected="alpine-baselayout alpine-baselayout-data alpine-keys alpine-release busybox busybox-binsh ca-certificates-bundle musl"; \` + "\n" +
		`    [ "$packages" = "$expected" ] || { echo "the final stage holds $packages, where it must hold exactly $expected" >&2; exit 1; }; \` + "\n" +
		`    [ -f /etc/ssl/certs/ca-certificates.crt ] || { echo "the final stage has no /etc/ssl/certs/ca-certificates.crt" >&2; exit 1; }` + "\n"
	const user = "RUN addgroup -S -g 10001 goiabada\nUSER 10001:10001\n"
	const smoke = "#!/bin/bash\nFINAL_STAGE_PACKAGES=(alpine-baselayout alpine-baselayout-data alpine-keys alpine-release " +
		"busybox busybox-binsh ca-certificates-bundle musl)\n"
	tree := func(t *testing.T, dockerfile, smokeTest string) string {
		t.Helper()
		root := t.TempDir()
		writeFixture(t, root, imageSmokeTest, smokeTest)
		for _, rel := range releaseDockerfiles {
			writeFixture(t, root, rel, dockerfile)
		}
		return root
	}
	joinedWith := func(t *testing.T, dockerfile, smokeTest string) string {
		t.Helper()
		got, err := finalStageFindings(tree(t, dockerfile, smokeTest))
		require.NoError(t, err)
		return strings.Join(got, "\n")
	}
	joined := func(t *testing.T, dockerfile string) string {
		t.Helper()
		return joinedWith(t, dockerfile, smoke)
	}
	// replaced is the strip with one of its packages' text replaced, to alter one step of it.
	replaced := func(old, new string) string { return strings.Replace(strip, old, new, 1) }

	t.Run("the strip and its check in the final stage", func(t *testing.T) {
		assert.Empty(t, joined(t, build+final+strip+check+user))
	})
	t.Run("the strip and its check each on one line", func(t *testing.T) {
		assert.Empty(t, joined(t, build+final+stripCommand+"\n"+packageSetCheck+"\n"+user))
	})
	t.Run("the same, written with CRLF line endings", func(t *testing.T) {
		assert.Empty(t, joinedWith(t, strings.ReplaceAll(build+final+strip+check+user, "\n", "\r\n"),
			strings.ReplaceAll(smoke, "\n", "\r\n")))
	})
	t.Run("a lowercase from opening the final stage", func(t *testing.T) {
		assert.Empty(t, joined(t, build+"from alpine:3.24 as final\n"+strip+check+user))
	})
	t.Run("a stock final stage, with neither", func(t *testing.T) {
		got := joined(t, build+final+user)
		assert.Contains(t, got, "does not strip its final stage")
		assert.Contains(t, got, "does not check its package set and CA bundle")
	})
	t.Run("#542's upgrade and zlib check in place of both", func(t *testing.T) {
		got := joined(t, build+final+"RUN apk upgrade --no-cache\n"+
			`RUN zlib="$(awk '/^P:/ { n++ }' /lib/apk/db/installed)"`+"\n"+user)
		assert.Contains(t, got, "runs RUN apk upgrade --no-cache: the instruction must be exactly")
		assert.Contains(t, got, "runs an altered package-set check")
	})
	t.Run("the strip without its check", func(t *testing.T) {
		assert.Contains(t, joined(t, build+final+strip+user), "does not check its package set and CA bundle")
	})
	t.Run("the check without the strip", func(t *testing.T) {
		assert.Contains(t, joined(t, build+final+check+user), "does not strip its final stage")
	})
	t.Run("the upgrade gone from the strip", func(t *testing.T) {
		got := joined(t, build+final+replaced("apk upgrade --no-cache \\\n    && ", "")+check+user)
		assert.Contains(t, got, "runs RUN apk add --no-cache ca-certificates-bundle")
	})
	t.Run("the CA bundle not added", func(t *testing.T) {
		got := joined(t, build+final+replaced("    && apk add --no-cache ca-certificates-bundle \\\n", "")+check+user)
		assert.Contains(t, got, "does not add ca-certificates-bundle before the delete")
	})
	t.Run("the CA bundle added after the delete", func(t *testing.T) {
		const late = "RUN apk upgrade --no-cache \\\n" +
			"    && apk --no-cache --purge del apk-tools ssl_client scanelf musl-utils \\\n" +
			"    && apk add --no-cache ca-certificates-bundle\n"
		assert.Contains(t, joined(t, build+final+late+check+user), "does not add ca-certificates-bundle before the delete")
	})
	t.Run("a package added beside the CA bundle", func(t *testing.T) {
		got := joined(t, build+final+replaced("ca-certificates-bundle", "ca-certificates-bundle curl")+check+user)
		assert.Contains(t, got, "adds curl, which the final stage must not hold")
	})
	t.Run("a package left undeleted", func(t *testing.T) {
		got := joined(t, build+final+replaced(" ssl_client", "")+check+user)
		assert.Contains(t, got, "leaves ssl_client installed")
	})
	t.Run("a package deleted beyond the four", func(t *testing.T) {
		got := joined(t, build+final+replaced("musl-utils", "musl-utils busybox")+check+user)
		assert.Contains(t, got, "also deletes busybox")
	})
	t.Run("the delete without --purge", func(t *testing.T) {
		got := joined(t, build+final+replaced("--purge ", "")+check+user)
		assert.Contains(t, got, "the instruction must be exactly "+stripCommand)
	})
	t.Run("a package added in another instruction", func(t *testing.T) {
		got := joined(t, build+final+"RUN apk add --no-cache curl\n"+strip+check+user)
		assert.Contains(t, got, "runs apk in more than one instruction of its final stage")
	})
	t.Run("the strip twice", func(t *testing.T) {
		assert.Contains(t, joined(t, build+final+strip+check+strip+user), "more than one instruction")
	})
	t.Run("the strip and its check in a build stage only", func(t *testing.T) {
		got := joined(t, "FROM golang:1.27.3-alpine AS build\n"+strip+check+final+user)
		assert.Contains(t, got, "strips a build stage")
		assert.Contains(t, got, "checks its package set in a build stage")
	})
	t.Run("the check not directly after the strip", func(t *testing.T) {
		assert.Contains(t, joined(t, build+final+strip+"WORKDIR /x\n"+check+user), "directly after the strip")
	})
	t.Run("the check before the strip", func(t *testing.T) {
		assert.Contains(t, joined(t, build+final+check+strip+user), "directly after the strip")
	})
	t.Run("the check twice", func(t *testing.T) {
		assert.Contains(t, joined(t, build+final+strip+check+check+user), "more than once")
	})
	t.Run("the check altered", func(t *testing.T) {
		altered := strings.Replace(check, "[ -f /etc/ssl/certs/ca-certificates.crt ]", "true", 1)
		assert.Contains(t, joined(t, build+final+strip+altered+user), "runs an altered package-set check")
	})
	t.Run("the check's list with a ninth package", func(t *testing.T) {
		altered := strings.Replace(check, " musl\"", " musl zlib\"", 1)
		got := joined(t, build+final+strip+altered+user)
		assert.Contains(t, got, "package-set check lists alpine-baselayout alpine-baselayout-data alpine-keys "+
			"alpine-release busybox busybox-binsh ca-certificates-bundle musl zlib")
	})
	t.Run("the smoke test's list differing from the Dockerfiles'", func(t *testing.T) {
		got := joinedWith(t, build+final+strip+check+user, strings.Replace(smoke, " musl)", ")", 1))
		assert.Contains(t, got, imageSmokeTest+" lists alpine-baselayout alpine-baselayout-data alpine-keys "+
			"alpine-release busybox busybox-binsh ca-certificates-bundle, where")
	})
	t.Run("the smoke test declaring no list", func(t *testing.T) {
		got := joinedWith(t, build+final+strip+check+user, "#!/bin/bash\n")
		assert.Contains(t, got, imageSmokeTest+" declares no FINAL_STAGE_PACKAGES=(...) line")
	})
	t.Run("the strip absorbed by a continuation", func(t *testing.T) {
		got := joined(t, build+final+"RUN echo safe \\\n"+strip+check+user)
		assert.Contains(t, got, "runs RUN echo safe RUN apk upgrade",
			"Docker reads the strip as arguments to echo")
	})
	t.Run("the strip as a heredoc's content", func(t *testing.T) {
		assert.Contains(t, joined(t, build+final+"COPY <<EOF /tmp/note\n"+strip+"EOF\n"+check+user),
			"uses a heredoc")
	})
	t.Run("the strip as the content of a heredoc with a numeric delimiter", func(t *testing.T) {
		assert.Contains(t, joined(t, build+final+"COPY <<1 /tmp/note\n"+strip+"1\n"+check+user),
			"uses a heredoc")
	})
	t.Run("the strip after a terminator BuildKit doesn't recognize", func(t *testing.T) {
		// "EOF " with a trailing space does not close the heredoc for BuildKit, so the strip after it
		// is still the file's content.
		assert.Contains(t, joined(t, build+final+"COPY <<EOF /tmp/note\nEOF \n"+strip+"EOF\n"+check+user),
			"uses a heredoc")
	})
	t.Run("any heredoc, with the real strip after it", func(t *testing.T) {
		assert.Contains(t, joined(t, build+final+"COPY <<EOF /tmp/note\nnote\nEOF\n"+strip+check+user),
			"uses a heredoc", "a heredoc is refused outright rather than parsed")
	})
	t.Run("the escape directive turning a backtick into the continuation", func(t *testing.T) {
		assert.Contains(t, joined(t, "# escape=`\n"+build+final+"RUN echo safe `\n"+strip+check+user),
			"sets the escape directive")
	})
	t.Run("a tree it cannot read", func(t *testing.T) {
		_, err := finalStageFindings(t.TempDir())
		require.Error(t, err)
	})
	t.Run("a smoke test but no Dockerfiles", func(t *testing.T) {
		root := t.TempDir()
		writeFixture(t, root, imageSmokeTest, smoke)
		_, err := finalStageFindings(root)
		require.Error(t, err)
	})
}
