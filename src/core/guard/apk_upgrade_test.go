package guard

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// apkUpgradeAlpine is the Alpine minor whose image needs the release images' final stage to run
// "apk upgrade --no-cache": alpine:3.24 still ships zlib 1.3.2-r0, CVE-2026-85091, which Alpine
// fixed in 1.3.2-r1 (#542). It is the record of that need, apart from the Dockerfiles, so removing
// the line from a Dockerfile while the pinned image still needs it fails here. When
// ./version-manager.sh update moves tools.alpine past it, the test below fails until the new image
// is checked: if it carries the fix, remove the line and its marker from both Dockerfiles and set
// this to ""; if not, set this and both markers to the new minor.
const apkUpgradeAlpine = "3.24"

// releaseDockerfiles are the release images' Dockerfiles, relative to the source root.
var releaseDockerfiles = []string{"build/Dockerfile-authserver", "build/Dockerfile-adminconsole"}

const (
	// apkUpgradeCommand is the one form the line takes: no cache left in the layer.
	apkUpgradeCommand = "RUN apk upgrade --no-cache"
	// apkUpgradeMarkerPrefix opens the comment directly above it, naming the minor it is for.
	apkUpgradeMarkerPrefix = "# apk-upgrade-until-alpine: "
	// zlibFloorCheck is the instruction that fails each platform's build of the final stage whose
	// zlib is older than the fix, or whose package database it cannot read: the release builds
	// amd64 and arm64 from one Dockerfile, and the smoke test runs on CI's amd64 image alone. It
	// stays when the upgrade goes, directly after the upgrade while there is one.
	zlibFloorCheck = `RUN zlib="$(awk '/^P:/ { n++; p = substr($0, 3) } /^V:/ && p == "zlib" { v = substr($0, 3) } ` +
		`END { if (n == 0) exit 1; print v }' /lib/apk/db/installed)" || { echo "unable to read the package database" >&2; ` +
		`exit 1; }; [ -z "$zlib" ] || apk version -t "$zlib" 1.3.2-r1 | grep -qx '[=>]' || ` +
		`{ echo "zlib $zlib is older than 1.3.2-r1 (CVE-2026-85091)" >&2; exit 1; }`
)

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
)

// dockerInstructions splits a Dockerfile into its instructions as Docker does without heredocs and
// with the default escape character: a line ending in a backslash continues the instruction, and a
// comment line or an empty line inside a continuation is dropped. What it cannot read as Docker
// does, a heredoc or an escape directive, it reports as unparseable rather than guess at: BuildKit
// keeps a heredoc's terminator untrimmed and an escape directive can turn a backtick into the
// continuation, and either can make an "apk upgrade" line read as an instruction here while Docker
// reads it as file content or an argument (#542).
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

// apkUpgradeFindings is every way the release Dockerfiles under root disagree with required, the
// minor needing the upgrade ("" for none), and with tools.alpine. It reads instructions as Docker
// does, so what counts is an instruction of the final stage, not a line that looks like one.
func apkUpgradeFindings(root, required string) ([]string, error) {
	alpine, err := pinnedTool(filepath.Join(root, "authserver", "versions.yaml"), "alpine")
	if err != nil {
		return nil, err
	}
	if required != "" && alpine != required {
		return []string{"tools.alpine is now " + alpine + ", and the release images run apk upgrade for alpine:" +
			required + "'s zlib (CVE-2026-85091): check that alpine:" + alpine + " ships zlib 1.3.2-r1 or later; " +
			"if it does, remove the apk upgrade line and its marker, keeping the zlib check, from " + strings.Join(releaseDockerfiles, " and ") +
			" and set apkUpgradeAlpine to \"\", and if it doesn't, set apkUpgradeAlpine and both markers to " + alpine +
			". The image smoke test holds the built images to zlib 1.3.2-r1 either way"}, nil
	}

	var findings []string
	for _, rel := range releaseDockerfiles {
		src, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			return nil, errs.Wrapf(err, "reading %s", rel)
		}
		instructions, unparseable := dockerInstructions(string(src))
		if unparseable != "" {
			findings = append(findings, rel+" "+unparseable+", which this test does not parse the way Docker does, "+
				"so it cannot tell whether the final stage really upgrades zlib: write the release Dockerfiles without it")
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
		var upgrades, checks []int
		for i, in := range instructions {
			switch {
			case in.text == zlibFloorCheck:
				checks = append(checks, i)
			case strings.Contains(in.text, "apk upgrade"):
				upgrades = append(upgrades, i)
			}
		}
		markers := strings.Count(string(src), "apk-upgrade-until-alpine")

		// The zlib check, whatever apkUpgradeAlpine says: exactly once, in the final stage.
		switch {
		case len(checks) == 0:
			findings = append(findings, rel+" does not check its zlib in its final stage: it must run the check "+
				"zlibFloorCheck names, which fails each platform's build whose zlib is older than 1.3.2-r1, "+
				"and it stays when the apk upgrade goes")
		case len(checks) > 1:
			findings = append(findings, rel+" checks its zlib more than once: keep the one in the final stage")
		case checks[0] < finalFrom:
			findings = append(findings, rel+" checks its zlib in a build stage, which never reaches the image: "+
				"move the check to the final stage")
		}

		if required == "" {
			if len(upgrades) > 0 || markers > 0 {
				findings = append(findings, rel+" still runs apk upgrade or keeps its marker, and apkUpgradeAlpine "+
					"says no Alpine image needs it: remove both and keep the zlib check, or set apkUpgradeAlpine "+
					"to the minor that does")
			}
			continue
		}

		switch {
		case len(upgrades) == 0:
			findings = append(findings, rel+" no longer runs "+apkUpgradeCommand+" as an instruction of its final stage, "+
				"and alpine:"+required+" still ships the vulnerable zlib: put it back, with its marker, or set "+
				"apkUpgradeAlpine to \"\" once the pinned image carries the fix")
		case len(upgrades) > 1:
			findings = append(findings, rel+" runs apk upgrade in more than one instruction: keep the one in the final stage")
		default:
			in := instructions[upgrades[0]]
			if upgrades[0] < finalFrom {
				findings = append(findings, rel+" runs apk upgrade in a build stage, which never reaches the image: "+
					"move it to the final stage")
			}
			if in.text != apkUpgradeCommand {
				findings = append(findings, rel+" runs "+in.text+", where the instruction must be exactly "+
					apkUpgradeCommand+", so no package cache is left in the layer")
			}
			if len(in.comments) == 0 || in.comments[len(in.comments)-1] != apkUpgradeMarkerPrefix+required {
				findings = append(findings, rel+" has no "+apkUpgradeMarkerPrefix+required+" line directly above "+
					"its apk upgrade, so nothing in the file says when it can go")
			}
			if len(checks) == 1 && checks[0] != upgrades[0]+1 {
				findings = append(findings, rel+" does not check its zlib directly after the apk upgrade, where the "+
					"check sees what the upgrade installed")
			}
		}
		if markers > 1 {
			findings = append(findings, rel+" mentions apk-upgrade-until-alpine more than once: keep the one marker "+
				"directly above the apk upgrade")
		}
	}
	return findings, nil
}

// pinnedTool reads tools.<key> out of versions.yaml, as pinnedMockeryVersion reads tools.mockery.
func pinnedTool(versionsFile, key string) (string, error) {
	src, err := os.ReadFile(versionsFile)
	if err != nil {
		return "", errs.Wrapf(err, "reading %s", versionsFile)
	}
	inTools := false
	for _, line := range strings.Split(string(src), "\n") {
		line = strings.TrimRight(line, " \t\r")
		if line == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			inTools = strings.HasPrefix(line, "tools:")
			continue
		}
		if k, v, found := strings.Cut(strings.TrimSpace(line), ":"); inTools && found && k == key {
			v, _, _ = strings.Cut(v, " #")
			if pin := strings.Trim(strings.TrimSpace(v), `"'`); pin != "" {
				return pin, nil
			}
		}
	}
	return "", errs.Errorf("tools.%s in %s has no value", key, versionsFile)
}

func TestReleaseDockerfiles_TheApkUpgradeGoesWithItsAlpineMinor(t *testing.T) {
	findings, err := apkUpgradeFindings(SourceRoot(t), apkUpgradeAlpine)
	require.NoError(t, err)
	for _, f := range findings {
		t.Error(f)
	}
}

// The finder over fixture trees, one case per way the upgrade can be wrong, and the ways it is right.
// joined is what each case's findings say, together, since several can come from one mistake.
func TestApkUpgradeFindings(t *testing.T) {
	const build = "FROM golang:1.27.2-alpine AS build\nRUN go build ./...\n\n"
	const final = "FROM alpine:3.24 AS final\nWORKDIR /app\n"
	const marker = "# apk-upgrade-until-alpine: 3.24\n"
	const upgrade = "RUN apk upgrade --no-cache\n"
	check := zlibFloorCheck + "\n"
	marked := marker + upgrade + check
	const user = "RUN addgroup -S -g 10001 goiabada\nUSER 10001:10001\n"
	tree := func(t *testing.T, alpine, dockerfile string) string {
		t.Helper()
		root := t.TempDir()
		writeFixture(t, root, "authserver/versions.yaml", "# comment\ntools:\n  alpine: \""+alpine+"\" # pinned\n")
		for _, rel := range releaseDockerfiles {
			writeFixture(t, root, rel, dockerfile)
		}
		return root
	}
	joined := func(t *testing.T, alpine, required, dockerfile string) string {
		t.Helper()
		got, err := apkUpgradeFindings(tree(t, alpine, dockerfile), required)
		require.NoError(t, err)
		return strings.Join(got, "\n")
	}

	t.Run("the marked command and its check in the final stage while the pinned image needs it", func(t *testing.T) {
		assert.Empty(t, joined(t, "3.24", "3.24", build+final+marked+user))
	})
	t.Run("the same, written with CRLF line endings", func(t *testing.T) {
		assert.Empty(t, joined(t, "3.24", "3.24", strings.ReplaceAll(build+final+marked+user, "\n", "\r\n")))
	})
	t.Run("a lowercase from opening the final stage", func(t *testing.T) {
		assert.Empty(t, joined(t, "3.24", "3.24", build+"from alpine:3.24 as final\n"+marked+user))
	})
	t.Run("all three removed while the pinned image still needs them", func(t *testing.T) {
		got := joined(t, "3.24", "3.24", build+final+user)
		assert.Contains(t, got, "no longer runs RUN apk upgrade --no-cache")
		assert.Contains(t, got, "does not check its zlib")
	})
	t.Run("the command without its marker", func(t *testing.T) {
		assert.Contains(t, joined(t, "3.24", "3.24", build+final+upgrade+check+user), "directly above")
	})
	t.Run("the marker away from the command", func(t *testing.T) {
		assert.Contains(t, joined(t, "3.24", "3.24", build+final+marker+"WORKDIR /x\n"+upgrade+check+user), "directly above")
	})
	t.Run("the marker separated from the command by a blank line", func(t *testing.T) {
		assert.Contains(t, joined(t, "3.24", "3.24", build+final+marker+"\n"+upgrade+check+user), "directly above")
	})
	t.Run("the marker naming another minor", func(t *testing.T) {
		assert.Contains(t, joined(t, "3.24", "3.24", build+final+"# apk-upgrade-until-alpine: 3.23\n"+upgrade+check+user),
			"directly above")
	})
	t.Run("a marker without the command", func(t *testing.T) {
		assert.Contains(t, joined(t, "3.24", "3.24", build+final+marker+user), "no longer runs")
	})
	t.Run("the command without its zlib check", func(t *testing.T) {
		assert.Contains(t, joined(t, "3.24", "3.24", build+final+marker+upgrade+user), "does not check its zlib")
	})
	t.Run("the zlib check away from the command", func(t *testing.T) {
		assert.Contains(t, joined(t, "3.24", "3.24", build+final+marker+upgrade+"WORKDIR /x\n"+check+user),
			"does not check its zlib")
	})
	t.Run("the zlib check altered", func(t *testing.T) {
		altered := strings.Replace(zlibFloorCheck, "1.3.2-r1 |", "1.3.2-r0 |", 1)
		assert.Contains(t, joined(t, "3.24", "3.24", build+final+marker+upgrade+altered+"\n"+user), "does not check its zlib")
	})
	t.Run("the zlib check in a build stage only", func(t *testing.T) {
		assert.Contains(t, joined(t, "3.24", "3.24", "FROM golang:1.27.2-alpine AS build\n"+check+final+marker+upgrade+user),
			"checks its zlib in a build stage")
	})
	t.Run("the upgrade in a build stage only", func(t *testing.T) {
		assert.Contains(t, joined(t, "3.24", "3.24", "FROM golang:1.27.2-alpine AS build\n"+marked+final+user),
			"in a build stage")
	})
	t.Run("the upgrade without --no-cache", func(t *testing.T) {
		assert.Contains(t, joined(t, "3.24", "3.24", build+final+marker+"RUN apk upgrade\n"+check+user),
			"must be exactly RUN apk upgrade --no-cache")
	})
	t.Run("the upgrade twice", func(t *testing.T) {
		assert.Contains(t, joined(t, "3.24", "3.24", build+final+marked+upgrade+user), "more than one instruction")
	})
	t.Run("the marked command absorbed by a continuation", func(t *testing.T) {
		got := joined(t, "3.24", "3.24", build+final+"RUN echo safe \\\n"+marked+user)
		assert.Contains(t, got, "must be exactly RUN apk upgrade --no-cache",
			"Docker drops the comment and reads the upgrade as arguments to echo")
	})
	t.Run("the marked command as a heredoc's content", func(t *testing.T) {
		assert.Contains(t, joined(t, "3.24", "3.24", build+final+"COPY <<EOF /tmp/note\n"+marked+"EOF\n"+user),
			"uses a heredoc")
	})
	t.Run("the marked command as the content of a heredoc with a numeric delimiter", func(t *testing.T) {
		assert.Contains(t, joined(t, "3.24", "3.24", build+final+"COPY <<1 /tmp/note\n"+marked+"1\n"+user),
			"uses a heredoc")
	})
	t.Run("the marked command after a terminator BuildKit doesn't recognize", func(t *testing.T) {
		// "EOF " with a trailing space does not close the heredoc for BuildKit, so the marked command
		// after it is still the file's content.
		assert.Contains(t, joined(t, "3.24", "3.24", build+final+"COPY <<EOF /tmp/note\nEOF \n"+marked+"EOF\n"+user),
			"uses a heredoc")
	})
	t.Run("any heredoc, with the real command after it", func(t *testing.T) {
		assert.Contains(t, joined(t, "3.24", "3.24", build+final+"COPY <<EOF /tmp/note\nnote\nEOF\n"+marked+user),
			"uses a heredoc", "a heredoc is refused outright rather than parsed")
	})
	t.Run("the escape directive turning a backtick into the continuation", func(t *testing.T) {
		assert.Contains(t, joined(t, "3.24", "3.24", "# escape=`\n"+build+final+"RUN echo safe `\n"+marked+user),
			"sets the escape directive")
	})
	t.Run("the pin moved past the minor that needed it", func(t *testing.T) {
		got, err := apkUpgradeFindings(tree(t, "3.25", build+final+marked+user), "3.24")
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Contains(t, got[0], "tools.alpine is now 3.25")
		assert.Contains(t, got[0], "set apkUpgradeAlpine to \"\"")
	})
	t.Run("no image needs it: the upgrade and its marker gone, the zlib check kept", func(t *testing.T) {
		assert.Empty(t, joined(t, "3.25", "", build+"FROM alpine:3.25 AS final\n"+check+user))
	})
	t.Run("no image needs it, and the zlib check went with the upgrade", func(t *testing.T) {
		assert.Contains(t, joined(t, "3.25", "", build+"FROM alpine:3.25 AS final\n"+user), "does not check its zlib",
			"the check stays: the release's arm64 image is checked nowhere else")
	})
	t.Run("no image needs it, and the command is left", func(t *testing.T) {
		assert.Contains(t, joined(t, "3.25", "", build+"FROM alpine:3.25 AS final\n"+marked+user), "remove both")
	})
	t.Run("a tree it cannot read", func(t *testing.T) {
		_, err := apkUpgradeFindings(t.TempDir(), "3.24")
		require.Error(t, err)
	})
}
