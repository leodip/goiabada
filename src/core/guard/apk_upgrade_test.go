package guard

import (
	"os"
	"path/filepath"
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
)

// apkUpgradeFindings is every way the release Dockerfiles under root disagree with required, the
// minor needing the upgrade ("" for none), and with tools.alpine.
func apkUpgradeFindings(root, required string) ([]string, error) {
	alpine, err := pinnedTool(filepath.Join(root, "authserver", "versions.yaml"), "alpine")
	if err != nil {
		return nil, err
	}
	if required != "" && alpine != required {
		return []string{"tools.alpine is now " + alpine + ", and the release images run apk upgrade for alpine:" +
			required + "'s zlib (CVE-2026-85091): check that alpine:" + alpine + " ships zlib 1.3.2-r1 or later; " +
			"if it does, remove the apk upgrade line and its marker from " + strings.Join(releaseDockerfiles, " and ") +
			" and set apkUpgradeAlpine to \"\", and if it doesn't, set apkUpgradeAlpine and both markers to " + alpine}, nil
	}

	var findings []string
	for _, rel := range releaseDockerfiles {
		src, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			return nil, errs.Wrapf(err, "reading %s", rel)
		}
		lines := strings.Split(strings.ReplaceAll(string(src), "\r\n", "\n"), "\n")
		finalFrom := -1
		for i, line := range lines {
			if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(line)), "FROM ") {
				finalFrom = i
			}
		}
		if finalFrom < 0 {
			return nil, errs.Errorf("%s has no FROM line", rel)
		}

		var upgrades, markers []int
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(trimmed, apkUpgradeMarkerPrefix) ||
				strings.Contains(trimmed, "apk-upgrade-until-alpine"):
				markers = append(markers, i)
			case strings.Contains(trimmed, "apk upgrade"):
				upgrades = append(upgrades, i)
			}
		}

		if required == "" {
			if len(upgrades) > 0 || len(markers) > 0 {
				findings = append(findings, rel+" still runs apk upgrade or keeps its marker, and apkUpgradeAlpine "+
					"says no Alpine image needs it: remove both, or set apkUpgradeAlpine to the minor that does")
			}
			continue
		}

		switch {
		case len(upgrades) == 0:
			findings = append(findings, rel+" no longer runs "+apkUpgradeCommand+" in its final stage, and alpine:"+
				required+" still ships the vulnerable zlib: put it back, with its marker, or set apkUpgradeAlpine to \"\" "+
				"once the pinned image carries the fix")
		case len(upgrades) > 1:
			findings = append(findings, rel+" runs apk upgrade more than once: keep the one in the final stage")
		default:
			i := upgrades[0]
			if i < finalFrom {
				findings = append(findings, rel+" runs apk upgrade in a build stage, which never reaches the image: "+
					"move it to the final stage")
			}
			if strings.TrimSpace(lines[i]) != apkUpgradeCommand {
				findings = append(findings, rel+" runs "+strings.TrimSpace(lines[i])+", where the line must be exactly "+
					apkUpgradeCommand+", so no package cache is left in the layer")
			}
			if i == 0 || strings.TrimSpace(lines[i-1]) != apkUpgradeMarkerPrefix+required {
				findings = append(findings, rel+" has no "+apkUpgradeMarkerPrefix+required+" line directly above "+
					"its apk upgrade, so nothing in the file says when it can go")
			}
		}
		if len(markers) > 1 || (len(markers) == 1 && (len(upgrades) != 1 || markers[0] != upgrades[0]-1)) {
			findings = append(findings, rel+" keeps an apk-upgrade-until-alpine marker that is not directly above "+
				"its one apk upgrade line")
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

// The finder over fixture trees, one case per way the line can be wrong, and the ways it is right.
func TestApkUpgradeFindings(t *testing.T) {
	const build = "FROM golang:1.27.2-alpine AS build\nRUN go build ./...\n\n"
	const final = "FROM alpine:3.24 AS final\nWORKDIR /app\n"
	const marked = "# apk-upgrade-until-alpine: 3.24\nRUN apk upgrade --no-cache\n"
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
	findings := func(t *testing.T, alpine, required, dockerfile string) []string {
		t.Helper()
		got, err := apkUpgradeFindings(tree(t, alpine, dockerfile), required)
		require.NoError(t, err)
		return got
	}

	t.Run("the marked command in the final stage while the pinned image needs it", func(t *testing.T) {
		assert.Empty(t, findings(t, "3.24", "3.24", build+final+marked+user))
	})
	t.Run("the same, written with CRLF line endings", func(t *testing.T) {
		assert.Empty(t, findings(t, "3.24", "3.24", strings.ReplaceAll(build+final+marked+user, "\n", "\r\n")))
	})
	t.Run("both removed while the pinned image still needs them", func(t *testing.T) {
		got := findings(t, "3.24", "3.24", build+final+user)
		require.Len(t, got, 2, "one per Dockerfile")
		assert.Contains(t, got[0], "no longer runs RUN apk upgrade --no-cache")
	})
	t.Run("the command without its marker", func(t *testing.T) {
		got := findings(t, "3.24", "3.24", build+final+"RUN apk upgrade --no-cache\n"+user)
		require.Len(t, got, 2)
		assert.Contains(t, got[0], "directly above")
	})
	t.Run("the marker away from the command", func(t *testing.T) {
		got := findings(t, "3.24", "3.24", build+final+"# apk-upgrade-until-alpine: 3.24\nWORKDIR /x\nRUN apk upgrade --no-cache\n"+user)
		assert.NotEmpty(t, got)
	})
	t.Run("the marker naming another minor", func(t *testing.T) {
		got := findings(t, "3.24", "3.24", build+final+"# apk-upgrade-until-alpine: 3.23\nRUN apk upgrade --no-cache\n"+user)
		assert.NotEmpty(t, got)
	})
	t.Run("a marker without the command", func(t *testing.T) {
		got := findings(t, "3.24", "3.24", build+final+"# apk-upgrade-until-alpine: 3.24\n"+user)
		require.NotEmpty(t, got)
		assert.Contains(t, strings.Join(got, "\n"), "no longer runs")
	})
	t.Run("the upgrade in a build stage only", func(t *testing.T) {
		got := findings(t, "3.24", "3.24", "FROM golang:1.27.2-alpine AS build\n"+marked+final+user)
		require.Len(t, got, 2)
		assert.Contains(t, got[0], "in a build stage")
	})
	t.Run("the upgrade without --no-cache", func(t *testing.T) {
		got := findings(t, "3.24", "3.24", build+final+"# apk-upgrade-until-alpine: 3.24\nRUN apk upgrade\n"+user)
		require.Len(t, got, 2)
		assert.Contains(t, got[0], "must be exactly RUN apk upgrade --no-cache")
	})
	t.Run("the upgrade twice", func(t *testing.T) {
		got := findings(t, "3.24", "3.24", build+final+marked+"RUN apk upgrade --no-cache\n"+user)
		require.NotEmpty(t, got)
		assert.Contains(t, strings.Join(got, "\n"), "more than once")
	})
	t.Run("the pin moved past the minor that needed it", func(t *testing.T) {
		got := findings(t, "3.25", "3.24", build+final+marked+user)
		require.Len(t, got, 1)
		assert.Contains(t, got[0], "tools.alpine is now 3.25")
		assert.Contains(t, got[0], "set apkUpgradeAlpine to \"\"")
	})
	t.Run("no image needs it, and both are gone", func(t *testing.T) {
		assert.Empty(t, findings(t, "3.25", "", build+"FROM alpine:3.25 AS final\n"+user))
	})
	t.Run("no image needs it, and the command is left", func(t *testing.T) {
		got := findings(t, "3.25", "", build+"FROM alpine:3.25 AS final\n"+marked+user)
		require.Len(t, got, 2)
		assert.Contains(t, got[0], "remove both")
	})
	t.Run("a tree it cannot read", func(t *testing.T) {
		_, err := apkUpgradeFindings(t.TempDir(), "3.24")
		require.Error(t, err)
	})
}
