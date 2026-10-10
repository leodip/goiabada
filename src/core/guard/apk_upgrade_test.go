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

// The release images' final stage runs "apk upgrade" for one reason, a package fix alpine:3.24
// was built without (zlib 1.3.2-r1, CVE-2026-85091), and carries a marker naming the Alpine
// minor it was added for. A minor's image is rebuilt with its fixes, so the line is meant to go
// with the next one: these hold the marker to versions.yaml's tools.alpine, so the bump
// ./version-manager.sh update writes fails here until the line and its marker are removed, or
// the marker is moved on deliberately (#542).

// releaseDockerfiles are the release images' Dockerfiles, relative to the source root.
var releaseDockerfiles = []string{"build/Dockerfile-authserver", "build/Dockerfile-adminconsole"}

var (
	apkUpgradeLine   = regexp.MustCompile(`(?m)^RUN apk upgrade\b`)
	apkUpgradeMarker = regexp.MustCompile(`(?m)^# apk-upgrade-until-alpine: (\S+)$`)
)

// apkUpgradeFindings is every way the apk upgrade lines under root disagree with tools.alpine.
func apkUpgradeFindings(root string) ([]string, error) {
	alpine, err := pinnedTool(filepath.Join(root, "authserver", "versions.yaml"), "alpine")
	if err != nil {
		return nil, err
	}
	var findings []string
	for _, rel := range releaseDockerfiles {
		src, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			return nil, errs.Wrapf(err, "reading %s", rel)
		}
		upgrades := apkUpgradeLine.Match(src)
		marker := apkUpgradeMarker.FindSubmatch(src)
		switch {
		case upgrades && marker == nil:
			findings = append(findings, rel+" runs apk upgrade with no apk-upgrade-until-alpine marker above it, "+
				"so nothing says when it can go")
		case !upgrades && marker != nil:
			findings = append(findings, rel+" keeps an apk-upgrade-until-alpine marker with no apk upgrade line: remove it")
		case upgrades && string(marker[1]) != alpine:
			findings = append(findings, rel+" runs apk upgrade, added for alpine:"+string(marker[1])+
				", and tools.alpine is now "+alpine+": check that alpine:"+alpine+" ships zlib 1.3.2-r1 or later "+
				"(CVE-2026-85091), then remove the apk upgrade line and its marker; if the image still lacks a fix, "+
				"set the marker to "+alpine)
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
	findings, err := apkUpgradeFindings(SourceRoot(t))
	require.NoError(t, err)
	for _, f := range findings {
		t.Error(f)
	}
}

// The finder over fixture trees: the marker matching the pin passes, a moved pin fails with the
// instruction, a line without its marker and a marker without its line fail, a tree with neither
// passes, and a tree it cannot read is an error rather than a pass.
func TestApkUpgradeFindings(t *testing.T) {
	const marked = "FROM alpine:3.24 AS final\n# apk-upgrade-until-alpine: 3.24\nRUN apk upgrade --no-cache\n"
	tree := func(t *testing.T, alpine, dockerfile string) string {
		t.Helper()
		root := t.TempDir()
		writeFixture(t, root, "authserver/versions.yaml", "# comment\ntools:\n  alpine: \""+alpine+"\" # pinned\n")
		for _, rel := range releaseDockerfiles {
			writeFixture(t, root, rel, dockerfile)
		}
		return root
	}

	t.Run("the marker names the pinned minor", func(t *testing.T) {
		findings, err := apkUpgradeFindings(tree(t, "3.24", marked))
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
	t.Run("the pin moved on", func(t *testing.T) {
		findings, err := apkUpgradeFindings(tree(t, "3.25", marked))
		require.NoError(t, err)
		require.Len(t, findings, 2, "one per Dockerfile")
		assert.Contains(t, findings[0], "tools.alpine is now 3.25")
		assert.Contains(t, findings[0], "remove the apk upgrade line and its marker")
	})
	t.Run("a line without its marker", func(t *testing.T) {
		findings, err := apkUpgradeFindings(tree(t, "3.24", "FROM alpine:3.24\nRUN apk upgrade --no-cache\n"))
		require.NoError(t, err)
		require.Len(t, findings, 2)
		assert.Contains(t, findings[0], "no apk-upgrade-until-alpine marker")
	})
	t.Run("a marker without its line", func(t *testing.T) {
		findings, err := apkUpgradeFindings(tree(t, "3.24", "FROM alpine:3.24\n# apk-upgrade-until-alpine: 3.24\n"))
		require.NoError(t, err)
		require.Len(t, findings, 2)
		assert.Contains(t, findings[0], "with no apk upgrade line")
	})
	t.Run("neither, once it is gone", func(t *testing.T) {
		findings, err := apkUpgradeFindings(tree(t, "3.25", "FROM alpine:3.25 AS final\n"))
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
	t.Run("a tree it cannot read", func(t *testing.T) {
		_, err := apkUpgradeFindings(t.TempDir())
		require.Error(t, err)
	})
}
