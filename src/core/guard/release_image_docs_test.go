package guard

// The deploy pages that describe the release images, held to the files that decide what the images
// are (#808 decisions 4, 10 and 12): the contents releaseImages lists, the health check each
// Dockerfile declares, the user it runs as, the check the setup wizard writes, and the manifest's
// container names a debug container targets. Each is read from that one source, so an image that
// gains a file, a timing that changes or a container renamed fails here rather than leaving a page
// that tells an operator to look for something the image no longer holds.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/docsreader"
)

// The pages, and the setup wizard's output they describe, relative to the source root.
const (
	imagesComposePage    = "../site/src/content/docs/deploy/docker-compose.mdx"
	imagesKubernetesPage = "../site/src/content/docs/deploy/kubernetes/overview.mdx"
	imagesUpgradePage    = "../site/src/content/docs/deploy/upgrade-goiabada.mdx"
	wizardComposeGolden  = "cmd/goiabada-setup/testdata/production-sqlite.golden"
	wizardManifestGolden = "cmd/goiabada-setup/testdata/kubernetes-gateway-postgres.golden"

	imagesContentsHeading  = "## What the images contain"
	imagesHealthHeading    = "## Health checks"
	imagesFilesRunHeading  = "## What the files run"
	imagesDebuggingHeading = "## Debugging without a shell"
	imagesStartHeading     = "### The migration lock"
)

// imagesSection reads one section of a page, failing the test when the page or the section is
// missing, so a check that read nothing cannot pass.
func imagesSection(t *testing.T, page, heading string) string {
	t.Helper()
	text, err := docsreader.Section(SourceRoot(t), page, heading)
	require.NoError(t, err)
	return text
}

// imageHealthcheckFlags are the flags of the health check every image declares, by name, such as
// "interval" → "10s".
func imageHealthcheckFlags(t *testing.T) map[string]string {
	t.Helper()
	flags := map[string]string{}
	for _, match := range regexp.MustCompile(`--([a-z-]+)=(\S+)`).FindAllStringSubmatch(imageHealthcheck("authserver"), -1) {
		flags[match[1]] = match[2]
	}
	require.Len(t, flags, 4, "the image health check sets four timings")
	return flags
}

// composeExecForm is the exec form a Compose file or an orchestrator writes to run what server's
// image declares as its check: the image's CMD array with "CMD" in front.
func composeExecForm(t *testing.T, server string) string {
	t.Helper()
	_, array, found := strings.Cut(imageHealthcheck(server), " CMD [")
	require.True(t, found, "the image health check is in exec form")
	return `["CMD", ` + array
}

// imageUserIDs is the uid:gid every image runs as.
func imageUserIDs() string {
	return strings.TrimPrefix(imageUser, "USER ")
}

// TestComposePage_WhatTheImagesContain: the section names every entry each image holds that holds
// nothing else, the user both run as, and how to replace the CA bundle, and says nothing of the
// Alpine base, BusyBox or wget, which the images no longer hold.
func TestComposePage_WhatTheImagesContain(t *testing.T) {
	section := imagesSection(t, imagesComposePage, imagesContentsHeading)
	for _, img := range releaseImages {
		var paths []string
		for _, entry := range img.contents {
			paths = append(paths, strings.Fields(entry)[2])
		}
		for _, path := range paths {
			isParent := false
			for _, other := range paths {
				if other != path && strings.HasPrefix(other, path) {
					isParent = true
				}
			}
			if isParent {
				continue
			}
			named := "`/" + strings.TrimSuffix(path, "/") + "`"
			assert.Containsf(t, section, named, "%s: %s does not name %s, which the %s image holds", imagesComposePage, imagesContentsHeading, named, img.server)
		}
	}
	assert.Containsf(t, section, "`"+imageUserIDs()+"`", "%s: %s names the user the images run as", imagesComposePage, imagesContentsHeading)
	assert.Containsf(t, section, "`"+imageUser+"`", "%s: %s tells a Dockerfile built FROM the image which USER to end with", imagesComposePage, imagesContentsHeading)
	assert.Containsf(t, section, "`SSL_CERT_FILE`", "%s: %s says how to replace the CA bundle", imagesComposePage, imagesContentsHeading)
	for _, gone := range []string{"Alpine", "BusyBox", "ssl_client", "wget"} {
		assert.NotContainsf(t, section, gone, "%s: %s still describes %s, which the images no longer hold", imagesComposePage, imagesContentsHeading, gone)
	}

	page, err := os.ReadFile(filepath.Join(SourceRoot(t), imagesComposePage))
	require.NoError(t, err)
	assert.NotContainsf(t, string(page), "wget", "%s: no command on the page can run wget in an image that holds none", imagesComposePage)
}

// TestComposePage_HealthChecks: the section gives each image's own check in the exec form an
// orchestrator writes, and the timings the images declare as the Compose fields that set them, so
// a check of your own copied from it behaves as the image's does.
func TestComposePage_HealthChecks(t *testing.T) {
	section := imagesSection(t, imagesComposePage, imagesHealthHeading)
	for _, server := range []string{"authserver", "adminconsole"} {
		form := composeExecForm(t, server)
		assert.Containsf(t, section, form, "%s: %s gives the %s image's check as %s", imagesComposePage, imagesHealthHeading, server, form)
	}
	composeField := map[string]string{"interval": "interval", "timeout": "timeout", "start-period": "start_period", "retries": "retries"}
	for flag, value := range imageHealthcheckFlags(t) {
		field := composeField[flag] + ": " + value
		assert.Containsf(t, section, field, "%s: %s gives the image's --%s as %q", imagesComposePage, imagesHealthHeading, flag, field)
	}
}

// TestComposePage_WhatTheFilesRunNamesTheCheck: the auth server's service runs the check the
// setup wizard writes, and the section names that command.
func TestComposePage_WhatTheFilesRunNamesTheCheck(t *testing.T) {
	golden, err := os.ReadFile(filepath.Join(SourceRoot(t), wizardComposeGolden))
	require.NoError(t, err)
	match := regexp.MustCompile(`(?m)^      test: \["CMD", "([^"]+)", "([^"]+)"\]$`).FindStringSubmatch(string(golden))
	require.NotNil(t, match, "%s: the auth server's service writes an exec-form check", wizardComposeGolden)
	command := "`" + match[1] + " " + match[2] + "`"

	section := imagesSection(t, imagesComposePage, imagesFilesRunHeading)
	assert.Containsf(t, section, command, "%s: %s names the check the auth server's service runs, %s", imagesComposePage, imagesFilesRunHeading, command)
	assert.Containsf(t, section, "(#health-checks)", "%s: %s links the health checks section", imagesComposePage, imagesFilesRunHeading)
}

// busyboxPin is the tool image the debugging sections run, pinned to a version.
var busyboxPin = regexp.MustCompile(`--image=busybox:\d+\.\d+(?:\.\d+)?\b|\bbusybox:\d+\.\d+(?:\.\d+)?\b`)

// TestComposePage_DebuggingWithoutAShell: the tool container shares the server's network and
// processes and runs as the images' user, the only one that can read the server's files under
// /proc/1/root, on a pinned BusyBox; docker compose cp reads a file out without one.
func TestComposePage_DebuggingWithoutAShell(t *testing.T) {
	section := imagesSection(t, imagesComposePage, imagesDebuggingHeading)
	for _, want := range []string{"--network container:", "--pid container:", "--user " + imageUserIDs(), "/proc/1/root", "docker compose cp goiabada-authserver:"} {
		assert.Containsf(t, section, want, "%s: %s says %q", imagesComposePage, imagesDebuggingHeading, want)
	}
	assert.Regexpf(t, busyboxPin, section, "%s: %s runs a BusyBox of a named version", imagesComposePage, imagesDebuggingHeading)
}

// TestKubernetesOverview_DebuggingWithoutAShell: the debug container meets the restricted Pod
// Security Standard, the wizard's namespace audits against, runs as the images' user from a custom
// spec, targets a container the wizard's manifest declares in its namespace, and the section links
// to what the images contain.
func TestKubernetesOverview_DebuggingWithoutAShell(t *testing.T) {
	section := imagesSection(t, imagesKubernetesPage, imagesDebuggingHeading)
	for _, want := range []string{"kubectl debug -it ", "--profile=restricted", "--custom=", "/proc/1/root", "(/deploy/docker-compose/#what-the-images-contain)"} {
		assert.Containsf(t, section, want, "%s: %s says %q", imagesKubernetesPage, imagesDebuggingHeading, want)
	}
	assert.Regexpf(t, busyboxPin, section, "%s: %s runs a BusyBox of a named version", imagesKubernetesPage, imagesDebuggingHeading)

	ids := strings.SplitN(imageUserIDs(), ":", 2)
	for _, want := range []string{"runAsUser: " + ids[0], "runAsGroup: " + ids[1]} {
		assert.Containsf(t, section, want, "%s: %s's custom spec sets %q, the images' user", imagesKubernetesPage, imagesDebuggingHeading, want)
	}

	manifest, err := os.ReadFile(filepath.Join(SourceRoot(t), wizardManifestGolden))
	require.NoError(t, err)
	namespace := regexp.MustCompile(`(?m)^kind: Namespace\nmetadata:\n  name: "([^"]+)"$`).FindStringSubmatch(string(manifest))
	require.NotNil(t, namespace, "%s declares its Namespace", wizardManifestGolden)
	assert.Containsf(t, section, "-n "+namespace[1]+" ", "%s: %s debugs in the wizard's namespace", imagesKubernetesPage, imagesDebuggingHeading)

	targets := regexp.MustCompile(`--target=([a-z0-9-]+)`).FindAllStringSubmatch(section, -1)
	require.NotEmptyf(t, targets, "%s: %s names the container to target", imagesKubernetesPage, imagesDebuggingHeading)
	for _, target := range targets {
		assert.Containsf(t, string(manifest), "\n      - name: "+target[1]+"\n", "%s: %s targets %q, a container the wizard's manifest declares", imagesKubernetesPage, imagesDebuggingHeading, target[1])
	}
}

// TestUpgradePage_TheImagesGiveDockerTheStartPeriod: the list of how long each platform gives a
// start says the images' own check gives Docker and Swarm the start period the images declare.
func TestUpgradePage_TheImagesGiveDockerTheStartPeriod(t *testing.T) {
	period, err := time.ParseDuration(imageHealthcheckFlags(t)["start-period"])
	require.NoError(t, err)
	minutes := fmt.Sprintf("%d minutes", int(period.Minutes()))

	section := imagesSection(t, imagesUpgradePage, imagesStartHeading)
	var bullet string
	for _, line := range strings.Split(section, "\n") {
		if strings.HasPrefix(line, "- **") && strings.Contains(line, "Swarm") {
			bullet = line
		}
	}
	require.NotEmptyf(t, bullet, "%s: %s has a bullet for Docker and Swarm", imagesUpgradePage, imagesStartHeading)
	assert.Containsf(t, bullet, minutes, "%s: the Docker and Swarm bullet gives the images' start period, %s", imagesUpgradePage, minutes)
	assert.Containsf(t, bullet, "(/deploy/docker-compose/#health-checks)", "%s: the Docker and Swarm bullet links the images' health check", imagesUpgradePage)
}
