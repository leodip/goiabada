package main

import (
	"bytes"
	"os"
	"regexp"
	"strings"
	"testing"
)

// releaseBuild is the script the release workflow builds the native binaries' archives with.
const releaseBuild = "../../build/build-binaries.sh"

// The wizard's native binaries instructions unpack the archive a release publishes, as the release
// script names and packs it: a zip, unpacked with unzip (#522).
func TestNativeInstructions_UnpackTheArchiveAReleasePublishes(t *testing.T) {
	script, err := os.ReadFile(releaseBuild)
	if err != nil {
		t.Fatalf("reading %s: %v", releaseBuild, err)
	}
	match := regexp.MustCompile(`\bzip -v "(goiabada-\$\{VERSION\}-\$\{os\}-\$\{arch\}\.zip)"`).FindSubmatch(script)
	if match == nil {
		t.Fatalf("%s packs no archive with zip -v \"goiabada-${VERSION}-${os}-${arch}.zip\"", releaseBuild)
	}
	archive := strings.NewReplacer("${VERSION}", "<version>", "${os}", "<os>", "${arch}", "<arch>").Replace(string(match[1]))
	if archive != nativeReleaseArchive {
		t.Errorf("the release script packs %s, and the wizard names %s", archive, nativeReleaseArchive)
	}

	config := testConfig()
	config.Deployment = deployments[deploymentNative]
	var buf bytes.Buffer
	printNativeInstructions(&console{w: &buf}, config, outputPaths{description: "goiabada.env"})
	if !strings.Contains(buf.String(), "  unzip "+archive+"\n") {
		t.Errorf("the native instructions do not say to unpack the release archive with unzip %s:\n%s", archive, buf.String())
	}
}
