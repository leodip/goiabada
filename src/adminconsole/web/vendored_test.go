package web

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// versionsYAML is the file the vendored web dependencies are pinned in, read from the source tree
// rather than embedded, since it ships in neither binary.
const versionsYAML = "../../authserver/versions.yaml"

// vendoredPin reads one key of versions.yaml's vendored section, a quoted string on a line of its
// own, which is the shape version-manager.sh writes.
func vendoredPin(t *testing.T, key string) string {
	t.Helper()
	content, err := os.ReadFile(versionsYAML)
	if err != nil {
		t.Fatalf("reading %s: %v", versionsYAML, err)
	}
	section := string(content)
	at := strings.Index(section, "\nvendored:\n")
	if at < 0 {
		t.Fatalf("%s has no vendored section", versionsYAML)
	}
	m := regexp.MustCompile(`(?m)^  ` + regexp.QuoteMeta(key) + `: "([^"]*)"$`).FindStringSubmatch(section[at:])
	if m == nil {
		t.Fatalf("%s pins no vendored.%s", versionsYAML, key)
	}
	return m[1]
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// thirdPartyAsset matches a script or stylesheet loaded from another origin: an absolute or
// protocol-relative URL in a script's src or a link's href. Each page's assets are served from
// /static, the vendored libraries among them, so no page makes a third-party request (#542).
var thirdPartyAsset = regexp.MustCompile(`(?i)<(script|link)\b[^>]*\b(src|href)\s*=\s*["']?\s*(https?:)?//`)

func TestTemplates_LoadNoScriptOrStylesheetFromAnotherOrigin(t *testing.T) {
	checked := 0
	err := fs.WalkDir(templateFS, "template", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".html") {
			return err
		}
		content, err := templateFS.ReadFile(path)
		if err != nil {
			return err
		}
		checked++
		for _, m := range thirdPartyAsset.FindAllString(string(content), -1) {
			t.Errorf("%s loads %q from another origin; vendor it under static and pin it in versions.yaml", path, m)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("no template was read")
	}
}

// catalogClass is a class attribute inside a catalog message, in either quote style.
var catalogClass = regexp.MustCompile(`class=\\?['"]([^'"\\]+)`)

// Every class the i18n catalogs write into message HTML is in the served main.css. Tailwind reads
// the templates and static scripts only, so a class used nowhere else would be built out of the
// stylesheet: input.css lists the catalogs' classes inline, and this fails when a catalog adds one
// it leaves out (#542).
func TestMainCSS_HoldsEveryClassTheCatalogsWrite(t *testing.T) {
	css, err := staticFS.ReadFile("static/main.css")
	if err != nil {
		t.Fatal(err)
	}
	catalogs, err := filepath.Glob("../../core/i18n/catalogs/*.toml")
	if err != nil || len(catalogs) == 0 {
		t.Fatalf("no catalog found: %v", err)
	}
	classes := map[string]bool{}
	for _, catalog := range catalogs {
		content, err := os.ReadFile(catalog)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range catalogClass.FindAllStringSubmatch(string(content), -1) {
			for _, class := range strings.Fields(m[1]) {
				classes[class] = true
			}
		}
	}
	if len(classes) == 0 {
		t.Fatal("the catalogs write no class, so this test reads nothing")
	}
	for class := range classes {
		if !regexp.MustCompile(`\.` + regexp.QuoteMeta(class) + `\b`).Match(css) {
			t.Errorf("a catalog writes class %q, which main.css lacks: add it to input.css's @source inline and rebuild", class)
		}
	}
}

// The vendored libraries the admin console serves are the files versions.yaml pins, byte for byte:
// version-manager.sh update downloads them and writes each digest, so a pin moved without them,
// or a file edited by hand, fails here (#542).
func TestVendoredLibraries_AreTheFilesVersionsYAMLPins(t *testing.T) {
	for path, key := range map[string]string{
		"static/vendor/humanize-duration/humanize-duration.js": "humanize-duration-sha256",
		"static/vendor/cropperjs/cropper.min.js":               "cropperjs-js-sha256",
		"static/vendor/cropperjs/cropper.min.css":              "cropperjs-css-sha256",
	} {
		content, err := staticFS.ReadFile(path)
		if err != nil {
			t.Errorf("%s is not embedded: %v", path, err)
			continue
		}
		if got, want := sha256Hex(content), vendoredPin(t, key); got != want {
			t.Errorf("%s has SHA-256 %s, and versions.yaml pins %s: run ./version-manager.sh update", path, got, want)
		}
		license := filepath.Dir(path) + "/LICENSE"
		if _, err := staticFS.ReadFile(license); err != nil {
			t.Errorf("%s ships without its license, %s", path, license)
		}
	}
}

// daisyUI's standalone-CLI bundle, which this server's main.css is built with, is the file
// versions.yaml pins, byte for byte, beside input.css (#542). It ships in no binary, so it is
// read off disk.
func TestDaisyUIBundle_IsTheFileVersionsYAMLPins(t *testing.T) {
	const bundle = "tailwindcss/daisyui.mjs"
	content, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := sha256Hex(content), vendoredPin(t, "daisyui-sha256"); got != want {
		t.Errorf("%s has SHA-256 %s, and versions.yaml pins %s: run ./version-manager.sh update", bundle, got, want)
	}
	if !strings.Contains(string(content), `"`+vendoredPin(t, "daisyui")+`"`) {
		t.Errorf("%s does not carry the version versions.yaml pins, %s", bundle, vendoredPin(t, "daisyui"))
	}
	if _, err := os.Stat("tailwindcss/daisyui.LICENSE"); err != nil {
		t.Errorf("%s has no daisyui.LICENSE beside it: %v", bundle, err)
	}
}
