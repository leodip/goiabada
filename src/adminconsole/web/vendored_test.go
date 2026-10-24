package web

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/guard"
)

// versionsYAML is the file the vendored web dependencies are pinned in, read from the source tree
// rather than embedded, since it ships in neither binary.
const versionsYAML = "../../authserver/versions.yaml"

// vendoredDigest matches one digest of versions.yaml's vendored section, a key ending in -sha256 and
// its quoted value on a line of their own, which is the shape version-manager.sh writes.
var vendoredDigest = regexp.MustCompile(`^  ([A-Za-z0-9._-]+-sha256): "([^"]*)"$`)

// vendoredDigests reads every digest of versions.yaml's vendored section, which runs from its
// vendored: line to the next line that is neither indented, a comment nor blank.
func vendoredDigests(versions []byte) (map[string]string, error) {
	lines := strings.Split(string(versions), "\n")
	at := -1
	for i, line := range lines {
		if strings.TrimRight(line, "\r") == "vendored:" {
			at = i
			break
		}
	}
	if at < 0 {
		return nil, errs.New("versions.yaml has no vendored section")
	}
	digests := map[string]string{}
	for _, line := range lines[at+1:] {
		line = strings.TrimRight(line, "\r")
		if line != "" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "#") {
			break
		}
		if m := vendoredDigest.FindStringSubmatch(line); m != nil {
			digests[m[1]] = m[2]
		}
	}
	return digests, nil
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

// vendoredLibraries are the libraries the admin console serves, each file under static with the
// versions.yaml key pinning its SHA-256. A library's LICENSE sits beside it.
var vendoredLibraries = map[string]string{
	"static/vendor/cropperjs/cropper.min.js": "cropperjs-js-sha256",
}

// pinsCheckedElsewhere are the vendored digests versions.yaml pins for files the console does not
// serve, each with the test that holds it.
var pinsCheckedElsewhere = map[string]string{
	"acorn-sha256": "core/guard's TestScriptSyntax_AcornIsThePinnedRelease",
}

// The vendored libraries the admin console serves are the files versions.yaml pins, byte for byte,
// in both directions: every file under static/vendor is a pinned library or its LICENSE, every
// pinned library ships with its license, and every vendored digest versions.yaml pins is checked
// here or by the test pinsCheckedElsewhere names. version-manager.sh update downloads the files and
// writes each digest, so a pin moved without them, a file edited by hand, a file left behind when a
// library is dropped, or a digest left behind with it, fails here (#542, #645).
func TestVendoredLibraries_AreTheFilesVersionsYAMLPins(t *testing.T) {
	content, err := os.ReadFile(versionsYAML)
	if err != nil {
		t.Fatalf("reading %s: %v", versionsYAML, err)
	}
	assertVendoredLibraries(t, staticFS, content, vendoredLibraries, pinsCheckedElsewhere)
}

// vendoredReach counts what a check reached, so the reporting half can tell a clean tree from one
// in which it read nothing.
type vendoredReach struct {
	files, pins int
}

// assertVendoredLibraries is the reporting half. A walk that reached no file under static/vendor,
// or a versions.yaml with no vendored digest, is fatal, because every rule passes vacuously over
// nothing.
func assertVendoredLibraries(r guard.Reporter, static fs.FS, versions []byte, libraries, elsewhere map[string]string) {
	r.Helper()

	faults, reach, err := findVendoredFaults(static, versions, libraries, elsewhere)
	if err != nil {
		r.Fatalf("checking the vendored libraries: %v", err)
	}
	for _, f := range faults {
		r.Errorf("%s", f)
	}
	if reach.files == 0 || reach.pins == 0 {
		r.Fatalf("reached %d files under static/vendor and %d vendored digests in versions.yaml; "+
			"this check is checking nothing", reach.files, reach.pins)
	}
}

// findVendoredFaults holds static's vendor folder and the vendored section of versions to each
// other and to libraries, and returns one fault per mismatch, sorted.
func findVendoredFaults(static fs.FS, versions []byte, libraries, elsewhere map[string]string) ([]string, vendoredReach, error) {
	var reach vendoredReach
	digests, err := vendoredDigests(versions)
	if err != nil {
		return nil, reach, err
	}
	reach.pins = len(digests)

	var faults []string
	fault := func(format string, args ...any) {
		faults = append(faults, fmt.Sprintf(format, args...)+"; run ./version-manager.sh update, or drop what it left (#645)")
	}

	shipped := map[string]bool{}
	checked := map[string]bool{}
	for path, key := range libraries {
		license := filepath.Dir(path) + "/LICENSE"
		shipped[path], shipped[license], checked[key] = true, true, true
		content, readErr := fs.ReadFile(static, path)
		if readErr != nil {
			fault("%s is not embedded", path)
			continue
		}
		if pin, ok := digests[key]; !ok {
			fault("versions.yaml pins no vendored.%s for %s", key, path)
		} else if got := sha256Hex(content); got != pin {
			fault("%s has SHA-256 %s, and versions.yaml pins %s", path, got, pin)
		}
		if _, statErr := fs.Stat(static, license); statErr != nil {
			fault("%s ships without its license, %s", path, license)
		}
	}

	err = fs.WalkDir(static, "static/vendor", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		reach.files++
		if !shipped[path] {
			fault("%s is under static/vendor and is no pinned library or its LICENSE", path)
		}
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, reach, err
	}

	for key := range digests {
		if _, ok := elsewhere[key]; !ok && !checked[key] {
			fault("versions.yaml pins vendored.%s, which no test checks", key)
		}
	}
	sort.Strings(faults)
	return faults, reach, nil
}

// ui.css, the design tokens and components both servers' pages are drawn with, is one file kept
// in each application's tailwindcss folder, so a copy of either folder builds on its own. This
// one is the auth server's, byte for byte, so the two servers draw the same components; the auth
// server's web tests hold its palettes to WCAG AA contrast (#617).
func TestUICSS_IsTheAuthServersCopy(t *testing.T) {
	ours, err := os.ReadFile("tailwindcss/ui.css")
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := os.ReadFile("../../authserver/web/tailwindcss/ui.css")
	if err != nil {
		t.Fatal(err)
	}
	if string(ours) != string(theirs) {
		t.Error("tailwindcss/ui.css differs from the auth server's copy; edit one, copy it over the other, and regenerate both main.css files")
	}
}
