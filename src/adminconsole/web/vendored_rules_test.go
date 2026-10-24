package web

// The rules assertVendoredLibraries enforces, over fstest.MapFS fixtures and fixture versions.yaml
// content walked through the same finder and reporting half the real tree is. The real tree is
// clean, so it passes whether each rule still fires or has quietly stopped matching anything; every
// refused case below is a mismatch the check must report, and the admitted tree one it must leave
// alone.

import (
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/guard"
)

// The SHA-256 of "lib" and "other", written out as sha256sum gives them rather than computed, so a
// finder that hashed wrongly would not agree with itself.
const (
	libDigest   = "76b5a357391276b282a516f54f48ef3c207f46d8192dc58c208d5183d38415f8"
	otherDigest = "d9298a10d1b0735837dc4bd85dac641b0f3cef27a47e5d53a54f2f3f5b2fcffa"
)

// fixtureLibraries and fixtureElsewhere stand in for the console's list and the digests held by
// another test.
var (
	fixtureLibraries = map[string]string{"static/vendor/lib/lib.js": "lib-sha256"}
	fixtureElsewhere = map[string]string{"tool-sha256": "the tool's own test"}
)

// fixtureVersions is a versions.yaml whose vendored section pins the fixture library and the tool,
// plus extra lines appended to that section.
func fixtureVersions(extra string) []byte {
	return []byte("tools:\n  go: \"1.0\"\n  stray-sha256: \"outside the vendored section\"\n\n" +
		"# Vendored dependencies\nvendored:\n  lib: \"1.0.0\"\n  lib-sha256: \"" + libDigest + "\"\n" +
		"  tool: \"2.0.0\"\n  tool-sha256: \"" + otherDigest + "\"\n" + extra)
}

// fixtureStatic is a static tree serving the fixture library with its license, with extra's files
// added, or removed where extra maps them to nil.
func fixtureStatic(extra fstest.MapFS) fstest.MapFS {
	fsys := fstest.MapFS{
		"static/main.css":           {Data: []byte("body{}")},
		"static/vendor/lib/lib.js":  {Data: []byte("lib")},
		"static/vendor/lib/LICENSE": {Data: []byte("MIT")},
	}
	for path, file := range extra {
		if file == nil {
			delete(fsys, path)
			continue
		}
		fsys[path] = file
	}
	return fsys
}

func vendoredReport(static fstest.MapFS, versions []byte) guard.Report {
	return guard.Run(func(r guard.Reporter) {
		assertVendoredLibraries(r, static, versions, fixtureLibraries, fixtureElsewhere)
	})
}

// A tree whose vendor folder is the pinned library and its license, and whose digests are each
// checked by the console or by another test, passes. A digest outside the vendored section is
// none of the check's business.
func TestVendoredLibraries_AdmitsAPinnedTree(t *testing.T) {
	report := vendoredReport(fixtureStatic(nil), fixtureVersions(""))

	assert.False(t, report.Failed(), "%s", report.Text())
}

func TestVendoredLibraries_RefusesEachMismatch(t *testing.T) {
	for _, tc := range []struct {
		name     string
		static   fstest.MapFS
		versions []byte
		want     string
	}{
		{
			name:     "a file under static/vendor that no library pins",
			static:   fixtureStatic(fstest.MapFS{"static/vendor/left/left.js": {Data: []byte("left")}}),
			versions: fixtureVersions(""),
			want:     "static/vendor/left/left.js is under static/vendor and is no pinned library or its LICENSE",
		},
		{
			name:     "a license left behind by a library",
			static:   fixtureStatic(fstest.MapFS{"static/vendor/left/LICENSE": {Data: []byte("MIT")}}),
			versions: fixtureVersions(""),
			want:     "static/vendor/left/LICENSE is under static/vendor and is no pinned library or its LICENSE",
		},
		{
			name:     "a pinned library missing",
			static:   fixtureStatic(fstest.MapFS{"static/vendor/lib/lib.js": nil}),
			versions: fixtureVersions(""),
			want:     "static/vendor/lib/lib.js is not embedded",
		},
		{
			name:     "a pinned library without its license",
			static:   fixtureStatic(fstest.MapFS{"static/vendor/lib/LICENSE": nil}),
			versions: fixtureVersions(""),
			want:     "static/vendor/lib/lib.js ships without its license, static/vendor/lib/LICENSE",
		},
		{
			name:     "a library edited by hand",
			static:   fixtureStatic(fstest.MapFS{"static/vendor/lib/lib.js": {Data: []byte("other")}}),
			versions: fixtureVersions(""),
			want:     "static/vendor/lib/lib.js has SHA-256 " + otherDigest + ", and versions.yaml pins " + libDigest,
		},
		{
			name:     "a library whose digest versions.yaml does not pin",
			static:   fixtureStatic(nil),
			versions: []byte("vendored:\n  tool-sha256: \"" + otherDigest + "\"\n"),
			want:     "versions.yaml pins no vendored.lib-sha256 for static/vendor/lib/lib.js",
		},
		{
			name:     "a stale digest",
			static:   fixtureStatic(nil),
			versions: fixtureVersions("  gone: \"3.0.0\"\n  gone-sha256: \"" + libDigest + "\"\n"),
			want:     "versions.yaml pins vendored.gone-sha256, which no test checks",
		},
		{
			name:     "a stale digest after a comment in the section",
			static:   fixtureStatic(nil),
			versions: fixtureVersions("  # a note\n\n  gone-sha256: \"" + libDigest + "\"\n"),
			want:     "versions.yaml pins vendored.gone-sha256, which no test checks",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := vendoredReport(tc.static, tc.versions)

			require.True(t, report.Failed(), "the check passed")
			assert.False(t, report.Stopped, "the check stopped instead of reporting: %s", report.Text())
			assert.Equal(t, []string{tc.want + "; run ./version-manager.sh update, or drop what it left (#645)"}, report.Errors)
		})
	}
}

// A walk that reached nothing, or a versions.yaml with nothing to read, is fatal rather than clean.
func TestVendoredLibraries_IsFatalOverNothing(t *testing.T) {
	for _, tc := range []struct {
		name     string
		static   fstest.MapFS
		versions []byte
		want     string
	}{
		{
			name:     "no vendor folder",
			static:   fstest.MapFS{"static/main.css": {Data: []byte("body{}")}},
			versions: fixtureVersions(""),
			want:     "reached 0 files under static/vendor",
		},
		{
			name:     "no vendored digest",
			static:   fixtureStatic(nil),
			versions: []byte("vendored:\n  lib: \"1.0.0\"\n"),
			want:     "and 0 vendored digests in versions.yaml",
		},
		{
			name:     "no vendored section",
			static:   fixtureStatic(nil),
			versions: []byte("tools:\n  lib-sha256: \"" + libDigest + "\"\n"),
			want:     "versions.yaml has no vendored section",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := vendoredReport(tc.static, tc.versions)

			require.True(t, report.Stopped, "the check did not stop: %s", report.Text())
			assert.Contains(t, report.Fatal, tc.want)
		})
	}
}
