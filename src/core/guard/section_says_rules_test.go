package guard

// Seam: AssertSectionSays over fixture pages written into a temp tree, driven through Run so its
// reporting is what is held: a section missing a text it must say, one holding a text it must not,
// one saying what it should, and a page without the section. Every docs guard that quotes the
// code's text reports through it, so a defect here would blind all of them at once (#584).

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeSectionPage writes a page holding a ## Logo section, with a ## Next section after it whose
// text the ## Logo section does not hold, and returns the tree's root.
func writeSectionPage(t *testing.T, content string) string {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "site"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "site", "page.mdx"), []byte(content), 0o600))
	return root
}

const sectionSaysPage = "## Logo\n\n" +
	"It carries `Cache-Control: no-store`.\n\n" +
	"```bash\ncurl -d grant_type=client_credentials\n```\n\n" +
	"## Next\n\n`Cache-Control: public, max-age=300`\n"

func TestAssertSectionSays_ATextTheSectionDoesNotSayFailsNamingIt(t *testing.T) {
	root := writeSectionPage(t, sectionSaysPage)

	report := Run(func(r Reporter) {
		AssertSectionSays(r, root, "site/page.mdx", "## Logo",
			[]string{"`Cache-Control: no-store`", "`Cache-Control: public, max-age=300`"}, nil)
	})

	assert.False(t, report.Stopped, "the check stopped rather than reporting: %s", report.Fatal)
	want := []string{"site/page.mdx: ## Logo does not say \"`Cache-Control: public, max-age=300`\""}
	assert.Equal(t, want, report.Errors)
}

func TestAssertSectionSays_ATextTheSectionMustNotSayFailsNamingIt(t *testing.T) {
	root := writeSectionPage(t, sectionSaysPage)

	report := Run(func(r Reporter) {
		AssertSectionSays(r, root, "site/page.mdx", "## Logo", nil,
			[]string{"grant_type=client_credentials", "max-age=300"})
	})

	assert.False(t, report.Stopped, "the check stopped rather than reporting: %s", report.Fatal)
	want := []string{`site/page.mdx: ## Logo says "grant_type=client_credentials"`}
	assert.Equal(t, want, report.Errors)
}

func TestAssertSectionSays_ASectionSayingWhatItShouldPasses(t *testing.T) {
	root := writeSectionPage(t, sectionSaysPage)

	report := Run(func(r Reporter) {
		AssertSectionSays(r, root, "site/page.mdx", "## Logo",
			[]string{"`Cache-Control: no-store`", "grant_type=client_credentials"}, []string{"max-age=300"})
	})

	assert.False(t, report.Failed(), "a section saying what it should was refused: %+v", report)
}

func TestAssertSectionSays_AMissingSectionStopsNamingIt(t *testing.T) {
	root := writeSectionPage(t, "## Client logo\n\n`Cache-Control: no-store`\n")

	report := Run(func(r Reporter) {
		AssertSectionSays(r, root, "site/page.mdx", "## Logo", []string{"`Cache-Control: no-store`"}, nil)
	})

	assert.True(t, report.Stopped, "a page without the section did not stop the check: %+v", report)
	assert.Contains(t, report.Fatal, `site/page.mdx has no "## Logo" section`)
	assert.Empty(t, report.Errors)
}
