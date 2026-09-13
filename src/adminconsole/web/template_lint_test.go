package web

import (
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/testutil"
)

// The three rules below run in both servers and live once, in core/testutil/template_lint.go, which
// carries each one's reasoning and the shared walk (#333). What stays here is this module's own
// evidence for them, the FS they are held against -- templateFS, the //go:embed set this binary
// renders from -- and TestTemplates_RedirectURIAndWebOriginCellsAreText, which is a rule about two
// of this module's own pages and belongs to no other.

// TestTemplates_NoHTMLInTitle guards the admin_users_* bug: markup in the {{define "title"}} block
// renders literally in the browser tab.
func TestTemplates_NoHTMLInTitle(t *testing.T) {
	testutil.AssertTemplatesNoHTMLInTitle(t, templateFS, "template")
}

// TestTemplates_RedirectURIAndWebOriginCellsAreText guards the issue #105 sink: the
// redirect URIs and web origins pages render a stored value into a table cell and read it
// back when deleting a row. Both sides must use textContent.
//
// innerHTML on the write side parses markup in the value, which made a DCR-registered
// "x:<svg onload=...>" execute in the admin console. innerHTML on the read side returns a
// re-serialised string, so a value containing "&" no longer matched the raw array entry and
// deletion silently did nothing.
//
// Deliberately scoped to these two files. Around twenty other innerHTML assignments across
// the admin templates take server data and are currently protected by input validation
// rather than by output encoding; auditing them is issue #120, which should replace this
// narrow check with a general rule plus an allowlist rather than add a second lint.
func TestTemplates_RedirectURIAndWebOriginCellsAreText(t *testing.T) {
	guarded := map[string]bool{
		"template/admin_clients_redirect_uris.html": true,
		"template/admin_clients_web_origins.html":   true,
	}

	// The write side, "cell1.innerHTML = uri", and the read side,
	// getElementsByTagName("td")[0].innerHTML.
	banned := []string{
		"innerHTML = uri",
		`getElementsByTagName("td")[0].innerHTML`,
	}

	seen := 0
	testutil.WalkHTMLTemplates(t, templateFS, "template", func(path, content string) {
		if !guarded[path] {
			return
		}
		seen++
		for _, b := range banned {
			if strings.Contains(content, b) {
				t.Errorf("%s: found %q; use textContent on both the write and the read side (issue #105)",
					path, b)
			}
		}
	})

	// If either file is renamed, the check above silently guards nothing.
	if seen != len(guarded) {
		t.Errorf("expected to check %d templates, checked %d; update the guarded set if a file was renamed",
			len(guarded), seen)
	}
}

// TestTemplates_NoCsrfField guards the half of the CSRF token deletion that nothing else in this
// module observes. Measured here rather than assumed: restoring {{ .csrfField }} to
// account_phone.html, which TestRender_AccountPhone and TestRender_JSBootstrapNoKeyLeak both render
// from a bind map that no longer carries it, left the whole adminconsole tier green. The bind side
// of the same deletion is guarded by internal/handlers/csrf_lint_test.go, which draws the same
// lexical boundary.
func TestTemplates_NoCsrfField(t *testing.T) {
	testutil.AssertTemplatesNoCsrfField(t, templateFS, "template")
}

// TestTemplates_HtmlLangNotHardcoded guards the <html lang="en"> bug: page layouts must render the
// lang attribute from the active locale. This module's email layouts are exempt, being per-locale
// sibling files.
func TestTemplates_HtmlLangNotHardcoded(t *testing.T) {
	testutil.AssertTemplatesHtmlLangNotHardcoded(t, templateFS, "template")
}
