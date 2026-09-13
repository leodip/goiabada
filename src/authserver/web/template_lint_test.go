package web

import (
	"testing"

	"github.com/leodip/goiabada/core/testutil"
)

// The three rules below run in both servers and live once, in core/testutil/template_lint.go, which
// carries each one's reasoning and the shared walk (#333). What stays here is this module's own
// evidence for them and the FS they are held against: templateFS, the //go:embed set this binary
// renders from.

// TestTemplates_NoHTMLInTitle guards the admin_users_* bug: markup in the {{define "title"}} block
// renders literally in the browser tab.
func TestTemplates_NoHTMLInTitle(t *testing.T) {
	testutil.AssertTemplatesNoHTMLInTitle(t, templateFS, "template")
}

// TestTemplates_NoCsrfField guards the half of the CSRF token deletion that nothing else in this
// module observes. Measured here rather than assumed: restoring {{ .csrfField }} to all eight forms
// that carried it left every one of them green, across the handler tests and the integration suite,
// because both assert on the fields a page carries rather than on the absence of a stray one.
func TestTemplates_NoCsrfField(t *testing.T) {
	testutil.AssertTemplatesNoCsrfField(t, templateFS, "template")
}

// TestTemplates_HtmlLangNotHardcoded guards the <html lang="en"> bug: page layouts must render the
// lang attribute from the active locale. This module's email layouts are exempt, being per-locale
// sibling files.
func TestTemplates_HtmlLangNotHardcoded(t *testing.T) {
	testutil.AssertTemplatesHtmlLangNotHardcoded(t, templateFS, "template")
}
