package web

import (
	"testing"

	"github.com/leodip/goiabada/core/guard"
)

// The three rules below run in both servers and live once, in core/guard/template_lint.go, which
// carries each one's reasoning and the shared walk (#333). What stays here is this module's own
// evidence for them and the FS they are held against: templateFS, the //go:embed set this binary
// renders from.

// TestTemplates_NoHTMLInTitle guards the admin_users_* bug: markup in the {{define "title"}} block
// renders literally in the browser tab.
func TestTemplates_NoHTMLInTitle(t *testing.T) {
	guard.AssertTemplatesNoHTMLInTitle(t, templateFS, "template")
}

// TestTemplates_NoCsrfField guards the half of the CSRF token deletion that nothing else in this
// module observes. Measured here rather than assumed: restoring {{ .csrfField }} to all eight forms
// that carried it left every one of them green, across the handler tests and the integration suite,
// because both assert on the fields a page carries rather than on the absence of a stray one.
func TestTemplates_NoCsrfField(t *testing.T) {
	guard.AssertTemplatesNoCsrfField(t, templateFS, "template")
}

// TestTemplates_HtmlLangNotHardcoded guards the <html lang="en"> bug: page layouts must render the
// lang attribute from the active locale. This module's email layouts are exempt, being per-locale
// sibling files.
func TestTemplates_HtmlLangNotHardcoded(t *testing.T) {
	guard.AssertTemplatesHtmlLangNotHardcoded(t, templateFS, "template")
}

// TestTemplates_AreWellFormed holds this server's pages to well-formed HTML and to the
// accessibility rules a template can be held to unrendered, through
// core/guard.AssertWellFormedTemplates, which carries each rule and its reasoning (#617).
func TestTemplates_AreWellFormed(t *testing.T) {
	guard.AssertWellFormedTemplates(t, templateFS, "template", emailTemplates, pendingTemplates)
}

// emailTemplates are not pages: no rule reads them.
var emailTemplates = []string{"emails/", "layouts/email_layout.html"}

// pendingTemplates are the pages not yet brought under the rules (#617). The guard reports one that
// meets them all, so the list only shrinks, page by page, to nothing.
var pendingTemplates = []string{
	"account_activate_password.html", "account_register.html", "auth_error.html", "auth_otp.html",
	"auth_otp_enrollment.html", "auth_redirect_blocked.html", "consent.html", "error.html",
	"forgot_password.html", "form_post.html", "logout_consent.html", "not_found.html",
	"reset_password.html", "unauthorized.html",
}
