package web

import (
	"testing"

	"github.com/leodip/goiabada/core/guard"
	"github.com/leodip/goiabada/core/stylingcontract"
)

// The four rules below run in both servers and live once, in core/guard/template_lint.go, which
// carries each one's reasoning and the shared walk (#333). What stays here is this module's own
// evidence for them and the FS they are held against: templateFS, the //go:embed set this binary
// renders from. #105's check on the redirect URI and web origin cells was here too, until #120's
// html_sink_lint_test.go took over what it held, on every page.

// TestTemplates_NoHTMLInTitle guards the admin_users_* bug: markup in the {{define "title"}} block
// renders literally in the browser tab.
func TestTemplates_NoHTMLInTitle(t *testing.T) {
	guard.AssertTemplatesNoHTMLInTitle(t, templateFS, "template")
}

// TestTemplates_NoCsrfField guards the half of the CSRF token deletion that nothing else in this
// module observes. Measured here rather than assumed: restoring {{ .csrfField }} to
// account_phone.html, which TestRender_AccountPhone and TestRender_JSBootstrapNoKeyLeak both render
// from a bind map that no longer carries it, left the whole adminconsole tier green. The bind side
// of the same deletion is guarded by internal/handlers/csrf_lint_test.go, which draws the same
// lexical boundary.
func TestTemplates_NoCsrfField(t *testing.T) {
	guard.AssertTemplatesNoCsrfField(t, templateFS, "template")
}

// TestTemplates_HtmlLangNotHardcoded guards the <html lang="en"> bug: page layouts must render the
// lang attribute from the active locale. This module sends no email, so it has no email layout.
func TestTemplates_HtmlLangNotHardcoded(t *testing.T) {
	guard.AssertTemplatesHtmlLangNotHardcoded(t, templateFS, "template")
}

// TestTemplates_NewTabLinksSaySo holds every link on this server's pages that opens a new tab to
// saying so to assistive technology, in built-in text: today the authenticator apps on the Account pages' two-factor setup page (#814 decision 13).
func TestTemplates_NewTabLinksSaySo(t *testing.T) {
	guard.AssertTemplatesNewTabLinksSaySo(t, templateFS, "template")
}

// TestTemplates_AreWellFormed holds this server's pages to well-formed HTML and to the
// accessibility rules a template can be held to unrendered, through
// core/guard.AssertWellFormedTemplates, which carries each rule and its reasoning (#617). Each page
// is read as served, in the layouts the handlers under ../internal render it in.
func TestTemplates_AreWellFormed(t *testing.T) {
	guard.AssertWellFormedTemplates(t, templateFS, "template", "../internal", nil)
}

// TestPages_NameOnlyClassesMainCSSDraws holds every class a page names to a rule in the
// served main.css, through core/guard.AssertClassesAreDrawn, so a misspelt or leftover class fails
// here rather than leaving an element undrawn (#617).
func TestPages_NameOnlyClassesMainCSSDraws(t *testing.T) {
	css, err := staticFS.ReadFile("static/main.css")
	if err != nil {
		t.Fatal(err)
	}
	guard.AssertClassesAreDrawn(t, css, nil, templateFS)
}

// TestTemplates_KeepTheStylingContract holds this server's end-user pages to the styling contract,
// core/stylingcontract's lists for the admin console, through core/guard.AssertStylingContract:
// every Account page and card names its data-page value and carries it on <body>, every listed
// value has a page, every hook class promised here is drawn by some page, and main.css declares
// every variable (#816 decisions 6 and 7). The admin pages are outside the contract, since custom
// CSS never reaches them, and so is the page for unreadable settings, drawn with no brand at all.
func TestTemplates_KeepTheStylingContract(t *testing.T) {
	css, err := staticFS.ReadFile("static/main.css")
	if err != nil {
		t.Fatal(err)
	}
	guard.AssertStylingContract(t, templateFS, "template", "../internal", css, guard.StylingContract{
		Pages:     stylingcontract.PagesOn(stylingcontract.AdminConsole),
		Classes:   stylingcontract.ClassesOn(stylingcontract.AdminConsole),
		Variables: stylingcontract.Variables(),
		Outside:   []string{"admin_*.html", "settings_unavailable.html"},
	})
}
