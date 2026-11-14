package web

import (
	"testing"

	"github.com/leodip/goiabada/core/guard"
	"github.com/leodip/goiabada/core/stylingcontract"
)

// The four rules below run in both servers and live once, in core/guard/template_lint.go, which
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
// lang attribute from the active locale, and the email layout from the language its text is written
// in.
func TestTemplates_HtmlLangNotHardcoded(t *testing.T) {
	guard.AssertTemplatesHtmlLangNotHardcoded(t, templateFS, "template")
}

// TestTemplates_NewTabLinksSaySo holds every link on this server's pages that opens a new tab to
// saying so to assistive technology, in built-in text: today the client's website, privacy policy and terms of service, each legal document the
// acceptance step links, and the authenticator apps on the two-factor setup page (#814 decision 13).
func TestTemplates_NewTabLinksSaySo(t *testing.T) {
	guard.AssertTemplatesNewTabLinksSaySo(t, templateFS, "template")
}

// TestTemplates_AreWellFormed holds this server's pages to well-formed HTML and to the
// accessibility rules a template can be held to unrendered, through
// core/guard.AssertWellFormedTemplates, which carries each rule and its reasoning (#617). Each page
// is read as served, in the layouts the handlers under ../internal render it in.
func TestTemplates_AreWellFormed(t *testing.T) {
	guard.AssertWellFormedTemplates(t, templateFS, "template", "../internal", emailTemplates)
}

// TestPages_NameOnlyClassesMainCSSDraws holds every class a page names to a rule in the
// served main.css, through core/guard.AssertClassesAreDrawn, so a misspelt or leftover class fails
// here rather than leaving an element undrawn (#617).
func TestPages_NameOnlyClassesMainCSSDraws(t *testing.T) {
	css, err := staticFS.ReadFile("static/main.css")
	if err != nil {
		t.Fatal(err)
	}
	guard.AssertClassesAreDrawn(t, css, emailTemplatesAsWalked(), templateFS)
}

// emailTemplatesAsWalked is emailTemplates as a walk of templateFS from its root spells them.
func emailTemplatesAsWalked() []string {
	walked := make([]string, 0, len(emailTemplates))
	for _, entry := range emailTemplates {
		walked = append(walked, "template/"+entry)
	}
	return walked
}

// emailTemplates are not pages: no rule reads them. An email's body is drawn by
// internal/emailtemplate, so the email layout is the one template an email has (#818).
var emailTemplates = []string{"layouts/email_layout.html"}

// TestTemplates_KeepTheStylingContract holds this server's pages to the styling contract,
// core/stylingcontract's lists for the auth server, through core/guard.AssertStylingContract: every
// page names its data-page value and carries it on <body>, every listed value has a page, every
// hook class promised here is drawn by some page, and main.css declares every variable (#816
// decision 7). Every page is in the contract.
func TestTemplates_KeepTheStylingContract(t *testing.T) {
	css, err := staticFS.ReadFile("static/main.css")
	if err != nil {
		t.Fatal(err)
	}
	guard.AssertStylingContract(t, templateFS, "template", "../internal", css, guard.StylingContract{
		Pages:     stylingcontract.PagesOn(stylingcontract.AuthServer),
		Classes:   stylingcontract.ClassesOn(stylingcontract.AuthServer),
		Variables: stylingcontract.Variables(),
	})
}
