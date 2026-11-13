// Package stylingcontract holds the styling contract (#816): what a brand's custom CSS can rely on
// from release to release on every page it reaches, the auth server's pages and the admin console's
// end-user pages. It is three lists: the CSS variables, the data-page value each of those pages
// carries on its <body>, and the hook classes. The docs' Styling contract page publishes them, a
// docs test holds the page to them, and core/guard.AssertStylingContract holds both servers'
// templates to them in each server's unit tier.
//
// The lists promise what a restyle reaches for, the pages' structure and the components every page
// shares, and leave free to change what only one page draws. Tailwind utility classes are never
// promised. Removing or renaming an entry of any list is a breaking change for the release notes.
package stylingcontract

import (
	"html/template"
	"strings"
	"text/template/parse"
)

// Server is a server whose pages the contract covers.
type Server string

const (
	// AuthServer draws the sign-in pages and every other page of its own.
	AuthServer Server = "auth server"
	// AdminConsole draws the Account pages and its cards: its home page, and its error and sign-out
	// pages. Its admin pages are outside the contract, since custom CSS never reaches them, and so is
	// the page it draws with no brand at all, for settings it cannot read.
	AdminConsole Server = "admin console"
)

// variables are the CSS variables the contract promises: the 23 color tokens, the two radii a
// brand's corners set, the font family and the two shadows. --radius-box, worked out from
// --radius-control, and --app-header-height, which the console's scroll offset depends on, are not
// promised.
var variables = []string{
	"--color-canvas", "--color-surface", "--color-subtle", "--color-line", "--color-line-strong",
	"--color-ink", "--color-ink-muted",
	"--color-brand", "--color-brand-strong", "--color-on-brand", "--color-brand-soft",
	"--color-danger", "--color-danger-strong", "--color-on-danger", "--color-danger-soft", "--color-danger-ink",
	"--color-positive-soft", "--color-positive-ink", "--color-caution-soft", "--color-caution-ink",
	"--color-note-soft", "--color-note-ink",
	"--color-focus",
	"--radius-control", "--radius-panel",
	"--font-sans",
	"--shadow-panel", "--shadow-overlay",
}

// Variables answers the CSS variables the contract promises, in the order the reference page lists
// them, as a copy the caller may change.
func Variables() []string {
	return append([]string(nil), variables...)
}

// pageGroup is a group of pages in the contract and the data-page value of each, one per page
// template, whatever state the page is drawn in.
type pageGroup struct {
	Name   string
	Server Server
	Pages  []string
}

// pageGroups are the contract's pages. Every console value has a prefix, so no two pages share a
// value and a prefix selects a group.
var pageGroups = []pageGroup{
	{Name: "Auth server pages", Server: AuthServer, Pages: []string{
		"sign-in", "one-time-code", "authenticator-setup", "recovery-code", "new-recovery-codes",
		"consent", "legal-acceptance", "legal-document",
		"register", "register-check-email", "register-success", "activation-result", "activate-account",
		"forgot-password", "reset-password",
		"sign-in-error", "redirect-blocked",
		"sign-out", "sign-out-declined", "signed-out",
		"form-post", "error", "not-found",
	}},
	{Name: "Account pages", Server: AdminConsole, Pages: []string{
		"account-profile", "account-email", "account-email-verification", "account-phone",
		"account-address", "account-password", "account-authenticator", "account-picture",
		"account-consents", "account-legal-documents", "account-sessions", "account-data",
		"account-delete", "account-deleted",
	}},
	{Name: "Other console pages", Server: AdminConsole, Pages: []string{
		"console-home", "console-sign-out", "console-sign-out-form-post", "console-sign-in-error",
		"console-unauthorized", "console-error", "console-not-found",
	}},
}

// hookClass is a class the contract promises, and the servers whose pages draw it.
type hookClass struct {
	Name    string
	Servers []Server
}

// classGroup is a group of hook classes.
type classGroup struct {
	Name    string
	Classes []hookClass
}

var (
	bothServers  = []Server{AuthServer, AdminConsole}
	authServer   = []Server{AuthServer}
	adminConsole = []Server{AdminConsole}
)

// classGroups are the contract's hook classes, each promised on the servers whose pages draw it
// today: a class one server's pages never draw is promised on the other's alone.
var classGroups = []classGroup{
	{Name: "Card layout", Classes: []hookClass{
		{"auth-page", bothServers}, {"auth-main", bothServers}, {"auth-card", bothServers},
		{"auth-logo", bothServers}, {"auth-brand", bothServers}, {"auth-title", bothServers},
		{"auth-lead", bothServers}, {"auth-status", bothServers}, {"auth-actions", bothServers},
		{"auth-footer", authServer},
	}},
	{Name: "Client block", Classes: []hookClass{
		{"auth-client", authServer}, {"auth-client-logo", authServer}, {"auth-client-name", authServer},
		{"auth-client-description", authServer},
	}},
	{Name: "Brand footer", Classes: []hookClass{
		{"brand-footer", bothServers}, {"brand-footer-panel", bothServers}, {"brand-footer-links", bothServers},
		{"brand-footer-link", bothServers}, {"brand-footer-contact", bothServers},
	}},
	{Name: "Components", Classes: []hookClass{
		{"panel", bothServers}, {"button", bothServers}, {"button-primary", bothServers},
		{"button-danger", adminConsole}, {"button-quiet", adminConsole},
		{"field", bothServers}, {"field-label", bothServers}, {"field-hint", bothServers},
		{"control", bothServers}, {"input-row", bothServers},
		{"notice", bothServers}, {"notice-danger", bothServers}, {"notice-positive", adminConsole},
		{"notice-caution", bothServers}, {"notice-note", authServer},
		{"status-icon", bothServers}, {"text-link", bothServers},
		{"check-list", authServer}, {"check-row", authServer},
	}},
	{Name: "Account shell", Classes: []hookClass{
		{"app-shell", adminConsole}, {"app-header", adminConsole}, {"app-sidebar", adminConsole},
		{"app-main", adminConsole}, {"app-footer", adminConsole}, {"page-header", adminConsole},
		{"page-title", adminConsole},
	}},
}

// PagesOn answers the data-page values of server's pages, every group's in order.
func PagesOn(server Server) []string {
	var pages []string
	for _, g := range pageGroups {
		if g.Server == server {
			pages = append(pages, g.Pages...)
		}
	}
	return pages
}

// ClassesOn answers the hook classes promised on server's pages, every group's in order.
func ClassesOn(server Server) []string {
	var classes []string
	for _, g := range classGroups {
		for _, c := range g.Classes {
			for _, s := range c.Servers {
				if s == server {
					classes = append(classes, c.Name)
				}
			}
		}
	}
	return classes
}

// PageTemplate is the template a page in the contract defines to name itself, holding its
// data-page value and nothing else: {{define "data-page"}}sign-in{{end}}. A layout writes the value
// on <body> from the dataPage the renderer binds, and a page parsed alone writes it from the
// template itself.
const PageTemplate = "data-page"

// PageName answers the data-page value a parsed page names: the text of its PageTemplate, the
// space around it trimmed. It answers "" for a page that defines none, as an admin page or a
// template copied from an older release, and for one whose template writes anything but text.
func PageName(t *template.Template) string {
	page := t.Lookup(PageTemplate)
	if page == nil || page.Tree == nil || page.Tree.Root == nil {
		return ""
	}
	var name strings.Builder
	for _, node := range page.Tree.Root.Nodes {
		text, ok := node.(*parse.TextNode)
		if !ok {
			return ""
		}
		name.Write(text.Text)
	}
	return strings.TrimSpace(name.String())
}
