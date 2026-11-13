package guard

// The rules AssertStylingContract enforces, over fixture trees walked through the same finder and
// reporting half the two servers' web packages reach: a tree breaking each rule, one keeping them
// all, and the walks that reach nothing.

import (
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// contractHandlers renders each fixture page in the layout a handler names, as the servers'
// handlers do.
var contractHandlers = fstest.MapFS{
	"handlers/pages.go": {Data: []byte(`package handlers

func pages() {
	r.RenderTemplate(w, req, "/layouts/card.html", "/sign_in.html", nil)
	r.RenderTemplate(w, req, "/layouts/card.html", "/consent.html", nil)
	r.RenderTemplate(w, req, "/layouts/card.html", "/admin_clients.html", nil)
	r.RenderTemplate(w, req, "/layouts/plain.html", "/error.html", nil)
}
`)},
}

const (
	contractCard = `<!DOCTYPE html><html lang="en"><head><title>{{template "title" .}}</title></head>` +
		`<body{{ with .dataPage }} data-page="{{ . }}"{{ end }}><main class="auth-page">{{template "body" .}}</main>` +
		`{{ with .brandFooter }}<footer class="brand-footer{{ if .Panel }} brand-footer-panel{{ end }}"></footer>{{ end }}` +
		`{{template "notice" .}}</body></html>`
	contractNotice = `{{define "notice"}}<p class="notice">Saved</p>{{end}}` +
		`{{define "unused"}}<p class="auth-lead">Unused</p>{{end}}`
	contractCSS = `:root{--color-canvas:#fff;--radius-control:.5rem}.x{color:var(--color-ink)}`
)

func contractOf(pages []string, classes []string, variables []string, outside []string) StylingContract {
	return StylingContract{Pages: pages, Classes: classes, Variables: variables, Outside: outside}
}

// auth-lead is drawn by no page in the contract: only by a partial no page calls, and by a class an
// action completes, auth-lead{{ .suffix }}, which draws some other class. page-title is drawn only
// by an admin page, outside the contract.
func TestStylingContract_TheGuardReportsEveryBrokenPromise(t *testing.T) {
	fsys := fstest.MapFS{
		"template/layouts/card.html":    {Data: []byte(contractCard)},
		"template/layouts/plain.html":   {Data: []byte(`<!DOCTYPE html><html lang="en"><head><title>{{template "title" .}}</title></head><body>{{template "body" .}}</body></html>`)},
		"template/partials/notice.html": {Data: []byte(contractNotice)},
		"template/sign_in.html": {Data: []byte(`{{define "title"}}Sign in{{end}}` + "\n" +
			`{{define "data-page"}}sgin-in{{end}}{{define "body"}}<h1 class="auth-title">Sign in</h1>{{end}}`)},
		"template/consent.html": {Data: []byte(`{{define "title"}}Consent{{end}}` +
			`{{define "body"}}<h1 class="auth-lead{{ .suffix }}">Consent</h1>{{end}}`)},
		"template/error.html": {Data: []byte(`{{define "title"}}Error{{end}}` +
			`{{define "data-page"}}error-{{ .code }}{{end}}{{define "body"}}<h1>Error</h1>{{end}}`)},
		"template/admin_clients.html": {Data: []byte(`{{define "title"}}Clients{{end}}` +
			`{{define "body"}}<h1 class="page-title">Clients</h1>{{end}}`)},
		"template/legal.html": {Data: []byte(`<!DOCTYPE html><html lang="en"><head><title>Legal</title></head>` +
			`<body data-page="{{ template "data-page" . }}"><h1>Legal</h1></body></html>{{define "data-page"}}legal-document{{end}}`)},
		"template/terms.html": {Data: []byte(`<!DOCTYPE html><html lang="en"><head><title>Terms</title></head>` +
			`<body data-page="{{ template "data-page" . }}"><h1>Terms</h1></body></html>{{define "data-page"}}legal-document{{end}}`)},
	}
	contract := contractOf(
		[]string{"sign-in", "consent", "error", "legal-document", "forgot-password"},
		[]string{"auth-page", "auth-title", "brand-footer-panel", "notice", "auth-lead", "page-title"},
		[]string{"--color-canvas", "--radius-control", "--color-ink", "--font-sans"},
		[]string{"admin_*.html", "settings_unavailable.html"},
	)

	report := Run(func(r Reporter) {
		assertStylingContract(r, fsys, "template", contractHandlers, []byte(contractCSS), contract)
	})

	require.True(t, report.Failed())
	require.False(t, report.Stopped, "the guard stopped: %s", report.Fatal)
	for _, want := range []string{
		`template/sign_in.html: line 2: names data-page "sgin-in", which the contract does not list for this server`,
		`template/consent.html: defines no "data-page" template; give it the page's data-page value`,
		`template/error.html: line 1: its "data-page" template writes more than the page's name; write the value alone`,
		`template/terms.html: line 1: names data-page "legal-document", which template/legal.html names too; give each page a value of its own`,
		`template/error.html: as served in template/layouts/plain.html, <body> carries no data-page; write data-page="{{ . }}" from .dataPage`,
		`data-page "sign-in": listed, and no page names it`,
		`data-page "consent": listed, and no page names it`,
		`data-page "forgot-password": listed, and no page names it`,
		`data-page "error": listed, and no page names it`,
		`hook class "auth-lead": promised, and no page in the contract draws it`,
		`hook class "page-title": promised, and no page in the contract draws it`,
		`--color-ink: promised, and main.css declares no such variable`,
		`--font-sans: promised, and main.css declares no such variable`,
		`settings_unavailable.html: listed as outside the contract, and no page there was reached; remove it from the list`,
	} {
		assert.Contains(t, report.Text(), want)
	}
	for _, kept := range []string{`"auth-page"`, `"auth-title"`, `"brand-footer-panel"`, `"notice"`, `--color-canvas`,
		`--radius-control`, `admin_clients.html`, `"legal-document":`, `admin_*.html`} {
		assert.NotContains(t, report.Text(), kept)
	}
}

func TestStylingContract_TheGuardPassesATreeKeepingEveryPromise(t *testing.T) {
	fsys := fstest.MapFS{
		"template/layouts/card.html":    {Data: []byte(contractCard)},
		"template/layouts/plain.html":   {Data: []byte(contractCard)},
		"template/partials/notice.html": {Data: []byte(contractNotice)},
		"template/sign_in.html": {Data: []byte(`{{define "title"}}Sign in{{end}}` +
			"{{define \"data-page\"}}\n  sign-in\n{{end}}" +
			`{{define "body"}}{{ if .x }}<h1 class="auth-title">Sign in</h1>{{ else }}<h1>Again</h1>{{ end }}{{end}}`)},
		"template/consent.html": {Data: []byte(`{{define "title"}}Consent{{end}}{{define "data-page"}}consent{{end}}` +
			`{{define "body"}}<h1>Consent</h1>{{end}}`)},
		"template/error.html": {Data: []byte(`{{define "title"}}Error{{end}}{{define "data-page"}}error{{end}}` +
			`{{define "body"}}<h1>Error</h1>{{end}}`)},
		"template/admin_clients.html": {Data: []byte(`{{define "title"}}Clients{{end}}` +
			`{{define "body"}}<h1 class="page-title">Clients</h1>{{end}}`)},
		"template/form_post.html": {Data: []byte(`{{define "data-page"}}form-post{{end}}<!DOCTYPE html><html lang="en">` +
			`<head><title>Post</title></head><body data-page="{{ template "data-page" . }}"><h1 class="auth-lead">Post</h1></body></html>`)},
		"template/emails/hello.html": {Data: []byte(`<p class="email-only">Hello</p>`)},
	}
	contract := contractOf(
		[]string{"sign-in", "consent", "error", "form-post"},
		[]string{"auth-page", "auth-title", "brand-footer-panel", "notice", "auth-lead"},
		[]string{"--color-canvas", "--radius-control"},
		[]string{"admin_*.html", "emails/"},
	)

	report := Run(func(r Reporter) {
		assertStylingContract(r, fsys, "template", contractHandlers, []byte(contractCSS), contract)
	})

	assert.False(t, report.Failed(), "a tree keeping every promise failed the guard: %s", report.Text())
}

// A walk that reaches no page, a contract every page is outside of, handlers that render nothing
// and a stylesheet declaring no variable each stop the guard, because it would be checking nothing.
func TestStylingContract_AWalkThatReachesNothingIsFatal(t *testing.T) {
	page := fstest.MapFS{
		"template/layouts/card.html": {Data: []byte(contractCard)},
		"template/sign_in.html":      {Data: []byte(`{{define "title"}}Sign in{{end}}{{define "data-page"}}sign-in{{end}}{{define "body"}}<h1>Sign in</h1>{{end}}`)},
	}
	contract := contractOf([]string{"sign-in"}, []string{"auth-page"}, []string{"--color-canvas"}, nil)

	for _, tc := range []struct {
		name     string
		fsys     fstest.MapFS
		handlers fstest.MapFS
		css      string
		contract StylingContract
		want     string
	}{
		{"no page under the root", fstest.MapFS{"template/page.js": {Data: []byte(`x()`)}}, contractHandlers,
			contractCSS, contract, "walked no .html files under template"},
		{"every page outside the contract", page, contractHandlers, contractCSS,
			contractOf(contract.Pages, contract.Classes, contract.Variables, []string{"sign_in.html"}),
			"every page under template is outside the contract"},
		{"no handler rendering a page", page, fstest.MapFS{"handlers/none.go": {Data: []byte("package handlers\n")}},
			contractCSS, contract, "found no RenderTemplate call naming a layout and a page"},
		{"a stylesheet declaring no variable", page, contractHandlers, `.x{color:red}`, contract,
			"the stylesheet declares no variable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := Run(func(r Reporter) {
				assertStylingContract(r, tc.fsys, "template", tc.handlers, []byte(tc.css), tc.contract)
			})

			require.True(t, report.Stopped, "the guard did not stop: %s", report.Text())
			assert.Contains(t, report.Fatal, tc.want)
			assert.Contains(t, report.Fatal, "this guard is checking nothing")
		})
	}
}

// A variable is declared where a stylesheet sets it, and only there: a var() reading it, a
// comment or a string naming it, and a longer name beginning with it declare nothing.
func TestStylingContract_AVariableIsDeclaredWhereAStylesheetSetsIt(t *testing.T) {
	declared := declaredVariables(`/* --in-comment: 1 */ :root{--a:1; --b : 2;--a-longer:3}` +
		`.x{color:var(--read);content:"--in-string: 4"} @media (min-width:1px){:root{--c:5}}`)

	assert.Equal(t, map[string]bool{"--a": true, "--b": true, "--a-longer": true, "--c": true}, declared)
}
