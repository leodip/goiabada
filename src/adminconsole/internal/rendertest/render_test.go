// Package rendertest executes the localized account pages through the
// real template renderer (funcmap + embedded template FS + full layout), in
// pt-BR, with the actual runtime data types. This is the regression guard for
// the class of bug where a template references a field its data doesn't carry
// (e.g. the phone dropdown referencing .Alpha2 on a DTO that lacked it, which
// 500'd in production but was invisible to mocked handler tests).
package rendertest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/accounthandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminclienthandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminsettingshandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminuserhandlers"
	adminmiddleware "github.com/leodip/goiabada/adminconsole/internal/middleware"
	"github.com/leodip/goiabada/adminconsole/internal/pagination"
	web "github.com/leodip/goiabada/adminconsole/web"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/countries"
	"github.com/leodip/goiabada/core/handlerhelpers"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/locales"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/timezones"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	if _, err := i18n.LoadBundle(); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

// rawKeyRe matches a leaked catalog key (dotted, in visible HTML).
var rawKeyRe = regexp.MustCompile(`\b(adminconsole|common|auth|account|admin|consent|validator|handler|email|system)\.[a-z0-9_]+(?:\.[a-z0-9_]+)+`)

func render(t *testing.T, page string, bind map[string]interface{}) string {
	t.Helper()
	return renderWithLayout(t, "/layouts/menu_layout.html", page, bind)
}

// renderWithLayout is render with the layout named, for the one page that is not a menu page: the
// logout form binding renders under no_menu_layout, the same layout the 404 and 500 pages use.
func renderWithLayout(t *testing.T, layout, page string, bind map[string]interface{}) string {
	t.Helper()
	return renderWithLayoutAs(t, layout, page, bind, nil)
}

// renderWithLayoutAs is renderWithLayout with an ID token on the context, which is how every
// authenticated page reaches the renderer in production: JwtSessionHandler puts an oauth.JwtInfo
// there and HttpHelper.RenderTemplateToBuffer turns its claims into the `loggedInUser` bind that
// menu_layout.html reads for the dropdown label. Passing nil claims is the anonymous request, which
// is what every other case in this file renders and why the label is blank in all of them.
func renderWithLayoutAs(t *testing.T, layout, page string, bind map[string]interface{},
	idTokenClaims jwt.MapClaims) string {

	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	settings := &api.PublicSettingsResponse{AppName: "Test", UITheme: "dark", SMTPEnabled: true}
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, settings))
	if idTokenClaims != nil {
		jwtInfo := oauth.JwtInfo{IdToken: &oauth.JwtToken{Claims: idTokenClaims}}
		req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, jwtInfo))
	}
	req = i18n.RefineLocalizerWithUILocales(req, []string{"pt-BR"})

	h := handlerhelpers.NewHttpHelper(web.TemplateFS(), adminmiddleware.SettingsReader{})
	buf, err := h.RenderTemplateToBuffer(req, layout, page, bind)
	require.NoErrorf(t, err, "render %s in pt-BR (template referenced data the bind lacks?)", page)

	out := buf.String()
	// <html lang> must reflect the active locale, not "en".
	assert.Containsf(t, out, `lang="pt-BR"`, "%s: <html lang> not localized", page)
	// No raw catalog key should leak into visible HTML (scripts hold the JS
	// bootstrap keys legitimately, so strip them first).
	visible := regexp.MustCompile(`(?s)<script.*?</script>`).ReplaceAllString(out, "")
	if leak := rawKeyRe.FindString(visible); leak != "" {
		t.Errorf("%s: raw i18n key leaked into visible HTML: %q", page, leak)
	}
	return out
}

// The 404 page, end to end: the real HttpHelper.NotFound over the real embedded template FS, at the
// HTTP seam. Everything else in this file renders a bind through RenderTemplateToBuffer, which
// cannot see a status; this one has to, because the status is half of what decision 11 changed and
// the console is invisible to the integration tier, which drives the auth server and only ever
// mentions the console's base URL as a string to assert against (#279).
func TestRender_NotFoundPage(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/clients/not-a-number/settings", nil)
	settings := &api.PublicSettingsResponse{AppName: "Test", UITheme: "dark", SMTPEnabled: true}
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, settings))
	req = i18n.RefineLocalizerWithUILocales(req, []string{"pt-BR"})

	w := httptest.NewRecorder()
	handlerhelpers.NewHttpHelper(web.TemplateFS(), adminmiddleware.SettingsReader{}).NotFound(w, req)

	res := w.Result()
	defer func() { _ = res.Body.Close() }()

	require.Equal(t, http.StatusNotFound, res.StatusCode)
	assert.Equal(t, "text/html; charset=UTF-8", res.Header.Get("Content-Type"))

	out := w.Body.String()
	assert.Containsf(t, out, `lang="pt-BR"`, "the 404 page's <html lang> is not localized")
	assert.Contains(t, out, "Não encontrado (404)")

	visible := regexp.MustCompile(`(?s)<script.*?</script>`).ReplaceAllString(out, "")
	if leak := rawKeyRe.FindString(visible); leak != "" {
		t.Errorf("raw i18n key leaked into the 404 page: %q", leak)
	}

	// Nothing of the rejected URL reaches the page, and no request id: there is no log line for one
	// to join it to, which is the whole of decision 11's "no log line".
	assert.NotContains(t, out, "not-a-number")
}

func TestRender_AccountPhone(t *testing.T) {
	bind := map[string]interface{}{
		"selectedPhoneCountryUniqueId": "",
		"phoneNumber":                  "",
		"phoneCountries": []api.PhoneCountryResponse{
			{UniqueId: "BRA_0", Alpha2: "BR", Emoji: "🇧🇷", CallingCode: "+55", Name: "🇧🇷 - Brazil (+55)"},
			{UniqueId: "ITA_0", Alpha2: "IT", Emoji: "🇮🇹", CallingCode: "+39", Name: "🇮🇹 - Italy (+39)"},
		},
		"savedSuccessfully": false,
	}
	out := render(t, "/account_phone.html", bind)
	// html/template escapes "+" to "&#43;", so assert on the emoji + localized
	// country name (the part the phone-500 bug and the CLDR work affect).
	assert.Contains(t, out, "🇧🇷 - Brasil") // RefPhoneCountry: CLDR-localized name
	assert.Contains(t, out, "🇮🇹 - Itália") // RefPhoneCountry: CLDR-localized name
}

func TestRender_AccountAddress(t *testing.T) {
	bind := map[string]interface{}{
		"user": &api.UserResponse{},
		"address": map[string]interface{}{
			"AddressLine": "", "AddressLocality": "", "AddressRegion": "",
			"AddressPostalCode": "", "AddressCountry": "BR",
		},
		"countries":         countries.AllInfo(),
		"savedSuccessfully": false,
	}
	out := render(t, "/account_address.html", bind)
	assert.Contains(t, out, "Itália") // RefCountry: CLDR-localized name
	assert.Contains(t, out, "México")
}

func TestRender_AccountProfile(t *testing.T) {
	bind := map[string]interface{}{
		"user":              &api.UserResponse{},
		"timezones":         timezones.Get(),
		"locales":           locales.Get(),
		"savedSuccessfully": false,
	}
	out := render(t, "/account_profile.html", bind)
	assert.Contains(t, out, "português (Brasil) (Portuguese (Brazil))") // LocaleLabel
	assert.Contains(t, out, "Estados Unidos")                           // RefTimezone country portion localized
}

// TestRender_AdminClients is the template hop of the self-registered badge. The pipeline from the
// database to this page is the client row, then apimapping.ToClientResponse, then that value straight into
// the template, since HandleAdminClientsGet binds "clients" and does no adminconsole-side mapping.
// So rendering the real page over two real api.ClientResponse values is what proves the badge is
// driven by CreatedViaDCR: an ordinary client next to a self-registered one is the case that fails
// if the conditional is dropped and every client gets marked (#108).
func TestRender_AdminClients(t *testing.T) {
	bind := map[string]interface{}{
		"clients": []api.ClientResponse{
			{Id: 1, ClientIdentifier: "dcr_a3f9e1b2", Enabled: true, CreatedViaDCR: true},
			{Id: 2, ClientIdentifier: "web-app", Enabled: true, CreatedViaDCR: false},
		},
	}
	out := render(t, "/admin_clients.html", bind)

	// Both clients render, so the count is what carries the claim: one badge, not two and not zero.
	assert.Equal(t, 1, strings.Count(out, "Autorregistrado"),
		"the self-registered badge must appear for the DCR client and only for it")
	assert.Contains(t, out, "dcr_a3f9e1b2")
	assert.Contains(t, out, "web-app")
}

// TestRender_JSBootstrapNoKeyLeak guards the window.i18n bootstrap: every value
// must be a real string, never its own key. A value == key means JSBootstrap
// failed to resolve a message (the {{param}}-placeholder bug where T executed
// the string as a template and leaked the key).
func TestRender_JSBootstrapNoKeyLeak(t *testing.T) {
	bind := map[string]interface{}{
		"selectedPhoneCountryUniqueId": "",
		"phoneNumber":                  "",
		"phoneCountries":               []api.PhoneCountryResponse{},
		"savedSuccessfully":            false,
	}
	out := render(t, "/account_phone.html", bind)

	m := regexp.MustCompile(`window\.i18n=(\{.*?\});`).FindStringSubmatch(out)
	require.Len(t, m, 2, "window.i18n bootstrap script not found in output")
	var kv map[string]string
	require.NoError(t, json.Unmarshal([]byte(m[1]), &kv))
	require.NotEmpty(t, kv)

	for k, v := range kv {
		assert.NotEqualf(t, k, v, "js bootstrap key %q leaked (value == key): JSBootstrap could not resolve it", k)
	}
}

// The enrolment form shows the QR code and the seed, and carries neither back as a hidden input.
//
// Both halves need HTML to see, which is why they are here rather than in the handler's own tests:
// a mocked RenderTemplate is handed a bind map, and a bind map cannot tell you whether a value was
// drawn for the user to scan or planted in a form for the browser to post back.
//
// The hidden inputs are what #247 removed. They put the TOTP shared secret and an image encoding it
// into the submitted body of every enrolment attempt, on a page that then let the server enrol
// whatever came back. The visible <img> and <pre> stay: those are what the user scans and types.
func TestRender_AccountOtp_Enrollment(t *testing.T) {
	const secretKey = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

	out := render(t, "/account_otp.html", map[string]interface{}{
		"otpEnabled":  false,
		"base64Image": "aW1hZ2UtYnl0ZXM=",
		"secretKey":   secretKey,
		"error":       "OTP code is required.",
	})

	assert.Contains(t, out, "data:image/png;base64,aW1hZ2UtYnl0ZXM=", "the QR code must be shown")
	assert.Contains(t, out, secretKey, "and the seed, for a user who cannot scan it")
	assert.Contains(t, out, `name="otp"`)
	assert.Contains(t, out, `name="password"`)

	assert.NotContains(t, out, `type="hidden"`,
		"the enrolment form must post nothing the user did not type")
	assert.NotContains(t, out, `name="secretKey"`)
	assert.NotContains(t, out, `name="base64Image"`)
}

// The enabled state carries neither, whatever the bind map happens to hold: a user with an
// authenticator is not enrolling, and the page is a disable form.
func TestRender_AccountOtp_Enabled(t *testing.T) {
	out := render(t, "/account_otp.html", map[string]interface{}{
		"otpEnabled": true,
		"error":      "Authentication failed. Check your password and try again.",
	})

	assert.NotContains(t, out, "data:image/png;base64,")
	assert.NotContains(t, out, `name="otp"`)
	assert.Contains(t, out, `name="password"`)
}

// TestRender_AdminClientRedirectURIs is the template hop of the redirect-flow gate. The handler
// resolves the per-client implicit override against the global setting and binds one boolean, so
// what is left to prove here is that the page shows the form for a client that can redirect and
// the explaining sentence for one that cannot (#250). render's own raw-key check is what proves
// the new catalog key exists in pt-BR: a missing key leaks its own name into the HTML.
func TestRender_AdminClientRedirectURIs(t *testing.T) {

	page := func(canManage bool) string {
		return render(t, "/admin_clients_redirect_uris.html", map[string]interface{}{
			"client": struct {
				ClientId              int64
				ClientIdentifier      string
				CanManageRedirectURIs bool
				RedirectURIs          map[int64]string
				IsSystemLevelClient   bool
			}{
				ClientId:              7,
				ClientIdentifier:      "an-implicit-app",
				CanManageRedirectURIs: canManage,
				RedirectURIs:          map[int64]string{1: "https://example.com/cb"},
			},
			"savedSuccessfully": false,
		})
	}

	manageable := page(true)
	assert.Contains(t, manageable, "redirectURIsEnabledPanel")
	assert.Contains(t, manageable, `id="btnSave"`)
	assert.NotContains(t, manageable, "URIs de redirecionamento são usadas pelo fluxo")

	blocked := page(false)
	assert.NotContains(t, blocked, "redirectURIsEnabledPanel")
	assert.NotContains(t, blocked, `id="btnSave"`)
	// The sentence names both redirect-based flows, which is the whole point of the change:
	// an implicit-only administrator used to be told to enable a flow their client never uses.
	assert.Contains(t, blocked, "URIs de redirecionamento são usadas pelo fluxo authorization code com PKCE e pelo fluxo implicit.")
}

// The Web Origins page has no gate left and shows two lists: this client's editable rows, and the
// effective server-wide list every client's origins land in. This case proves the template can
// display what it is handed; that the handler assembles the server-wide list at all is proved in
// handler_admin_client_web_origins_test.go, because a bind written by the test cannot see a fetch
// that was deleted (#250).
func TestRender_AdminClientWebOrigins(t *testing.T) {

	type effectiveWebOrigin struct {
		Origin           string
		ClientIdentifier string
	}

	out := render(t, "/admin_clients_web_origins.html", map[string]interface{}{
		"client": struct {
			ClientId            int64
			ClientIdentifier    string
			WebOrigins          map[int64]string
			EffectiveWebOrigins []effectiveWebOrigin
			IsSystemLevelClient bool
		}{
			ClientId:         7,
			ClientIdentifier: "a-javascript-app",
			WebOrigins:       map[int64]string{1: "https://mine.example.com"},
			EffectiveWebOrigins: []effectiveWebOrigin{
				{Origin: "https://mine.example.com", ClientIdentifier: "a-javascript-app"},
				{Origin: "https://theirs.example.com", ClientIdentifier: "another-app"},
			},
		},
		"savedSuccessfully": false,
	})

	// The form renders unconditionally now. This client has the authorization code flow off,
	// which the bind no longer even carries, and it still gets the form and the save button:
	// needing a web origin is about the app being JavaScript in a browser, not about any flow.
	assert.Contains(t, out, "webOriginsEnabledPanel")
	assert.Contains(t, out, `id="btnSave"`)

	// Another client's origin is visible here, and the sentence above the list says why an
	// origin registered anywhere is honoured everywhere. Without both, the page still implies
	// a per-client scoping the server does not honour.
	assert.Contains(t, out, "https://theirs.example.com")
	assert.Contains(t, out, "another-app")
	assert.Contains(t, out, "Origens permitidas em todo o servidor")
	assert.Contains(t, out, "é permitida para todos os clientes")

	// The intro says the value is a bare origin rather than a URL, which is where the trailing
	// slash that CORS can never match used to come from.
	assert.Contains(t, out, "sem nada depois do host")
}

// TestRender_AdminUsersPaginator is the template hop of the paginator swap (#271): the partial is
// unchanged and now reads a *pagination.Paginator instead of the unmaintained library's value, so
// what needs proving is that a Go template resolves the replacement's exported fields the way it
// resolved the library's niladic methods, and that addUrlParam turns them into page links.
//
// 73 users at 10 a page on page 4 is 8 pages, which exercises both ends of the bar at once:
// "1 2 3 [4] 5 6 ...". The lone "1" is decision 3's rule, the one place this change departs from
// the library, which would have put dots there and left page 1 reachable only by walking back.
func TestRender_AdminUsersPaginator(t *testing.T) {
	out := render(t, "/admin_users.html", map[string]interface{}{
		"pageResult": adminuserhandlers.PageResult{
			// Subject is left empty: the row only has to render.
			Users:    []api.UserResponse{{Id: 1, Username: "alice", Email: "alice@example.com"}},
			Total:    73,
			Query:    "",
			Page:     4,
			PageSize: 10,
		},
		"paginator": pagination.New(73, 10, 4, 5),
	})

	// Page 1 is a link, not dots. Reverting the rule renders "..." here instead.
	assert.Contains(t, out, `href="/admin/users?page=1"`)
	assert.Contains(t, out, `href="/admin/users?page=2"`)
	assert.Contains(t, out, `href="/admin/users?page=6"`)

	// One set of dots, at the trailing end, standing for pages 7 and 8. btn-disabled is the
	// partial's ellipsis class and nothing else on this page uses it.
	assert.Equal(t, 1, strings.Count(out, "btn-disabled"), "expected exactly one ellipsis in the bar")
	assert.Contains(t, out, ">...</a>")

	// Pages 3 and 5 are each a number link and an arrow target, so two occurrences each. That
	// count is what says Previous and Next resolved at all: a field the template cannot read
	// renders as nothing and would leave one.
	assert.Equal(t, 2, strings.Count(out, `href="/admin/users?page=3"`), "page 3 as a number and as the back arrow")
	assert.Equal(t, 2, strings.Count(out, `href="/admin/users?page=5"`), "page 5 as a number and as the forward arrow")

	// The current page is the active button and carries no link of its own.
	assert.Contains(t, out, `class="join-item btn btn-sm btn-active">4</a>`)
	assert.NotContains(t, out, `href="/admin/users?page=4"`)

	// The -1 sentinel must never reach addUrlParam: it means "ellipsis", not a page.
	assert.NotContains(t, out, "page=-1")
}

// TestRender_AdminSettingsAuditLogViewer is seam 8's rendering half (#328). The page test
// above the handler drives a mocked HttpHelper and therefore renders nothing, so the three
// things that can only go wrong in HTML are proved here: the fourth column carries each
// row's request id, an entry written off a request shows a dash rather than an empty cell,
// and an id echoed back into the filter input is escaped. The id is whatever a client put
// in X-Request-Id, so the escaping is the one thing on this page standing between a stored
// id and script in an administrator's browser.
func TestRender_AdminSettingsAuditLogViewer(t *testing.T) {
	out := render(t, "/admin_settings_audit_log_viewer.html", map[string]interface{}{
		"pageResult": adminsettingshandlers.AuditLogsPageResult{
			AuditLogs: []api.AuditLogResponse{
				{Id: 1, CreatedAt: "2026-09-12T10:00:00Z", AuditEvent: "user_login",
					Details: `{"email":"alice@example.com"}`, RequestId: "host/Ppg6bHPK5f-000012"},
				{Id: 2, CreatedAt: "2026-09-12T10:00:01Z", AuditEvent: "revoked_user_auth_state",
					Details: `{}`, RequestId: ""},
			},
			Total:      73,
			Page:       4,
			PageSize:   20,
			AuditEvent: "user_login",
			RequestId:  `"><script>alert(1)</script>`,
		},
		"paginator":         pagination.New(73, 20, 4, 5),
		"selectedEvent":     "user_login",
		"selectedRequestId": `"><script>alert(1)</script>`,
		"paginatorLink": "/admin/settings/audit-log-viewer?auditEvent=user_login&requestId=" +
			url.QueryEscape(`"><script>alert(1)</script>`),
		"auditEventTypes": []string{"user_login", "revoked_user_auth_state"},
	})

	// The column exists and is localized: pt-BR, like every other page in this file.
	assert.Contains(t, out, "Id da requisição")

	// Each row's id, and the dash standing for "not written on a request".
	assert.Contains(t, out, "host/Ppg6bHPK5f-000012")
	assert.Contains(t, out, ">-</td>")

	// The id typed into the filter comes back into the input escaped. The raw sequence
	// would close the value attribute and open a script element; the escaped one cannot.
	assert.NotContains(t, out, `<script>alert(1)</script>`)
	assert.Contains(t, out, "&#34;&gt;&lt;script&gt;alert(1)&lt;/script&gt;")

	// The paginator's links carry both filters, escaped, and the page number is the only
	// "page" in them: an id holding "&page=" would otherwise win over the real one.
	assert.Contains(t, out, "requestId=%22%3E%3Cscript%3Ealert%281%29%3C%2Fscript%3E")
	assert.Contains(t, out, "auditEvent=user_login")
	assert.NotContains(t, out, "page=-1")
}

// The Device cell's tooltip, on all three session pages at once.
//
// The raw User-Agent is attacker-chosen: it is a request header copied into the row verbatim, so
// the one thing that needs proving about showing it is that it stays an attribute value. A header
// carrying a quote and an angle bracket is what would break out of title="..." if the cell were
// ever built by concatenation or marked safe, and only rendered HTML can see that (#281 decision 6).
//
// The three pages are one case because they carry one edit between them: the same <td>, in three
// files, and a tooltip added to two of the three is the shape this guards against.
func TestRender_SessionPagesTooltipTheRawUserAgent(t *testing.T) {
	const header = `Mozilla/5.0 "odd" <build>`
	const escaped = `Mozilla/5.0 &#34;odd&#34; &lt;build&gt;`

	for _, tc := range []struct {
		name string
		page string
		bind map[string]interface{}
	}{
		{
			name: "account",
			page: "/account_user_sessions.html",
			bind: map[string]interface{}{
				"sessions": []accounthandlers.SessionInfo{{
					UserSessionId: 1, DeviceName: "Chrome 120", DeviceType: "Desktop",
					DeviceOS: "Linux", UserAgent: header,
				}},
			},
		},
		{
			name: "admin user",
			page: "/admin_users_sessions.html",
			bind: map[string]interface{}{
				"user": &api.UserResponse{Id: 7, Email: "someone@example.com"},
				"sessions": []adminuserhandlers.SessionInfo{{
					UserSessionId: 1, DeviceName: "Chrome 120", DeviceType: "Desktop",
					DeviceOS: "Linux", UserAgent: header,
				}},
				"page":  "1",
				"query": "",
			},
		},
		{
			name: "admin client",
			page: "/admin_clients_usersessions.html",
			bind: map[string]interface{}{
				"client": &api.ClientResponse{Id: 3, ClientIdentifier: "web-app"},
				"sessions": []adminclienthandlers.SessionInfo{{
					UserSessionId: 1, UserId: 7, UserEmail: "someone@example.com",
					DeviceName: "Chrome 120", DeviceType: "Desktop",
					DeviceOS: "Linux", UserAgent: header,
				}},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := render(t, tc.page, tc.bind)

			// The tooltip is on the Device cell, which is also what carries the labels.
			assert.Containsf(t, out, `<td title="`+escaped+`">Chrome 120 Desktop Linux`,
				"%s: the Device cell carries no User-Agent tooltip", tc.page)

			// And the header never reaches the page as markup. Counting the escaped form is
			// what says so: one occurrence, and no unescaped one anywhere.
			assert.Equal(t, 1, strings.Count(out, escaped),
				"the header belongs in the tooltip and nowhere else")
			assert.NotContains(t, out, header,
				"the raw header must never reach the page unescaped")
		})
	}
}

// The Device label reaches a second sink the tooltip above does not, and this is the case that
// says it arrives there as text.
//
// A label is derived from Sec-CH-UA and Sec-CH-UA-Platform, whose values UA-CH requires a
// server to accept arbitrarily (authserver/internal/useragent pins that premise), so any user
// can put markup in their own session's label by completing a login with hand-written headers.
// On these two pages the End Session button hands that label to endSessionClick, which builds a
// message showModalDialog assigns to innerHTML. html/template escapes the label for the JavaScript
// string literal in the onclick attribute and stops there, so the concatenation is where the
// escaping has to happen, and only rendered HTML can see whether it does (#281).
//
// The third session page passes the user's email rather than the device label to its modal, so
// it is asserted here as the negative: no device concatenation to escape.
func TestRender_SessionPagesEscapeTheDeviceLabelIntoTheModal(t *testing.T) {
	const markup = `<script>alert(1)</script>`

	// The unescaped concatenation, in any spacing. This is the shape that shipped and the shape
	// a later edit would reintroduce; matching on it rather than on the fixed text is what makes
	// the guard survive reformatting.
	unescaped := regexp.MustCompile(`\+\s*device\s*\+`)

	for _, tc := range []struct {
		name       string
		page       string
		bind       map[string]interface{}
		modalTakes bool
	}{
		{
			name: "account",
			page: "/account_user_sessions.html",
			bind: map[string]interface{}{
				"sessions": []accounthandlers.SessionInfo{{
					UserSessionId: 1, DeviceName: markup, DeviceType: "Desktop",
					DeviceOS: "Linux", UserAgent: "curl/8.5.0",
				}},
			},
			modalTakes: true,
		},
		{
			name: "admin user",
			page: "/admin_users_sessions.html",
			bind: map[string]interface{}{
				"user": &api.UserResponse{Id: 7, Email: "someone@example.com"},
				"sessions": []adminuserhandlers.SessionInfo{{
					UserSessionId: 1, DeviceName: markup, DeviceType: "Desktop",
					DeviceOS: "Linux", UserAgent: "curl/8.5.0",
				}},
				"page":  "1",
				"query": "",
			},
			modalTakes: true,
		},
		{
			name: "admin client",
			page: "/admin_clients_usersessions.html",
			bind: map[string]interface{}{
				"client": &api.ClientResponse{Id: 3, ClientIdentifier: "web-app"},
				"sessions": []adminclienthandlers.SessionInfo{{
					UserSessionId: 1, UserId: 7, UserEmail: "someone@example.com",
					DeviceName: markup, DeviceType: "Desktop",
					DeviceOS: "Linux", UserAgent: "curl/8.5.0",
				}},
			},
			modalTakes: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := render(t, tc.page, tc.bind)

			// Neither the cell nor the onclick attribute carries the label as markup: the cell
			// is HTML text and the attribute is a JavaScript string literal, and html/template
			// escapes each for its own context.
			assert.NotContains(t, out, markup,
				"the device label must never reach the page as markup")
			assert.Contains(t, out, "&lt;script&gt;alert(1)&lt;/script&gt;",
				"the label belongs in the Device cell, as text")

			if !tc.modalTakes {
				assert.NotContains(t, out, "escapeHtml(device)")
				assert.NotRegexp(t, unescaped, out,
					"this page's modal takes the email, so no device label reaches it")
				return
			}

			// And the script that reads it back out of the attribute escapes it before the
			// innerHTML sink. Dropping the call leaves every other assertion here passing.
			assert.Contains(t, out, "escapeHtml(device)",
				"the device label must be escaped before showModalDialog assigns it to innerHTML")
			assert.NotRegexp(t, unescaped, out,
				"the device label must not be concatenated into the modal message unescaped")
		})
	}
}

// The End Session button's arguments against endSessionClick's parameters, on all three session
// pages.
//
// Folded in with #281: the admin-client page declared six parameters -- it kept a `device` the
// body never reads, unlike the two pages whose modal names the device -- and its button passed
// five, so `IsCurrent` landed in `device` and `isCurrent` was always undefined. The "you are
// ending your own session" warning could therefore never appear on that page, although its
// handler sets the flag. JavaScript pads a short call with undefined rather than failing, so
// nothing anywhere reported it: not the renderer, not the browser, not a handler test that
// only sees the bind.
//
// Counting rather than pinning the argument lists is what makes this a guard for the next edit
// as well as this one: a parameter added to one page's function and not to its button, in
// either direction, is the same defect and fails here too. The fixture values carry no comma,
// which is what lets the count be commas plus one.
func TestRender_SessionPagesPassEveryArgumentEndSessionClickDeclares(t *testing.T) {
	declRe := regexp.MustCompile(`function endSessionClick\(([^)]*)\)`)
	callRe := regexp.MustCompile(`onclick="endSessionClick\(([^)]*)\)`)

	for _, tc := range []struct {
		name string
		page string
		bind map[string]interface{}
	}{
		{
			name: "account",
			page: "/account_user_sessions.html",
			bind: map[string]interface{}{
				"sessions": []accounthandlers.SessionInfo{{
					UserSessionId: 1, DeviceName: "Chrome 120", DeviceType: "Desktop",
					DeviceOS: "Linux", UserAgent: "curl/8.5.0", IsCurrent: true,
				}},
			},
		},
		{
			name: "admin user",
			page: "/admin_users_sessions.html",
			bind: map[string]interface{}{
				"user": &api.UserResponse{Id: 7, Email: "someone@example.com"},
				"sessions": []adminuserhandlers.SessionInfo{{
					UserSessionId: 1, DeviceName: "Chrome 120", DeviceType: "Desktop",
					DeviceOS: "Linux", UserAgent: "curl/8.5.0", IsCurrent: true,
				}},
				"page":  "1",
				"query": "",
			},
		},
		{
			name: "admin client",
			page: "/admin_clients_usersessions.html",
			bind: map[string]interface{}{
				"client": &api.ClientResponse{Id: 3, ClientIdentifier: "web-app"},
				"sessions": []adminclienthandlers.SessionInfo{{
					UserSessionId: 1, UserId: 7, UserEmail: "someone@example.com",
					DeviceName: "Chrome 120", DeviceType: "Desktop",
					DeviceOS: "Linux", UserAgent: "curl/8.5.0", IsCurrent: true,
				}},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := render(t, tc.page, tc.bind)

			decl := declRe.FindStringSubmatch(out)
			require.NotNilf(t, decl, "%s: no endSessionClick declaration", tc.page)
			call := callRe.FindStringSubmatch(out)
			require.NotNilf(t, call, "%s: no End Session button", tc.page)

			assert.Equal(t, strings.Count(decl[1], ",")+1, strings.Count(call[1], ",")+1,
				"%s: endSessionClick(%s) is called with (%s)", tc.page, decl[1], call[1])

			// The flag is the argument the mismatch swallowed, and it is the last one on every
			// page, so pinning it is what says the count above lines up where it matters.
			assert.True(t, strings.HasSuffix(strings.TrimSpace(decl[1]), "isCurrent"),
				"%s: isCurrent is expected last, got (%s)", tc.page, decl[1])
			assert.True(t, strings.HasSuffix(strings.TrimSpace(call[1]), "true"),
				"%s: the current session must pass true last, got (%s)", tc.page, call[1])
		})
	}
}

// The two admin user pages that read a timestamp and a full name off the bind. Neither was covered
// here before #350, and between them they carry every template edit the user family's move made:
// the created-at and last-updated cells, which read a *time.Time where they read a sql.NullTime's
// two fields; the full-name cell, which reads a value the handler assembles where it called a
// method on the model; and the delete page's memberships list, which now ranges over groups the
// handler loaded instead of a field the API never filled.
//
// A page that renders is the whole claim: RenderTemplateToBuffer fails on a field the bind lacks,
// which is the bug this package exists for and the one a DTO swap is most likely to reach.
func TestRender_AdminUserDetails(t *testing.T) {
	createdAt := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updatedAt := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

	out := render(t, "/admin_users_details.html", map[string]interface{}{
		"user": &api.UserResponse{
			Id: 7, Subject: "3f2a1c4e-5b6d-4e8f-9a0b-1c2d3e4f5a6b", Username: "jdoe",
			Email: "jane@example.com", Enabled: true,
			CreatedAt: &createdAt, UpdatedAt: &updatedAt,
		},
		"userFullName":      "Jane Q Doe",
		"page":              "1",
		"query":             "",
		"savedSuccessfully": false,
		"userCreated":       false,
	})

	assert.Contains(t, out, "jane@example.com")
	assert.Contains(t, out, "Jane Q Doe")
	assert.Contains(t, out, "02 Jan 2026 03:04:05 UTC", "the created-at cell renders from the *time.Time")
	assert.Contains(t, out, "04 Mar 2026 05:06:07 UTC", "and so does the last-updated cell")
}

// A user whose timestamps are absent renders an empty cell rather than the year 1: the guard in
// front of each Format call is what stops a nil pointer ending the page in a 500.
func TestRender_AdminUserDetailsWithNoTimestamps(t *testing.T) {
	out := render(t, "/admin_users_details.html", map[string]interface{}{
		"user":              &api.UserResponse{Id: 7, Email: "jane@example.com"},
		"userFullName":      "",
		"page":              "1",
		"query":             "",
		"savedSuccessfully": false,
		"userCreated":       false,
	})

	assert.NotContains(t, out, "0001", "an absent timestamp must render as nothing, not as the zero time")
}

// The delete confirmation, which is the one page in this change whose output moves for a real
// user: the memberships row listed "none" for everybody before, and lists what deleting the user
// will discard now (#350, deferred decision 1).
func TestRender_AdminUserDelete(t *testing.T) {
	createdAt := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	out := render(t, "/admin_users_delete.html", map[string]interface{}{
		"user": &api.UserResponse{
			Id: 7, Subject: "3f2a1c4e-5b6d-4e8f-9a0b-1c2d3e4f5a6b", Username: "jdoe",
			Email: "jane@example.com", CreatedAt: &createdAt,
		},
		"userFullName": "Jane Q Doe",
		"groups": []api.GroupResponse{
			{Id: 2, GroupIdentifier: "admins"},
			{Id: 3, GroupIdentifier: "site-viewers"},
		},
		"page":  "1",
		"query": "",
	})

	assert.Contains(t, out, "Jane Q Doe")
	assert.Contains(t, out, "02 Jan 2026 03:04:05 UTC")
	assert.Contains(t, out, "admins", "the memberships the deletion discards have to be on the page")
	assert.Contains(t, out, "site-viewers")
	assert.NotContains(t, out, "(nenhum)", "with two groups listed, the none arm must not also render")
}

// The none arm, which is what every user saw before the fix and what a user in no groups sees now.
func TestRender_AdminUserDeleteWithNoGroups(t *testing.T) {
	out := render(t, "/admin_users_delete.html", map[string]interface{}{
		"user":         &api.UserResponse{Id: 7, Email: "jane@example.com"},
		"userFullName": "",
		"groups":       []api.GroupResponse{},
		"page":         "1",
		"query":        "",
	})

	assert.Contains(t, out, "jane@example.com")
	assert.Contains(t, out, "(nenhum)", "a user in no groups still gets the row's none arm")
}

// Seam 4 for the group family (#350): the three group pages whose templates read the fields the
// apiclient used to rebuild into a models.Group. This is the only seam that catches a template
// naming a field the DTO does not carry, because it runs the real template FS, funcmap and layout.
//
// The list is the page that reads the most of the response: five columns, of which two are the
// booleans that decide which token a membership reaches and one is the member count.
func TestRender_AdminGroups(t *testing.T) {
	out := render(t, "/admin_groups.html", map[string]interface{}{
		"groups": []api.GroupResponse{
			{Id: 2, GroupIdentifier: "admins", Description: "Administradores",
				IncludeInIdToken: true, IncludeInAccessToken: false, MemberCount: 17},
			{Id: 3, GroupIdentifier: "site-viewers", MemberCount: 0},
		},
	})

	assert.Contains(t, out, "admins")
	assert.Contains(t, out, "Administradores")
	assert.Contains(t, out, "site-viewers")
	assert.Regexp(t, `<td>\s*17\s*</td>`, out,
		"the member count column is what GetGroupById's second return used to carry")

	// The two token columns, both arms: "Sim" for the id token on the first row and "Não" for its
	// access token. A row that rendered neither would still contain both words, from the other
	// row, so the count is what tells them apart: three noes (one per row for access token, plus
	// the second row's id token) and one yes.
	assert.Equal(t, 1, strings.Count(out, ">Sim<"))
	assert.Equal(t, 3, strings.Count(out, ">Não<"))
}

// The delete confirmation, whose member count comes off the response now rather than from a second
// return value the apiclient answered beside the group.
func TestRender_AdminGroupDelete(t *testing.T) {
	out := render(t, "/admin_groups_delete.html", map[string]interface{}{
		"group":        &api.GroupResponse{Id: 2, GroupIdentifier: "admins", Description: "Administradores"},
		"countOfUsers": 17,
	})

	assert.Contains(t, out, "admins")
	assert.Contains(t, out, "Administradores")
	assert.Contains(t, out, "Quantidade de membros")
	assert.Regexp(t, `<td class="">17 <a`, out,
		"the count the administrator is about to orphan has to be on the page")
}

// The attributes page, both arms: a group with attributes and a group with none. The empty arm is
// the one a decode that answered an empty slice for a populated group would land on silently.
func TestRender_AdminGroupAttributes(t *testing.T) {
	t.Run("with attributes", func(t *testing.T) {
		out := render(t, "/admin_groups_attributes.html", map[string]interface{}{
			"groupId":         int64(2),
			"groupIdentifier": "admins",
			"description":     "Administradores",
			"attributes": []api.GroupAttributeResponse{
				{Id: 7, Key: "tier", Value: "gold", GroupId: 2, IncludeInIdToken: true},
				{Id: 8, Key: "region", Value: "br", GroupId: 2, IncludeInAccessToken: true},
			},
		})

		assert.Contains(t, out, "admins")
		assert.Contains(t, out, "tier")
		assert.Contains(t, out, "gold")
		assert.Contains(t, out, "region")
		assert.NotContains(t, out, "Nenhum atributo associado ao grupo.",
			"with two attributes listed, the empty arm must not also render")
	})

	t.Run("with none", func(t *testing.T) {
		out := render(t, "/admin_groups_attributes.html", map[string]interface{}{
			"groupId":         int64(2),
			"groupIdentifier": "admins",
			"description":     "Administradores",
			"attributes":      []api.GroupAttributeResponse{},
		})

		assert.Contains(t, out, "Nenhum atributo associado ao grupo.")
	})
}

// The two resource pages, which hold this change's last two families: admin_resources.html ranges
// over the resource DTOs the API client now hands back untouched, and admin_resources_permissions
// pushes each permission DTO into a JavaScript array by field. Both used to read a models.Resource
// and a models.Permission that the API client rebuilt column by column. This is the only seam that
// catches a template naming a field the DTO does not carry, which is the whole reason the package
// exists (#350).
func TestRender_AdminResourcesList(t *testing.T) {
	bind := map[string]interface{}{
		"resources": []api.ResourceResponse{
			{Id: 1, ResourceIdentifier: "authserver", Description: "Servidor de autenticação",
				IsSystemLevelResource: true},
			{Id: 2, ResourceIdentifier: "faturamento", Description: ""},
		},
	}

	out := render(t, "/admin_resources.html", bind)

	assert.Contains(t, out, "authserver")
	assert.Contains(t, out, "Servidor de autenticação")
	assert.Contains(t, out, "/admin/resources/2/settings",
		"the row's links are built from the DTO's Id")
}

func TestRender_AdminResourcePermissions(t *testing.T) {
	bind := map[string]interface{}{
		"resourceId":                   2,
		"resourceIdentifier":           "faturamento",
		"resourceDescription":          "Faturamento",
		"isSystemLevelResource":        false,
		"builtInPermissionIdentifiers": []string{},
		"savedSuccessfully":            false,
		"permissions": []api.PermissionResponse{
			{Id: 9, PermissionIdentifier: "ler", Description: "Ler faturas", ResourceId: 2,
				Resource: api.ResourceResponse{Id: 2, ResourceIdentifier: "faturamento"}},
		},
	}

	out := render(t, "/admin_resources_permissions.html", bind)

	// The page bootstraps its editor from a JavaScript array built out of the DTO's fields, so a
	// renamed or missing field arrives as an empty string rather than as a template error.
	assert.Contains(t, out, `"permissionIdentifier": "ler"`)
	assert.Contains(t, out, `"description": "Ler faturas"`)
	// html/template pads a number interpolated into a script with spaces, so the id is asserted in
	// the form the browser actually receives rather than the form the template reads.
	assert.Contains(t, out, `"id":  9 `)
}

// Seam 4 for the logout form binding (#350 decision 2). The only seam that reads the real template
// through the real layout, and so the only one that can see the page a browser would receive.
//
// What it asserts is what the browser would submit and where: one POST form, an action equal to the
// endpoint the API named with nothing appended to it, a hidden input per parameter, and the hook
// that submits it. The action matters most. Building the same parameters into a query string here
// would leave every case above this one green while restoring exactly the leak this mode closes,
// because the id_token_hint would be back in a top-level navigation's URL.
//
// Where it stops: no browser executes here, so that the submission actually fires is the code gate's
// to confirm. This case sees the hook declared, not run.
func TestRender_AccountLogoutFormPost(t *testing.T) {
	// The host deliberately does not start "auth.": rawKeyRe above reads "auth.example.com" as a
	// leaked catalog key, which is a property of the fixture and not of the page.
	const endpoint = "https://op.example.com/auth/logout"
	params := map[string]string{
		"id_token_hint":            "eyJhbGciOiJSUzI1NiJ9.e30.sig",
		"post_logout_redirect_uri": "https://console.example.com/",
		"state":                    "a-state",
	}

	out := renderWithLayout(t, "/layouts/no_menu_layout.html", "/account_logout_form_post.html",
		map[string]interface{}{"endpoint": endpoint, "params": params})

	assert.Equal(t, 1, strings.Count(out, "<form "), "exactly one form, so document.forms is unambiguous")
	assert.Contains(t, out, `method="post"`, "the whole point of this page is the POST binding")
	assert.Contains(t, out, `action="`+endpoint+`"`,
		"the action is the endpoint the API named, with nothing appended")

	for name, value := range params {
		assert.Containsf(t, out, `name="`+name+`" value="`+value+`"`,
			"%s must reach the form as a hidden input", name)
	}

	// The hint reaches the page exactly once, in the field it belongs in. A second occurrence would
	// be it in a URL: an action, a link or a script, which is the leak this mode exists to close.
	assert.Equal(t, 1, strings.Count(out, params["id_token_hint"]),
		"the id_token_hint appears only as a form field, never in a URL")
	assert.NotContains(t, out, endpoint+"?", "nothing may turn the endpoint back into a query string")

	assert.Contains(t, out, `document.getElementById("logoutForm").submit()`,
		"the form submits itself; without the hook the visitor sits on a blank page")
	assert.Contains(t, out, "<noscript>", "a browser without JavaScript still needs a way through")
}

// menuLabelRe captures the dropdown label in menu_layout.html: everything between the opening
// <span class="inline-block text-sm align-middle"> and the chevron <svg> that closes it. That is
// the whole of what a signed-in administrator reads at the top right of every admin and account
// page, and reading it back off a rendered page is the only way to see it, because the layout is a
// file no handler test ever executes.
var menuLabelRe = regexp.MustCompile(`(?s)<span class="inline-block text-sm align-middle">(.*?)<svg`)

func menuLabel(t *testing.T, out string) string {
	t.Helper()
	m := menuLabelRe.FindStringSubmatch(out)
	require.Lenf(t, m, 2, "the dropdown label span is not in the rendered page at all")
	return strings.TrimSpace(m[1])
}

// tagRe strips markup, so a case can assert on what an administrator actually reads rather than on
// the elements carrying it. The subject-only case needs the distinction: the guard on a one-key map
// is still true, so the inner <span> is emitted and only its text is empty.
var tagRe = regexp.MustCompile(`<[^>]*>`)

func menuLabelText(t *testing.T, out string) string {
	t.Helper()
	return strings.TrimSpace(tagRe.ReplaceAllString(menuLabel(t, out), ""))
}

// TestRender_MenuLabelShowsTheLoggedInUser is the case the rest of this file could not see. Every
// other render here is an anonymous request, so `loggedInUser` is never bound and the dropdown
// label comes back empty — which reads as "no handler binds it" if the harness is mistaken for the
// product. The bind is real and it is central: HttpHelper.RenderTemplateToBuffer builds it from the
// ID token's claims, and JwtSessionHandler puts that token on the context ahead of every route in
// routes.go that renders a menu page. Rendering with a token is what distinguishes the two.
func TestRender_MenuLabelShowsTheLoggedInUser(t *testing.T) {
	claims := jwt.MapClaims{
		"sub":         "a5f0c6b4-0000-4000-8000-000000000001",
		"email":       "alice@example.com",
		"given_name":  "Alice",
		"middle_name": "Q",
		"family_name": "Doe",
	}

	out := renderWithLayoutAs(t, "/layouts/menu_layout.html", "/admin_groups.html",
		map[string]interface{}{"groups": []api.GroupResponse{}}, claims)

	label := menuLabel(t, out)
	assert.Contains(t, label, "Alice Q Doe",
		"the full name assembled from the ID token's name claims must reach the dropdown")
	assert.Contains(t, label, "alice@example.com", "the email must reach the dropdown")
}

// The name claims are optional; the email is what an administrator always has. With no name, the
// label carries the email alone and no empty line above it.
func TestRender_MenuLabelWithNoNameClaimsShowsTheEmailAlone(t *testing.T) {
	claims := jwt.MapClaims{
		"sub":   "a5f0c6b4-0000-4000-8000-000000000002",
		"email": "bob@example.com",
	}

	out := renderWithLayoutAs(t, "/layouts/menu_layout.html", "/admin_groups.html",
		map[string]interface{}{"groups": []api.GroupResponse{}}, claims)

	label := menuLabel(t, out)
	assert.Contains(t, label, "bob@example.com")
	assert.NotContains(t, label, "<br />", "with no name there is no line to break")
}

// The ID token carries the name and email claims only when IncludeOpenIDConnectClaimsInIdToken is
// on — the seeded default, but an administrator may turn it off globally or for the admin console's
// own client, and then `sub` is all that arrives. The guard on the map is still satisfied, since a
// one-key map is truthy, so the label renders with a missing `Email` key. A missing key on a
// map[string]interface{} is an untyped nil, which text/template prints as "<no value>"; this pins
// that the label degrades to blank instead of putting that string on every page.
func TestRender_MenuLabelWithSubjectOnlyIsBlankNotNoValue(t *testing.T) {
	claims := jwt.MapClaims{"sub": "a5f0c6b4-0000-4000-8000-000000000003"}

	out := renderWithLayoutAs(t, "/layouts/menu_layout.html", "/admin_groups.html",
		map[string]interface{}{"groups": []api.GroupResponse{}}, claims)

	assert.NotContains(t, out, "no value", "a missing claim must not print a template placeholder")
	assert.Empty(t, menuLabelText(t, out), "with only a subject there is nothing to show")
}

// The anonymous request, stated rather than left implicit: with no ID token on the context nothing
// is bound, the outer guard is false, and the label is blank. This is the shape every other render
// in this file has, and saying so here is what keeps the next reader from reading those blanks as a
// defect in the page.
func TestRender_MenuLabelWithNoTokenIsBlank(t *testing.T) {
	out := render(t, "/admin_groups.html", map[string]interface{}{"groups": []api.GroupResponse{}})
	assert.Empty(t, menuLabel(t, out), "an anonymous render binds no user, so not even the span is emitted")
}
