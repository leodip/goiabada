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

	"github.com/leodip/goiabada/adminconsole/internal/handlers/accounthandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminclienthandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminsettingshandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminuserhandlers"
	"github.com/leodip/goiabada/adminconsole/internal/pagination"
	web "github.com/leodip/goiabada/adminconsole/web"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/countries"
	"github.com/leodip/goiabada/core/handlerhelpers"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/locales"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/timezones"

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
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	settings := &models.Settings{AppName: "Test", UITheme: "dark", SMTPEnabled: true}
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, settings))
	req = i18n.RefineLocalizerWithUILocales(req, []string{"pt-BR"})

	h := handlerhelpers.NewHttpHelper(web.TemplateFS())
	buf, err := h.RenderTemplateToBuffer(req, "/layouts/menu_layout.html", page, bind)
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
	settings := &models.Settings{AppName: "Test", UITheme: "dark", SMTPEnabled: true}
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, settings))
	req = i18n.RefineLocalizerWithUILocales(req, []string{"pt-BR"})

	w := httptest.NewRecorder()
	handlerhelpers.NewHttpHelper(web.TemplateFS()).NotFound(w, req)

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
		"user": &models.User{},
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
		"user":              &models.User{},
		"timezones":         timezones.Get(),
		"locales":           locales.Get(),
		"savedSuccessfully": false,
	}
	out := render(t, "/account_profile.html", bind)
	assert.Contains(t, out, "português (Brasil) (Portuguese (Brazil))") // LocaleLabel
	assert.Contains(t, out, "Estados Unidos")                           // RefTimezone country portion localized
}

// TestRender_AdminClients is the template hop of the self-registered badge. The pipeline from the
// database to this page is the client row, then api.ToClientResponse, then that value straight into
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
			Users:    []models.User{{Id: 1, Username: "alice", Email: "alice@example.com"}},
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
				"user": &models.User{Id: 7, Email: "someone@example.com"},
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
