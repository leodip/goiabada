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
	"os"
	"regexp"
	"strings"
	"testing"

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
