// Package rendertest executes the reference-data account pages through the
// real template renderer (funcmap + embedded template FS + full layout), in
// pt-BR, with the actual runtime data types. This is the regression guard for
// the class of bug where a template references a field its data doesn't carry
// (e.g. the phone dropdown referencing .Alpha2 on a DTO that lacked it, which
// 500'd in production but was invisible to mocked handler tests).
package rendertest

import (
	"context"
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
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
		"csrfField":         template.HTML(""),
	}
	out := render(t, "/account_phone.html", bind)
	// html/template escapes "+" to "&#43;", so assert on the emoji + localized
	// country name (the part the phone-500 bug and the CLDR work affect).
	assert.Contains(t, out, "🇧🇷 - Brasil") // curated pt-BR label
	assert.Contains(t, out, "🇮🇹 - Itália") // uncurated -> CLDR
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
		"csrfField":         template.HTML(""),
	}
	out := render(t, "/account_address.html", bind)
	assert.Contains(t, out, "Itália") // RefCountry CLDR (uncurated)
	assert.Contains(t, out, "México")
}

func TestRender_AccountProfile(t *testing.T) {
	bind := map[string]interface{}{
		"user":              &models.User{},
		"timezones":         timezones.Get(),
		"locales":           locales.Get(),
		"savedSuccessfully": false,
		"csrfField":         template.HTML(""),
	}
	out := render(t, "/account_profile.html", bind)
	assert.Contains(t, out, "português (Brasil) (Portuguese (Brazil))") // LocaleLabel
	assert.Contains(t, out, "Estados Unidos")                           // RefTimezone country portion localized
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
		"csrfField":                    template.HTML(""),
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
