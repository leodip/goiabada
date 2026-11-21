package renderintegration

import (
	"encoding/json"
	"regexp"
	"testing"
	"time"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminsettingshandlers"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The two places a page writes server data into a <script> as JSON are written as plain template
// values, so the template engine's JavaScript-context escaping is what keeps a value from closing
// its script. They used to go through helpers that typed the value as already safe, marshal on the
// keys page and a whole template.HTML script element from the bootstrap helper, and the engine
// skipped them (#120). Each case plants the four values that break a hand-rolled encoding: a
// closing script tag followed by live markup, an ampersand, U+2028, which ends a line inside a
// JavaScript string literal on older engines, and a double quote. The expected bytes are written
// out by hand rather than recomputed.

// hostileScriptValue is all four at once: the closing tag, live markup, an ampersand, U+2028 and a
// pair of double quotes.
const hostileScriptValue = "</script><svg onload=alert(1)> & \u2028 \"q\""

// hostileScriptJSON is hostileScriptValue as a JSON string the page may carry inside a script:
// every <, > and & as a \u escape, U+2028 as its escape and each quote backslashed.
const hostileScriptJSON = `"\u003c/script\u003e\u003csvg onload=alert(1)\u003e \u0026 \u2028 \"q\""`

func TestRender_AdminSettingsKeysWritesTheKeyListAsEscapedJSON(t *testing.T) {
	created := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	key := adminsettingshandlers.SettingsKey{
		ID: 1, CreatedAt: &created, State: "current", KeyIdentifier: hostileScriptValue,
		Type: "RSA", Algorithm: "RS256",
		PublicKeyASN1DER: "MIIBIjAN&<>", PublicKeyPEM: hostileScriptValue, PublicKeyJWK: `{"kid":"</script>"}`,
	}

	out := renderMenuPage(t, "/admin_settings_keys.html", map[string]interface{}{
		"keys": []adminsettingshandlers.SettingsKey{key},
	})

	assert.Contains(t, out, `"KeyIdentifier":`+hostileScriptJSON)
	assert.Contains(t, out, `"PublicKeyPEM":`+hostileScriptJSON)
	assert.Contains(t, out, `"PublicKeyASN1DER":"MIIBIjAN\u0026\u003c\u003e"`)
	assert.Contains(t, out, `"PublicKeyJWK":"{\"kid\":\"\u003c/script\u003e\"}"`)
	assert.NotContains(t, out, "<svg onload", "a key value reached the page as live markup")

	// Escaped once and no more: the list the script reads decodes back to exactly what was bound.
	m := regexp.MustCompile(`<script type="application/json" id="signing-keys">(\[.*?\])</script>`).FindStringSubmatch(out)
	require.Len(t, m, 2, "the key list is not in the page's signing-keys data block")
	// The whole block, every key included, as the page wrote it before #482 respelled the Go
	// names: the keys are what the page's script reads, so they do not follow a field's Go name
	// (#482 decision 7).
	assert.Equal(t, `[{"Id":1,"CreatedAt":"2026-09-16T12:00:00Z","State":"current","KeyIdentifier":`+hostileScriptJSON+
		`,"Type":"RSA","Algorithm":"RS256","PublicKeyASN1DER":"MIIBIjAN\u0026\u003c\u003e","PublicKeyPEM":`+hostileScriptJSON+
		`,"PublicKeyJWK":"{\"kid\":\"\u003c/script\u003e\"}"}]`, m[1])
	var decoded []adminsettingshandlers.SettingsKey
	require.NoError(t, json.Unmarshal([]byte(m[1]), &decoded))
	require.Len(t, decoded, 1)
	assert.Equal(t, hostileScriptValue, decoded[0].KeyIdentifier)
	assert.Equal(t, hostileScriptValue, decoded[0].PublicKeyPEM)
	assert.Equal(t, "MIIBIjAN&<>", decoded[0].PublicKeyASN1DER)
	assert.Equal(t, `{"kid":"</script>"}`, decoded[0].PublicKeyJWK)
}

// builtInUnexpectedError is the pt-BR catalog's js.error.unexpected, which holds markup for the
// script to insert and a placeholder for tFormat, and builtInUnexpectedErrorJSON is how the page may
// carry it inside a script: every < and > as a \u escape.
const (
	builtInUnexpectedError     = "Ocorreu um erro inesperado: <span class='text-error'>{{detail}}</span>. Atualize a página e tente novamente."
	builtInUnexpectedErrorJSON = `"Ocorreu um erro inesperado: \u003cspan class='text-error'\u003e{{detail}}\u003c/span\u003e. Atualize a página e tente novamente."`
)

// The bootstrap block carries catalog text, and a built-in value holds markup, so the engine's
// escaping is what keeps it from reaching the page as live markup. Both console layouts write the
// block, and each is rendered.
func TestRender_JSBootstrapWritesCatalogValuesAsEscapedJSON(t *testing.T) {

	layouts := []struct {
		layout, page string
		bind         map[string]interface{}
	}{
		{"/layouts/menu_layout.html", "/account_phone.html", map[string]interface{}{
			"selectedPhoneCountryUniqueId": "", "phoneNumber": "", "phoneCountries": nil, "savedSuccessfully": false,
		}},
		{"/layouts/no_menu_layout.html", "/index.html", map[string]interface{}{
			"AuthServerBaseURL": "https://auth.example", "AccountLink": "/account/profile", "AdminLink": "/admin/clients", "IsAuthenticated": false,
			"LoggedInUser": "", "LogoutLink": "", "SessionEnded": false,
		}},
	}
	for _, l := range layouts {
		t.Run(l.layout, func(t *testing.T) {
			out := renderWithLayout(t, l.layout, l.page, l.bind)

			assert.Contains(t, out, `"js.error.unexpected":`+builtInUnexpectedErrorJSON)
			assert.NotContains(t, out, "<span class='text-error'>", "a catalog value reached the page as live markup")

			m := jsI18nBlockRe.FindStringSubmatch(out)
			require.Len(t, m, 2, "the #js-i18n data block is not in the page")
			var kv map[string]string
			require.NoError(t, json.Unmarshal([]byte(m[1]), &kv))
			assert.Equal(t, builtInUnexpectedError, kv["js.error.unexpected"], "escaped once and no more")
			assert.Equal(t, "Sessão expirada", kv["js.error.session_expired_title"])
			// A counted phrase arrives as the forms the page's catalog has, placeholders unfilled, for
			// the script's tCount to choose among.
			assert.Equal(t, "{{count}} resultado", kv["js.combobox.results.one"])
			assert.Equal(t, "{{count}} resultados", kv["js.combobox.results.other"])
			for _, category := range []string{"zero", "two", "few", "many"} {
				assert.NotContainsf(t, kv, "js.combobox.results."+category, "pt-BR has no %s form", category)
			}
		})
	}
}
