package renderintegration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminsettingshandlers"
	"github.com/leodip/goiabada/core/i18n"

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
		Id: 1, CreatedAt: &created, State: "current", KeyIdentifier: hostileScriptValue,
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
	m := regexp.MustCompile(`const keys = (\[.*?\]);`).FindStringSubmatch(out)
	require.Len(t, m, 2, "the key list is not in the page's script")
	var decoded []adminsettingshandlers.SettingsKey
	require.NoError(t, json.Unmarshal([]byte(m[1]), &decoded))
	require.Len(t, decoded, 1)
	assert.Equal(t, hostileScriptValue, decoded[0].KeyIdentifier)
	assert.Equal(t, hostileScriptValue, decoded[0].PublicKeyPEM)
	assert.Equal(t, "MIIBIjAN&<>", decoded[0].PublicKeyASN1DER)
	assert.Equal(t, `{"kid":"</script>"}`, decoded[0].PublicKeyJWK)
}

// The bootstrap block carries catalog text, which an operator can replace through the override
// directory, so the hostile value arrives the way a self-hoster's catalog would deliver it. Both
// console layouts write the block, and each is rendered.
func TestRender_JSBootstrapWritesCatalogValuesAsEscapedJSON(t *testing.T) {
	installCatalogOverride(t, "active.pt-BR.toml",
		`"js.error.error_title" = "</script><svg onload=alert(1)> & \u2028 \"q\""`+"\n")

	layouts := []struct {
		layout, page string
		bind         map[string]interface{}
	}{
		{"/layouts/menu_layout.html", "/account_phone.html", map[string]interface{}{
			"selectedPhoneCountryUniqueId": "", "phoneNumber": "", "phoneCountries": nil, "savedSuccessfully": false,
		}},
		{"/layouts/no_menu_layout.html", "/index.html", map[string]interface{}{
			"AuthServerBaseUrl": "https://auth.example", "IsAuthenticated": false,
			"LoggedInUser": "", "LogoutLink": "", "SessionEnded": false,
		}},
	}
	for _, l := range layouts {
		t.Run(l.layout, func(t *testing.T) {
			out := renderWithLayout(t, l.layout, l.page, l.bind)

			assert.Contains(t, out, `"js.error.error_title":`+hostileScriptJSON)
			assert.NotContains(t, out, "<svg onload", "a catalog value reached the page as live markup")

			m := regexp.MustCompile(`<script>window\.i18n=(\{.*?\});</script>`).FindStringSubmatch(out)
			require.Len(t, m, 2, "the window.i18n script element is not in the page")
			var kv map[string]string
			require.NoError(t, json.Unmarshal([]byte(m[1]), &kv))
			assert.Equal(t, hostileScriptValue, kv["js.error.error_title"])
			assert.Equal(t, "Sessão expirada", kv["js.error.session_expired_title"],
				"the rest of the catalog is untouched by the override")
		})
	}
}

// installCatalogOverride installs the embedded catalogs with one override file over them, the way
// GOIABADA_I18N_OVERRIDES_DIR does at startup, and puts the embedded catalogs alone back after the
// test, which is what every other test in this package renders against.
func installCatalogOverride(t *testing.T, name, content string) {
	t.Helper()
	dir := t.TempDir()
	catalogs := filepath.Join(dir, "catalogs")
	require.NoError(t, os.MkdirAll(catalogs, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(catalogs, name), []byte(content), 0o600))
	require.NoError(t, i18n.LoadBundle(dir))
	t.Cleanup(func() { require.NoError(t, i18n.LoadBundle("")) })
}
