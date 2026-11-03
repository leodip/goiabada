package i18n

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// passwordToggleName matches the accessible name of a password field's show/hide button: a
// <server>.password_toggle.show_<kind> or hide_<kind> key, whose visible word is the same server's
// password_toggle.show or hide.
var passwordToggleName = regexp.MustCompile(`^([a-z]+)\.password_toggle\.(show|hide)_[a-z_]+$`)

// The client secret's button keeps its visible words' IDs (#722 decision 8), so its names contain
// those words rather than the generic pair.
var passwordToggleVisibleWord = map[string]string{
	"adminconsole.password_toggle.show_client_secret": "adminconsole.admin_clients.authentication.reveal_link",
	"adminconsole.password_toggle.hide_client_secret": "adminconsole.admin_clients.authentication.hide_link",
}

// The console's show/hide buttons read "Show" or "Hide", a status region says "Shown" or "Hidden",
// and each button is named after its field's kind (#722 decision 8).
func TestCatalog_ConsolePasswordToggleWordsInEnglish(t *testing.T) {
	en := loadCatalogFlat(t, "active.en.toml")
	want := map[string]string{
		"adminconsole.password_toggle.show":                           "Show",
		"adminconsole.password_toggle.hide":                           "Hide",
		"adminconsole.password_toggle.shown":                          "Shown",
		"adminconsole.password_toggle.hidden":                         "Hidden",
		"adminconsole.password_toggle.show_password":                  "Show password",
		"adminconsole.password_toggle.hide_password":                  "Hide password",
		"adminconsole.password_toggle.show_current_password":          "Show current password",
		"adminconsole.password_toggle.hide_current_password":          "Hide current password",
		"adminconsole.password_toggle.show_new_password":              "Show new password",
		"adminconsole.password_toggle.hide_new_password":              "Hide new password",
		"adminconsole.password_toggle.show_new_password_confirmation": "Show new password confirmation",
		"adminconsole.password_toggle.hide_new_password_confirmation": "Hide new password confirmation",
		"adminconsole.password_toggle.show_client_secret":             "Show client secret",
		"adminconsole.password_toggle.hide_client_secret":             "Hide client secret",
		"adminconsole.password_toggle.show_secret_key":                "Show secret key",
		"adminconsole.password_toggle.hide_secret_key":                "Hide secret key",
	}
	for key, value := range want {
		assert.Equalf(t, value, en[key], "active.en.toml: %q", key)
	}
	for key := range en {
		if strings.HasPrefix(key, "adminconsole.password_toggle.") {
			_, ok := want[key]
			assert.Truef(t, ok, "active.en.toml has %q, which no console show/hide button uses", key)
		}
	}
}

// The auth server's show/hide buttons read "Show" or "Hide", a status region says "Shown" or
// "Hidden", and each button is named after its field's kind, the password or its confirmation
// (#722 decision 8).
func TestCatalog_AuthServerPasswordToggleWordsInEnglish(t *testing.T) {
	en := loadCatalogFlat(t, "active.en.toml")
	want := map[string]string{
		"common.password_toggle.show":                       "Show",
		"common.password_toggle.hide":                       "Hide",
		"common.password_toggle.shown":                      "Shown",
		"common.password_toggle.hidden":                     "Hidden",
		"common.password_toggle.show_password":              "Show password",
		"common.password_toggle.hide_password":              "Hide password",
		"common.password_toggle.show_password_confirmation": "Show password confirmation",
		"common.password_toggle.hide_password_confirmation": "Hide password confirmation",
	}
	for key, value := range want {
		assert.Equalf(t, value, en[key], "active.en.toml: %q", key)
	}
	for key := range en {
		if strings.HasPrefix(key, "common.password_toggle.") {
			_, ok := want[key]
			assert.Truef(t, ok, "active.en.toml has %q, which no auth server show/hide button uses", key)
		}
	}
}

// Every show/hide button's accessible name contains the word the button shows, case aside, in every
// built-in catalog: a person using speech input says what they see (WCAG 2.2 SC 2.5.3 Label in
// Name). A translation that names the button with another verb than its visible word fails here.
func TestCatalog_PasswordToggleNamesContainTheirVisibleWord(t *testing.T) {
	for _, name := range catalogNames(t) {
		t.Run(name, func(t *testing.T) {
			catalog := loadCatalogFlat(t, name)
			checked := 0
			for key, value := range catalog {
				m := passwordToggleName.FindStringSubmatch(key)
				if m == nil {
					continue
				}
				wordKey, ok := passwordToggleVisibleWord[key]
				if !ok {
					wordKey = m[1] + ".password_toggle." + m[2]
				}
				word, ok := catalog[wordKey]
				if !assert.Truef(t, ok, "%s: %q has no visible word %q", name, key, wordKey) {
					continue
				}
				checked++
				assert.Containsf(t, strings.ToLower(value), strings.ToLower(word),
					"%s: the name %q (%s) does not contain its visible word %q (%s)", name, value, key, word, wordKey)
			}
			// The console's six kinds and the auth server's two, a show and a hide name each, at
			// the least.
			assert.GreaterOrEqualf(t, checked, 16, "%s: %d show/hide names read", name, checked)
		})
	}
}
