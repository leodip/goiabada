package middleware

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// A signed-in user whose page language is pl reads the console in Polish over ?ui_locales and the
// browser, and Automatic follows a request asking for Polish (#665).
func TestPolish_ThePageLanguageWinsAndAutomaticFollowsTheRequest(t *testing.T) {
	for _, tc := range []struct {
		name           string
		pageLanguage   string
		target         string
		acceptLanguage string
		wantTitle      string
		wantCatalog    string
	}{
		{"pl chosen, over ui_locales and the browser", "pl", "/admin/users?ui_locales=de", "it", "Zaloguj się", "pl"},
		{"Automatic, ui_locales=pl", "", "/admin/users?ui_locales=pl", "it", "Zaloguj się", "pl"},
		{"Automatic, the browser's pl-PL", "", "/admin/users", "pl-PL", "Zaloguj się", "pl"},
		{"German chosen over the browser's pl-PL", "de", "/admin/users", "pl-PL", "Anmelden", "de"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newSessionHarness(t)
			h.parser.On("DecodeAndValidateStoredIDToken", mock.Anything, storedIDTokenRaw).
				Return(verifiedStoredWithLocale, nil)
			cookies := h.seed(signedInWithPageLanguage(tc.pageLanguage, true))

			title, catalog := h.pageLanguageSeen(tc.target, tc.acceptLanguage, cookies)

			assert.Equal(t, tc.wantTitle, title)
			assert.Equal(t, tc.wantCatalog, catalog)
		})
	}
}
