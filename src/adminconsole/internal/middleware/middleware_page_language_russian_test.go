package middleware

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// A signed-in user whose page language is ru reads the console in Russian over ?ui_locales and the
// browser, and Automatic follows a request asking for Russian (#666).
func TestRussian_ThePageLanguageWinsAndAutomaticFollowsTheRequest(t *testing.T) {
	for _, tc := range []struct {
		name           string
		pageLanguage   string
		target         string
		acceptLanguage string
		wantTitle      string
		wantCatalog    string
	}{
		{"ru chosen, over ui_locales and the browser", "ru", "/admin/users?ui_locales=de", "it", "Вход", "ru"},
		{"Automatic, ui_locales=ru", "", "/admin/users?ui_locales=ru", "it", "Вход", "ru"},
		{"Automatic, the browser's ru-RU", "", "/admin/users", "ru-RU", "Вход", "ru"},
		{"Automatic, the browser's Ukrainian then Russian", "", "/admin/users", "uk-UA,ru;q=0.8", "Вход", "ru"},
		{"German chosen over the browser's ru-RU", "de", "/admin/users", "ru-RU", "Anmelden", "de"},
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
