package middleware

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// A signed-in user whose page language is ja reads the console in Japanese over ?ui_locales and the
// browser, and Automatic follows a request asking for Japanese (#662).
func TestJapanese_ThePageLanguageWinsAndAutomaticFollowsTheRequest(t *testing.T) {
	for _, tc := range []struct {
		name           string
		pageLanguage   string
		target         string
		acceptLanguage string
		wantTitle      string
		wantCatalog    string
	}{
		{"ja chosen, over ui_locales and the browser", "ja", "/admin/users?ui_locales=de", "it", "ログイン", "ja"},
		{"Automatic, ui_locales=ja", "", "/admin/users?ui_locales=ja", "it", "ログイン", "ja"},
		{"Automatic, the browser's ja-JP", "", "/admin/users", "ja-JP", "ログイン", "ja"},
		{"Automatic, the browser's Chinese then Japanese", "", "/admin/users", "zh-CN,ja;q=0.8", "ログイン", "ja"},
		{"German chosen over the browser's ja-JP", "de", "/admin/users", "ja-JP", "Anmelden", "de"},
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
