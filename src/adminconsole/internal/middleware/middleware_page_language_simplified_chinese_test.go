package middleware

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// A signed-in user whose page language is zh-Hans reads the console in Simplified Chinese over
// ?ui_locales and the browser, and Automatic follows a request asking for Simplified Chinese, or
// listing a bare zh after Traditional Chinese, while Traditional Chinese alone reads English (#663
// decision 3).
func TestSimplifiedChinese_ThePageLanguageWinsAndAutomaticFollowsTheRequest(t *testing.T) {
	for _, tc := range []struct {
		name           string
		pageLanguage   string
		target         string
		acceptLanguage string
		wantTitle      string
		wantCatalog    string
	}{
		{"zh-Hans chosen, over ui_locales and the browser", "zh-Hans", "/admin/users?ui_locales=de", "it", "登录", "zh-Hans"},
		{"zh-Hans chosen, over the browser's zh-TW", "zh-Hans", "/admin/users", "zh-TW", "登录", "zh-Hans"},
		{"Automatic, ui_locales=zh", "", "/admin/users?ui_locales=zh", "it", "登录", "zh-Hans"},
		{"Automatic, the browser's zh-CN", "", "/admin/users", "zh-CN", "登录", "zh-Hans"},
		{"Automatic, Chrome set to Chinese (Taiwan)", "", "/admin/users", "zh-TW,zh;q=0.9", "登录", "zh-Hans"},
		{"Automatic, the browser's zh-TW alone", "", "/admin/users", "zh-TW", "Sign in", "en"},
		{"German chosen over the browser's zh-CN", "de", "/admin/users", "zh-CN", "Anmelden", "de"},
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
