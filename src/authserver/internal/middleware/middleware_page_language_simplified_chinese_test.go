package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// A known user whose page language is zh-Hans reads the auth server's pages in Simplified Chinese
// over a request asking for German, whether the user is the sign-in's or the browser session's
// (#663).
func TestSimplifiedChinese_AKnownUsersPageLanguageWinsOverTheRequest(t *testing.T) {
	for _, tc := range []struct {
		name   string
		signIn signInUser
	}{
		{"the sign-in's user", 7},
		{"the session's user", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := datamocks.NewDatabase(t)
			db.On("GetUserByID", mock.Anything, mock.Anything, int64(7)).
				Return(&record.User{ID: 7, PageLanguage: "zh-Hans"}, nil).Once()

			req := httptest.NewRequest(http.MethodGet, "/auth/consent?ui_locales=de", nil)
			req.Header.Set("Accept-Language", "it")
			req = req.WithContext(i18n.ResolveRequestLocale(req.Context(), req))
			req = req.WithContext(reqctx.WithSessionUserID(reqctx.WithSessionIdentifier(req.Context(), "the-session"), 7))
			var title, catalog string
			PageLanguage(tc.signIn, db)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				title = i18n.T(r.Context(), "auth.pwd.title")
				catalog = i18n.CatalogTag(r.Context())
			})).ServeHTTP(httptest.NewRecorder(), req)

			assert.Equal(t, "zh-Hans", catalog)
			assert.Equal(t, "登录", title)
		})
	}
}
