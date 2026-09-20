package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/adminconsole/internal/constants"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
)

func newJwtInfoWithLocale(locale string) oauth.JwtInfo {
	return oauth.JwtInfo{
		IdToken: &oauth.JwtToken{
			Claims: jwt.MapClaims{"locale": locale},
		},
	}
}

// localeSeenBy runs the global locale middleware and then the JWT refinement
// over req, and reports the locale the handler below them would render in. The
// two run in that order in routes.go, and the refinement's whole job is what it
// does to what the first one resolved.
func localeSeenBy(t *testing.T, req *http.Request) string {
	t.Helper()

	var base *http.Request
	i18n.MiddlewareLocale(nil)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		base = r
	})).ServeHTTP(httptest.NewRecorder(), req)

	var seen string
	MiddlewareLocaleFromJWT()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = i18n.T(r.Context(), "auth.pwd.title")
	})).ServeHTTP(httptest.NewRecorder(), base)
	return seen
}

func TestMiddlewareLocaleFromJWT_ReadsLocaleClaim(t *testing.T) {
	// No explicit intent, locale claim present → the claim applies.
	req := httptest.NewRequest("GET", "/admin/users", nil)
	req = req.WithContext(context.WithValue(req.Context(),
		constants.ContextKeyJwtInfo, newJwtInfoWithLocale("pt-BR")))

	assert.Equal(t, "Entrar", localeSeenBy(t, req))
}

func TestMiddlewareLocaleFromJWT_SkipsWhenExplicitIntent(t *testing.T) {
	// Explicit ?ui_locales=pt-BR; the user's claim is "en" — the refinement
	// must not downgrade away from what the request asked for.
	req := httptest.NewRequest("GET", "/admin/users?ui_locales=pt-BR", nil)
	req = req.WithContext(context.WithValue(req.Context(),
		constants.ContextKeyJwtInfo, newJwtInfoWithLocale("en")))

	assert.Equal(t, "Entrar", localeSeenBy(t, req),
		"explicit pt-BR must not be overridden by claim=en")
}

func TestMiddlewareLocaleFromJWT_FallsThroughWhenClaimMissing(t *testing.T) {
	// No explicit intent, JWT present but no locale claim → keeps the
	// previously resolved localizer. Accept-Language pt-BR is the signal that
	// must survive.
	req := httptest.NewRequest("GET", "/admin/users", nil)
	req.Header.Set("Accept-Language", "pt-BR")
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, oauth.JwtInfo{
		IdToken: &oauth.JwtToken{Claims: jwt.MapClaims{}},
	}))

	assert.Equal(t, "Entrar", localeSeenBy(t, req),
		"a missing locale claim must NOT silently jump to English")
}

func TestMiddlewareLocaleFromJWT_NoJwtInfoIsANoOp(t *testing.T) {
	// The unauthenticated shape: nothing wrote ContextKeyJwtInfo, so there is
	// no claim to read and the baseline stands.
	req := httptest.NewRequest("GET", "/admin/users", nil)
	req.Header.Set("Accept-Language", "pt-BR")

	assert.Equal(t, "Entrar", localeSeenBy(t, req))
}
