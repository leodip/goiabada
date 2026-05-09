package i18n

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newJwtInfoWithLocale(locale string) oauth.JwtInfo {
	return oauth.JwtInfo{
		IdToken: &oauth.JwtToken{
			Claims: jwt.MapClaims{"locale": locale},
		},
	}
}

// stubAuthCtxReader returns the configured AuthContext (or err).
type stubAuthCtxReader struct {
	ac  *oauth.AuthContext
	err error
}

func (s *stubAuthCtxReader) GetAuthContext(_ *http.Request) (*oauth.AuthContext, error) {
	return s.ac, s.err
}

func TestSanitizeUILocales(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{"pt-BR", []string{"pt-BR"}},
		{"pt-BR es en", []string{"pt-BR", "es", "en"}},
		{"PT-br ZH-Hans-CN", []string{"PT-br", "ZH-Hans-CN"}}, // case preserved
		{"!!!! garbage 😈 ", nil},
		{"pt-BR garbage es", []string{"pt-BR", "es"}}, // garbage dropped, others kept
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got := SanitizeUILocales(c.in)
			assert.Equal(t, c.want, got)
		})
	}
}

func TestSanitizeUILocales_TagCountCap(t *testing.T) {
	// Build 12 valid tags; expect first 10 retained.
	tags := []string{"en", "es", "pt", "fr", "de", "it", "ja", "ko", "zh", "ru", "ar", "nl"}
	got := SanitizeUILocales(strings.Join(tags, " "))
	assert.Equal(t, tags[:maxUILocaleTags], got)
}

func TestSanitizeUILocales_ByteCap(t *testing.T) {
	// Build a tag list whose summed bytes cross the 256-byte cap.
	var b strings.Builder
	for i := 0; i < 50; i++ {
		// Each tag is "en-AAAAAAAA" (11 bytes); 50 of them = 550 bytes of tag content.
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString("en-AAAAAAAA")
	}
	got := SanitizeUILocales(b.String())
	assert.LessOrEqual(t, len(got), maxUILocaleTags, "result must respect tag-count cap")
	used := 0
	for _, tg := range got {
		used += len(tg)
	}
	assert.LessOrEqual(t, used, maxUILocaleBytes, "result must respect byte cap")
}

func TestMiddlewareLocale_QueryParamWins(t *testing.T) {
	mw := MiddlewareLocale(nil)
	req := httptest.NewRequest("GET", "/auth/authorize?ui_locales=pt-BR", nil)
	req.Header.Set("Accept-Language", "fr-FR")
	rr := httptest.NewRecorder()

	var seen string
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = T(r.Context(), "auth.pwd.title")
		assert.True(t, hasExplicitIntent(r.Context()))
	})).ServeHTTP(rr, req)
	assert.Equal(t, "Entrar", seen)
}

func TestMiddlewareLocale_AuthContextWinsOverHeader(t *testing.T) {
	mw := MiddlewareLocale(&stubAuthCtxReader{ac: &oauth.AuthContext{UILocales: []string{"pt-BR"}}})
	req := httptest.NewRequest("GET", "/auth/pwd", nil)
	req.Header.Set("Accept-Language", "fr-FR")
	rr := httptest.NewRecorder()

	var seen string
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = T(r.Context(), "auth.pwd.title")
		assert.True(t, hasExplicitIntent(r.Context()))
	})).ServeHTTP(rr, req)
	assert.Equal(t, "Entrar", seen)
}

func TestMiddlewareLocale_AcceptLanguageFallback(t *testing.T) {
	// No query, no AuthContext, just Accept-Language. pt-BR should resolve.
	mw := MiddlewareLocale(nil)
	req := httptest.NewRequest("GET", "/auth/pwd", nil)
	req.Header.Set("Accept-Language", "pt-BR,en;q=0.9")
	rr := httptest.NewRecorder()

	var seen string
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = T(r.Context(), "auth.pwd.title")
		assert.False(t, hasExplicitIntent(r.Context()), "Accept-Language is not explicit intent")
	})).ServeHTTP(rr, req)
	assert.Equal(t, "Entrar", seen)
}

func TestMiddlewareLocale_EnglishFallback(t *testing.T) {
	// No signals → English.
	mw := MiddlewareLocale(nil)
	req := httptest.NewRequest("GET", "/auth/pwd", nil)
	rr := httptest.NewRecorder()

	var seen string
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = T(r.Context(), "auth.pwd.title")
		assert.False(t, hasExplicitIntent(r.Context()))
	})).ServeHTTP(rr, req)
	assert.Equal(t, "Login", seen)
}

func TestMiddlewareLocale_DoesNotConsumePostBody(t *testing.T) {
	// MiddlewareLocale must NOT call r.ParseForm — it would interfere
	// with the authorize handler's own form parsing on POST.
	body := strings.NewReader("ui_locales=pt-BR&client_id=x")
	req := httptest.NewRequest("POST", "/auth/authorize", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	mw := MiddlewareLocale(nil)
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reading the body inside the handler should still work — the
		// middleware did not consume it.
		assert.Equal(t, "pt-BR", r.FormValue("ui_locales"))
	})).ServeHTTP(rr, req)
}

func TestRefineLocalizerWithUser_ReturnsNewRequest(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	user := &models.User{Locale: "pt-BR"}

	// Apply the global locale middleware first so the request has a
	// baseline localizer.
	mw := MiddlewareLocale(nil)
	var inner *http.Request
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inner = r
	})).ServeHTTP(httptest.NewRecorder(), req)

	refined := RefineLocalizerWithUser(inner, user)
	assert.NotSame(t, inner, refined, "RefineLocalizerWithUser must return a new *http.Request")
	assert.Equal(t, "Entrar", T(refined.Context(), "auth.pwd.title"))
	// Original context untouched.
	assert.Equal(t, "Login", T(inner.Context(), "auth.pwd.title"))
}

func TestRefineLocalizerWithUser_NoOpWhenLocaleEmpty(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	mw := MiddlewareLocale(nil)
	var inner *http.Request
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inner = r
	})).ServeHTTP(httptest.NewRecorder(), req)

	user := &models.User{Locale: ""}
	refined := RefineLocalizerWithUser(inner, user)
	assert.Equal(t, "Login", T(refined.Context(), "auth.pwd.title"))
}

func TestRefineLocalizerWithUser_SkipsWhenExplicitIntent(t *testing.T) {
	// Explicit ?ui_locales=pt-BR should suppress the user-locale override.
	// The assertion below is that "Entrar" (pt-BR) wins over user.Locale="en".
	req := httptest.NewRequest("GET", "/auth/pwd?ui_locales=pt-BR", nil)
	mw := MiddlewareLocale(nil)
	var inner *http.Request
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inner = r
	})).ServeHTTP(httptest.NewRecorder(), req)

	require.True(t, hasExplicitIntent(inner.Context()))

	// User.Locale = "en", but explicit pt-BR should win.
	user := &models.User{Locale: "en"}
	refined := RefineLocalizerWithUser(inner, user)
	assert.Equal(t, "Entrar", T(refined.Context(), "auth.pwd.title"),
		"explicit intent (?ui_locales=pt-BR) must not be overridden by User.Locale")
}

func TestRefineLocalizerWithUILocales_RoundTrip(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	refined := RefineLocalizerWithUILocales(req, []string{"pt-BR"})
	assert.NotSame(t, req, refined)
	assert.True(t, hasExplicitIntent(refined.Context()))
	assert.Equal(t, "Entrar", T(refined.Context(), "auth.pwd.title"))
}

func TestRefineLocalizerWithUILocales_EmptyIsNoOp(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	refined := RefineLocalizerWithUILocales(req, nil)
	assert.Same(t, req, refined)
}

func TestMiddlewareLocaleFromJWT_ReadsLocaleClaim(t *testing.T) {
	// No explicit intent, locale claim present → the JWT-locale refinement
	// applies the claim.
	req := httptest.NewRequest("GET", "/admin/users", nil)
	ctx := context.WithValue(req.Context(), constants.ContextKeyJwtInfo, newJwtInfoWithLocale("pt-BR"))
	req = req.WithContext(ctx)

	// Run the global locale middleware first (no signals → English baseline).
	mw := MiddlewareLocale(nil)
	var baseReq *http.Request
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		baseReq = r
	})).ServeHTTP(httptest.NewRecorder(), req)
	require.False(t, hasExplicitIntent(baseReq.Context()))

	// JWT-locale refinement picks up the locale claim.
	refine := MiddlewareLocaleFromJWT()
	var seen string
	refine(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = T(r.Context(), "auth.pwd.title")
	})).ServeHTTP(httptest.NewRecorder(), baseReq)
	assert.Equal(t, "Entrar", seen)
}

func TestMiddlewareLocaleFromJWT_SkipsWhenExplicitIntent(t *testing.T) {
	// Explicit ?ui_locales=pt-BR; user's claim is "en" — the JWT-locale
	// refinement must not downgrade away from the explicit intent.
	req := httptest.NewRequest("GET", "/admin/users?ui_locales=pt-BR", nil)
	ctx := context.WithValue(req.Context(), constants.ContextKeyJwtInfo, newJwtInfoWithLocale("en"))
	req = req.WithContext(ctx)

	mw := MiddlewareLocale(nil)
	var baseReq *http.Request
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		baseReq = r
	})).ServeHTTP(httptest.NewRecorder(), req)
	require.True(t, hasExplicitIntent(baseReq.Context()))

	refine := MiddlewareLocaleFromJWT()
	var seen string
	refine(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = T(r.Context(), "auth.pwd.title")
	})).ServeHTTP(httptest.NewRecorder(), baseReq)
	assert.Equal(t, "Entrar", seen, "explicit pt-BR must not be overridden by claim=en")
}

func TestMiddlewareLocaleFromJWT_FallsThroughWhenClaimMissing(t *testing.T) {
	// No explicit intent, no locale claim → keeps the previously-resolved
	// localizer. Accept-Language pt-BR is the signal we keep.
	req := httptest.NewRequest("GET", "/admin/users", nil)
	req.Header.Set("Accept-Language", "pt-BR")
	// JwtInfo present but no locale claim:
	ctx := context.WithValue(req.Context(), constants.ContextKeyJwtInfo, oauth.JwtInfo{
		IdToken: &oauth.JwtToken{Claims: jwt.MapClaims{}},
	})
	req = req.WithContext(ctx)

	mw := MiddlewareLocale(nil)
	var baseReq *http.Request
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		baseReq = r
	})).ServeHTTP(httptest.NewRecorder(), req)

	refine := MiddlewareLocaleFromJWT()
	var seen string
	refine(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = T(r.Context(), "auth.pwd.title")
	})).ServeHTTP(httptest.NewRecorder(), baseReq)
	assert.Equal(t, "Entrar", seen, "missing locale claim must NOT silently jump to English")
}

func TestIsMachineRequest(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		// Surface B (machine)
		{"/api/v1/admin/users", true},
		{"/api/v1/account/profile", true},
		{"/api/public/settings", true},
		{"/auth/token", true},
		{"/connect/register", true},
		{"/userinfo", true},
		{"/userinfo/picture/abc", true},
		{"/.well-known/openid-configuration", true},
		{"/certs", true},
		{"/client/logo/foo", true},
		// Surface A (browser)
		{"/auth/authorize", false},
		{"/auth/pwd", false},
		{"/auth/otp", false},
		{"/auth/consent", false},
		{"/account/register", false},
		{"/admin/clients", false},
		{"/", false},
		{"/health", false},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			req := httptest.NewRequest("GET", c.path, nil)
			assert.Equal(t, c.want, IsMachineRequest(req))
		})
	}
}

