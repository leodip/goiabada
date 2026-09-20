package i18n

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubUILocalesReader struct {
	locales []string
}

func (s *stubUILocalesReader) UILocales(_ *http.Request) []string {
	return s.locales
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

func TestMiddlewareLocale_UILocalesReaderWinsOverHeader(t *testing.T) {
	mw := MiddlewareLocale(&stubUILocalesReader{locales: []string{"pt-BR"}})
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

func TestMiddlewareLocale_EmptyUILocalesFallsBackToHeader(t *testing.T) {
	mw := MiddlewareLocale(&stubUILocalesReader{})
	req := httptest.NewRequest("GET", "/auth/pwd", nil)
	req.Header.Set("Accept-Language", "pt-BR")
	rr := httptest.NewRecorder()

	var seen string
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = T(r.Context(), "auth.pwd.title")
		assert.False(t, hasExplicitIntent(r.Context()))
	})).ServeHTTP(rr, req)
	assert.Equal(t, "Entrar", seen)
}

func TestMiddlewareLocale_AcceptLanguageFallback(t *testing.T) {
	// No query or in-flight UI locales, just Accept-Language. pt-BR should resolve.
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

// WithLocale is the whole of core/i18n's locale-setting surface, so these cases
// own both halves of it: the primitive's own rules, and the three helpers it
// replaced, each against the expression that replaced it (#385).

func TestWithLocale_TagsResolveInOrderAndTheWholeListReachesTheMatcher(t *testing.T) {
	// "fr pt-BR" is the shape an RP's ui_locales arrives in. fr has no catalog,
	// so the answer is pt-BR only because every usable tag reaches the matcher:
	// resolving usable[0] alone would answer English and silently discard the
	// RP's second choice.
	ctx := WithLocale(context.Background(), true, "fr", "pt-BR")
	assert.Equal(t, "Entrar", T(ctx, "auth.pwd.title"))
	assert.Equal(t, "fr", LocaleTag(ctx), "the recorded tag is the first usable one, not the matched one")
}

func TestWithLocale_EmptyTagIsSkippedRatherThanEndingTheSearch(t *testing.T) {
	ctx := WithLocale(context.Background(), true, "", "pt-BR")
	assert.Equal(t, "Entrar", T(ctx, "auth.pwd.title"))
	assert.Equal(t, "pt-BR", LocaleTag(ctx))

	// Whitespace is not a tag either. The translator cannot show this on its
	// own — the matcher discards an unparseable preference, so it lands on
	// pt-BR whether or not the tag was skipped — but the recorded tag can:
	// skipping records pt-BR, not the whitespace.
	ctx = WithLocale(context.Background(), true, "   ", "pt-BR")
	assert.Equal(t, "Entrar", T(ctx, "auth.pwd.title"))
	assert.Equal(t, "pt-BR", LocaleTag(ctx))
}

func TestWithLocale_NoUsableTagReturnsTheContextUnchanged(t *testing.T) {
	// The edge that preserves RefineLocalizerWithUserLocale's no-op: a user
	// with no stored locale must keep the localizer the request already has,
	// not be moved to English.
	base := WithLocale(context.Background(), true, "pt-BR")
	for _, tags := range [][]string{nil, {}, {""}, {"", "  "}} {
		// explicit true on purpose: a non-explicit call would be turned back
		// by the intent guard above, which would answer this case for the
		// wrong reason and hide a tag that was wrongly judged usable.
		got := WithLocale(base, true, tags...)
		assert.Equal(t, base, got, "tags %q must return ctx identically", tags)
		assert.Equal(t, "Entrar", T(got, "auth.pwd.title"))
		assert.Equal(t, "pt-BR", LocaleTag(got))
	}
}

func TestWithLocale_NonExplicitDefersToExplicitIntentAndExplicitAlwaysWins(t *testing.T) {
	explicit := WithLocale(context.Background(), true, "pt-BR")
	require.True(t, hasExplicitIntent(explicit))

	kept := WithLocale(explicit, false, "en")
	assert.Equal(t, "Entrar", T(kept, "auth.pwd.title"),
		"a non-explicit call must not clobber a locale the request asked for")

	won := WithLocale(explicit, true, "en")
	assert.Equal(t, "Login", T(won, "auth.pwd.title"), "an explicit call always wins")

	// A non-explicit locale is not itself protected.
	tentative := WithLocale(context.Background(), false, "pt-BR")
	require.False(t, hasExplicitIntent(tentative))
	assert.Equal(t, "Login", T(WithLocale(tentative, false, "en"), "auth.pwd.title"))
}

func TestWithLocale_TrailingEnglishIsTheEmptyLocaleArm(t *testing.T) {
	// WithLocale(ctx, true, locale, "en") is what replaced EmailContext, and
	// this is the arm that made the old helper two branches: an empty
	// recipient locale renders English rather than the locale of whoever
	// triggered the send.
	ctx := WithLocale(WithLocale(context.Background(), true, "pt-BR"), true, "", "en")
	assert.Equal(t, "Login", T(ctx, "auth.pwd.title"))
	assert.Equal(t, "en", LocaleTag(ctx))

	// And a recipient who does have one still gets it.
	ctx = WithLocale(context.Background(), true, "pt-BR", "en")
	assert.Equal(t, "Entrar", T(ctx, "auth.pwd.title"))
	assert.Equal(t, "pt-BR", LocaleTag(ctx))
}

func TestWithLocale_ReplacesRefineLocalizerWithUserLocale(t *testing.T) {
	// r = r.WithContext(i18n.WithLocale(r.Context(), false, user.Locale)),
	// at handler_auth_pwd.go once the password has been checked.
	inner := throughLocaleMiddleware(t, httptest.NewRequest("GET", "/", nil))

	refined := inner.WithContext(WithLocale(inner.Context(), false, "pt-BR"))
	assert.Equal(t, "Entrar", T(refined.Context(), "auth.pwd.title"))
	assert.Equal(t, "Login", T(inner.Context(), "auth.pwd.title"),
		"contexts are immutable: the original must be untouched")

	// An empty stored locale changes nothing.
	assert.Equal(t, inner.Context(), WithLocale(inner.Context(), false, ""))

	// And an explicit ?ui_locales suppresses the override.
	explicit := throughLocaleMiddleware(t, httptest.NewRequest("GET", "/auth/pwd?ui_locales=pt-BR", nil))
	assert.Equal(t, "Entrar", T(WithLocale(explicit.Context(), false, "en"), "auth.pwd.title"))
}

func TestWithLocale_ReplacesRefineLocalizerWithUILocales(t *testing.T) {
	// r = r.WithContext(i18n.WithLocale(r.Context(), true, uiLocales...)),
	// at handler_authorize.go and refineLogoutLocale, where uiLocales is a
	// SanitizeUILocales list.
	req := httptest.NewRequest("GET", "/", nil)
	refined := req.WithContext(WithLocale(req.Context(), true, SanitizeUILocales("pt-BR")...))
	assert.NotSame(t, req, refined)
	assert.True(t, hasExplicitIntent(refined.Context()))
	assert.Equal(t, "Entrar", T(refined.Context(), "auth.pwd.title"))

	// An absent parameter sanitizes to nothing and must stay a no-op.
	assert.Equal(t, req.Context(), WithLocale(req.Context(), true, SanitizeUILocales("")...))
}

func TestWithLocale_ReplacesEmailContext(t *testing.T) {
	// emailReq := r.WithContext(i18n.WithLocale(r.Context(), true, user.Locale, "en")),
	// at the five email-send sites. The request's own locale is the admin's;
	// the email is the recipient's, so the call overrides rather than defers.
	admin := throughLocaleMiddleware(t, httptest.NewRequest("GET", "/api/v1/admin/users?ui_locales=pt-BR", nil))
	require.True(t, hasExplicitIntent(admin.Context()))

	assert.Equal(t, "Login", T(WithLocale(admin.Context(), true, "en", "en"), "auth.pwd.title"),
		"the recipient's locale must win over the sending admin's explicit one")
	assert.Equal(t, "Entrar", T(WithLocale(admin.Context(), true, "pt-BR", "en"), "auth.pwd.title"))
	assert.Equal(t, "Login", T(WithLocale(admin.Context(), true, "", "en"), "auth.pwd.title"),
		"a recipient with no stored locale reads English, not the admin's")
}

func TestWithLocale_NilContextIsTolerated(t *testing.T) {
	// EmailContext documented this for a background worker with no request.
	//nolint:staticcheck // SA1012: the nil tolerance is the behaviour under test.
	ctx := WithLocale(nil, true, "pt-BR")
	require.NotNil(t, ctx)
	assert.Equal(t, "Entrar", T(ctx, "auth.pwd.title"))
}

// throughLocaleMiddleware runs the global locale middleware over req and returns
// the request it handed down, which is the baseline every refinement starts from.
func throughLocaleMiddleware(t *testing.T, req *http.Request) *http.Request {
	t.Helper()

	var inner *http.Request
	MiddlewareLocale(nil)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		inner = r
	})).ServeHTTP(httptest.NewRecorder(), req)
	require.NotNil(t, inner)
	return inner
}

// TestResolveRequestLocale covers the exported resolution a middleware answering
// ahead of MiddlewareLocale uses for its own response. Same three signals as the
// middleware, minus the AuthContext step, which has no reader to consult.
//
// The rows are the ones a rejection actually meets: an operator following a link
// with ?ui_locales, a browser announcing a language, and a request that says
// nothing.
func TestResolveRequestLocale(t *testing.T) {
	tests := []struct {
		name           string
		target         string
		acceptLanguage string
		want           string
	}{
		{"ui_locales wins over the header", "/auth/pwd?ui_locales=pt-BR", "fr-FR", "Entrar"},
		{"Accept-Language is honoured", "/auth/pwd", "pt-BR,en;q=0.9", "Entrar"},
		{"nothing to go on falls back to English", "/auth/pwd", "", "Login"},
		{"an unsupported language falls back to English", "/auth/pwd", "fr-FR", "Login"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.target, nil)
			if tt.acceptLanguage != "" {
				req.Header.Set("Accept-Language", tt.acceptLanguage)
			}

			ctx := ResolveRequestLocale(req.Context(), req)

			assert.Equal(t, tt.want, T(ctx, "auth.pwd.title"))
		})
	}
}

// The context it returns is the caller's own: it is for the one response being
// written, and handing it to the next handler is not what it is for. This pins
// that it does not mutate the request, so a caller that forgets to use the return
// value gets English rather than a silently localized chain.
func TestResolveRequestLocale_LeavesTheRequestUntouched(t *testing.T) {
	req := httptest.NewRequest("GET", "/auth/pwd", nil)
	req.Header.Set("Accept-Language", "pt-BR")

	_ = ResolveRequestLocale(req.Context(), req)

	assert.Equal(t, "Login", T(req.Context(), "auth.pwd.title"))
}
