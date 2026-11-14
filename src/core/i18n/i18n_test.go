package i18n

import (
	"context"
	"testing"

	"github.com/leodip/goiabada/core/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestT_EnglishKeyResolves(t *testing.T) {
	ctx := context.Background()
	got := T(ctx, "auth.pwd.title")
	assert.Equal(t, "Sign in", got)
}

func TestT_PtBRKeyResolves(t *testing.T) {
	assert.Equal(t, "Entrar", T(ctxFor("pt-BR"), "auth.pwd.title"))
}

func TestT_UnknownLocaleFallsBackToEnglish(t *testing.T) {
	// "xx" is not a registered locale; the matcher falls back to the tag at
	// index 0, which is English.
	assert.Equal(t, "Sign in", T(ctxFor("xx"), "auth.pwd.title"))
}

func TestT_MissingKeyReturnsKey(t *testing.T) {
	// Visible-miss policy: missing-in-English keys surface the literal key
	// so the gap is obvious in dev.
	got := T(context.Background(), "nope.this.key.does.not.exist")
	assert.Equal(t, "nope.this.key.does.not.exist", got)
}

func TestLocalizer_NoCtxFallsBackToEnglish(t *testing.T) {
	loc := localizer(context.Background())
	require.NotNil(t, loc)
	// T against an empty context resolves through the English fallback.
	assert.Equal(t, "Sign in", T(context.Background(), "auth.pwd.title"))
}

// ctxFor builds a context carrying the translator the built-in bundle resolves
// for prefs — the shape Locale produces, without the HTTP layer.
func ctxFor(prefs ...string) context.Context {
	return ctxForBundle(builtIn(), prefs...)
}

// ctxForBundle is ctxFor over a bundle the test built, installed nowhere.
func ctxForBundle(b *bundle, prefs ...string) context.Context {
	return context.WithValue(context.Background(), ctxKeyLocalizer, b.localizerFor(prefs))
}

// builtInWithout builds, installed nowhere, the built-in bundle with key left out of tag's
// catalog: the one way a built-in language can miss a key English has.
func builtInWithout(t *testing.T, tag, key string) *bundle {
	t.Helper()
	files, err := loadEmbeddedCatalogs()
	require.NoError(t, err)
	found := false
	for _, f := range files {
		if f.tag.String() == tag {
			_, found = f.messages[key]
			delete(f.messages, key)
		}
	}
	require.True(t, found, "%s's catalog holds %q", tag, key)
	return build(files)
}

// A built-in catalog missing a key renders the English text, not the key: the catalog hygiene test
// holds the shipped catalogs to English's keys, and the English hop is what a miss still reads.
func TestT_KeyMissingInMatchedLocaleFallsBackToEnglish(t *testing.T) {
	b := builtInWithout(t, "pt-BR", "auth.pwd.password_label")

	ctx := ctxForBundle(b, "pt-BR")
	assert.Equal(t, "Entrar", T(ctx, "auth.pwd.title"))
	assert.Equal(t, "Password", T(ctx, "auth.pwd.password_label"))
	assert.Equal(t, "Password", Raw(ctx, "auth.pwd.password_label"))
}

// The embedded default has no caller to hand an error to, so a failure to build it renders every
// key or code as itself, the visible-miss policy, and none of the rendering surfaces panics on the
// empty bundle it serves (#431).
func TestOrEmpty_AnEmbeddedFailureRendersEveryKeyAsItself(t *testing.T) {
	b := orEmpty(nil, errs.New("the embedded catalogs did not parse"))
	require.NotNil(t, b)

	for _, ctx := range []context.Context{ctxForBundle(b), ctxForBundle(b, "pt-BR"), ctxForBundle(b, "fr-CA,de;q=0.5")} {
		assert.Equal(t, "en", CatalogTag(ctx))
		assert.Equal(t, "auth.pwd.title", T(ctx, "auth.pwd.title"))
		assert.Equal(t, "js.error.unexpected", Raw(ctx, "js.error.unexpected"))
	}
	assert.Equal(t, ErrCodeLoginAuthFailed, b.english.render(ErrCodeLoginAuthFailed, nil))
}

func TestOrEmpty_ALoadThatSucceededIsServedAsItIs(t *testing.T) {
	b, err := load()
	require.NoError(t, err)
	assert.Same(t, b, orEmpty(b, nil))
}

func TestT_TemplatedValueRendersItsData(t *testing.T) {
	assert.Equal(t, "The email address cannot exceed a maximum length of 60 characters.",
		T(context.Background(), "validator.email.too_long", map[string]any{"max": 60}))
}

func TestT_TemplatedValueWithoutDataRendersNoValue(t *testing.T) {
	// text/template's missingkey=default, which is what go-i18n configured
	// too: an absent field renders <no value> rather than failing the render.
	assert.Equal(t, "The email address cannot exceed a maximum length of <no value> characters.",
		T(context.Background(), "validator.email.too_long"))
}

func TestT_ValueThatIsNotAGoTemplateRendersTheKey(t *testing.T) {
	// The JS bootstrap strings carry {{param}} placeholders that tFormat()
	// substitutes client-side, so text/template cannot parse them. T renders
	// the key for those; Raw() is what the bootstrap calls (#273).
	assert.Equal(t, "js.error.unexpected", T(context.Background(), "js.error.unexpected"))
}

// A value that parses can still fail while evaluating its data: a channel cannot be printed. That
// is the fifth rendering outcome, and it renders the key like the parse failure above rather than
// the half string Execute wrote before it failed, in every built-in language. Missing data is not
// this case: missingkey=default renders <no value> and returns no error (#273).
func TestT_TemplatedValueThatFailsToExecuteRendersTheKey(t *testing.T) {
	for _, tag := range CatalogTags() {
		ctx := ctxFor(tag)
		assert.Equalf(t, "validator.email.too_long",
			T(ctx, "validator.email.too_long", map[string]any{"max": make(chan int)}), "%s", tag)
	}
}

// TestLocalizerFor_MatchesAsGoI18nDid is the parity table for the matcher that
// replaced go-i18n's: every row was derived by running go-i18n's Localizer and
// this one side by side over the same input, and every row is self-contained
// here. The rows that decide it, because nothing else observes them: a later
// range winning
// ("nl-NL,pt;q=0.8"), a q=0 range being excluded, quality reordering the list,
// unparseable input falling to English, and the ui_locales shape where the
// first tag is unsupported.
func TestLocalizerFor_MatchesAsGoI18nDid(t *testing.T) {
	const (
		en = "Sign in"
		pt = "Entrar"
	)
	for _, tc := range []struct {
		prefs []string
		want  string
	}{
		{[]string{"pt-BR"}, pt},
		{[]string{"pt"}, pt},
		{[]string{"pt-PT"}, pt},
		{[]string{"en"}, en},
		{[]string{"en-US"}, en},
		{[]string{"xx"}, en},
		{[]string{"nl"}, en},
		{[]string{"nl-NL"}, en},
		{[]string{""}, en},
		{[]string{"pt-BR,en;q=0.9"}, pt},
		{[]string{"nl-NL,pt;q=0.8"}, pt},
		{[]string{"garbage!!"}, en},
		{[]string{"*"}, en},
		{[]string{"nl", "pt-BR"}, pt},
		{[]string{"xx", "pt-BR"}, pt},
		{[]string{"pt-BR;q=0"}, en},
		{[]string{"en;q=0.1,pt-BR;q=0.9"}, pt},
	} {
		assert.Equalf(t, tc.want, T(ctxFor(tc.prefs...), "auth.pwd.title"),
			"locale resolution moved for %q", tc.prefs)
	}
}
