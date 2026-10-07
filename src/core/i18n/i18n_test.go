package i18n

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	// Build a localizer that prefers pt-BR — exercising the loaded stub catalog.
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

// TestRendering_WithNoLoadBundleServesTheEmbeddedCatalogs is the case that made the nine TestMains
// whose only job was LoadBundle unnecessary: nothing installed, and every rendering surface still
// answers the embedded English and pt-BR text rather than its key (#431). Nothing is installed
// while it runs, whatever ran before it, and the cleanup puts back what was.
func TestRendering_WithNoLoadBundleServesTheEmbeddedCatalogs(t *testing.T) {
	saved := installed.Load()
	t.Cleanup(func() { installed.Store(saved) })
	installed.Store(nil)

	assert.Equal(t, "Sign in", T(context.Background(), "auth.pwd.title"))
	assert.Equal(t, "Entrar", T(ctxFor("pt-BR"), "auth.pwd.title"))
	assert.NotEqual(t, "js.error.unexpected", Raw(context.Background(), "js.error.unexpected"))

	le := NewLocalizedError(ErrCodeLoginAuthFailed, nil)
	assert.NotEqual(t, ErrCodeLoginAuthFailed, le.EnglishFallback())
	assert.Equal(t, le.EnglishFallback(), le.Localize(context.Background()))
}

// TestLoad_EmptyDirIsTheEmbeddedCatalogs: load("") reads no directory at all and answers exactly
// what the embedded default serves.
func TestLoad_EmptyDirIsTheEmbeddedCatalogs(t *testing.T) {
	b, err := load("")
	require.NoError(t, err)

	assert.Equal(t, tagStrings(embedded()), tagStrings(b))
	assert.Equal(t, []string{"en", "pt-BR"}, tagStrings(b))
	assert.Equal(t, "Entrar", T(ctxForBundle(b, "pt-BR"), "auth.pwd.title"))
	assert.Equal(t, "Sign in", T(ctxForBundle(b, "en"), "auth.pwd.title"))
}

// TestLoad_TouchesNothingGlobal: a load with overrides installs nothing, so what every rendering
// surface serves is unchanged by it.
func TestLoad_TouchesNothingGlobal(t *testing.T) {
	saved := installed.Load()
	t.Cleanup(func() { installed.Store(saved) })
	installed.Store(nil)

	b, err := loadWithOverrides(t, map[string]string{
		"active.pt-BR.toml": "\"auth.pwd.title\" = \"Acesse\"\n",
	})
	require.NoError(t, err)
	require.Equal(t, "Acesse", T(ctxForBundle(b, "pt-BR"), "auth.pwd.title"))

	assert.Nil(t, installed.Load())
	assert.Equal(t, "Entrar", T(ctxFor("pt-BR"), "auth.pwd.title"))
}

func TestOverrideDir_MergesOnTopOfEmbedded(t *testing.T) {
	// Override pt-BR's "auth.pwd.title" with a self-host-customized value.
	b, err := loadWithOverrides(t, map[string]string{
		"active.pt-BR.toml": "\"auth.pwd.title\" = \"Acesse\"\n",
	})
	require.NoError(t, err)

	ctx := ctxForBundle(b, "pt-BR")
	assert.Equal(t, "Acesse", T(ctx, "auth.pwd.title"))

	// Untouched key still falls back to the embedded pt-BR catalog.
	assert.Equal(t, "Senha", T(ctx, "auth.pwd.password_label"))
}

func TestOverrideDir_NoCatalogsSubdir_IsNoOp(t *testing.T) {
	// An override dir without a catalogs/ subdir is valid — log + skip.
	b, err := load(t.TempDir())
	require.NoError(t, err)
	assert.Equal(t, []string{"en", "pt-BR"}, tagStrings(b))
}

// TestOverrideDir_ACatalogsPathThatIsNotADirectoryIsRefused: the directory exists but cannot be
// read as one, which is the operator's misconfiguration rather than an absent optional layer, so
// the load answers an error and main stops on it.
func TestOverrideDir_ACatalogsPathThatIsNotADirectoryIsRefused(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "catalogs"), []byte("not a directory"), 0o644))

	b, err := load(dir)
	require.Error(t, err)
	assert.Nil(t, b)
	assert.Contains(t, err.Error(), "is not a directory")
}

func TestOverrideOnlyLocale_IsSupported(t *testing.T) {
	// A self-hoster ships only an override file for a locale that isn't in
	// the embedded set. The bundle must carry that locale in its tags, or the
	// matcher answers English for a request asking for it.
	b, err := loadWithOverrides(t, map[string]string{
		"active.fr.toml": "\"auth.pwd.title\" = \"Connexion\"\n",
	})
	require.NoError(t, err)

	// Embedded locales first, the override-only one after them.
	assert.Equal(t, []string{"en", "pt-BR", "fr"}, tagStrings(b))

	// And the override translation actually works.
	assert.Equal(t, "Connexion", T(ctxForBundle(b, "fr"), "auth.pwd.title"))
}

// TestLoadBundle_InstallsTheOverrides: after LoadBundle, every rendering surface reads the
// directory it was given, with no bundle threaded through anything.
func TestLoadBundle_InstallsTheOverrides(t *testing.T) {
	saved := installed.Load()
	t.Cleanup(func() { installed.Store(saved) })

	dir := overridesDir(t, map[string]string{
		"active.pt-BR.toml": "\"auth.pwd.title\" = \"Acesse\"\n",
		"active.en.toml":    "\"auth.pwd.title\" = \"Welcome back\"\n",
	})
	require.NoError(t, LoadBundle(dir))

	assert.Equal(t, "Acesse", T(ctxFor("pt-BR"), "auth.pwd.title"))
	assert.Equal(t, "Welcome back", T(context.Background(), "auth.pwd.title"))
}

// TestLoadBundle_AFailureLeavesThePreviousBundleInstalled: an override that does not parse is
// answered as an error and installs nothing, so whatever was served is served still.
func TestLoadBundle_AFailureLeavesThePreviousBundleInstalled(t *testing.T) {
	saved := installed.Load()
	t.Cleanup(func() { installed.Store(saved) })

	require.NoError(t, LoadBundle(overridesDir(t, map[string]string{
		"active.en.toml": "\"auth.pwd.title\" = \"Welcome back\"\n",
	})))
	before := installed.Load()

	err := LoadBundle(overridesDir(t, map[string]string{
		"active.en.toml": "[section]\nother = \"x\"\n",
	}))
	require.Error(t, err)

	assert.Same(t, before, installed.Load())
	assert.Equal(t, "Welcome back", T(context.Background(), "auth.pwd.title"))
}

// TestOrEmpty_AnEmbeddedFailureRendersEveryKeyAsItself is the leniency the embedded default
// chooses, since it has no caller to hand an error to: every rendering surface answers the key or
// the code, the visible-miss policy, and none of them panics on the empty bundle it serves (#431).
func TestOrEmpty_AnEmbeddedFailureRendersEveryKeyAsItself(t *testing.T) {
	saved := installed.Load()
	t.Cleanup(func() { installed.Store(saved) })

	b := orEmpty(nil, errs.New("the embedded catalogs did not parse"))
	require.NotNil(t, b)
	installed.Store(b)

	assert.Equal(t, "auth.pwd.title", T(context.Background(), "auth.pwd.title"))
	assert.Equal(t, "js.error.unexpected", Raw(context.Background(), "js.error.unexpected"))

	le := NewLocalizedError(ErrCodeLoginAuthFailed, nil)
	assert.Equal(t, ErrCodeLoginAuthFailed, le.EnglishFallback())
	assert.Equal(t, ErrCodeLoginAuthFailed, le.Localize(context.Background()))

	for _, ctx := range []context.Context{
		resolveLocale(context.Background(), acceptLanguageRequest("pt-BR"), nil),
		WithLocale(context.Background(), true, "pt-BR"),
	} {
		assert.Equal(t, "auth.pwd.title", T(ctx, "auth.pwd.title"))
		assert.Equal(t, "pt-BR", LocaleTag(ctx))
	}
}

func TestOrEmpty_ALoadThatSucceededIsServedAsItIs(t *testing.T) {
	b, err := load("")
	require.NoError(t, err)
	assert.Same(t, b, orEmpty(b, nil))
}

func TestCurrent_ContainsEnAndPtBR(t *testing.T) {
	tags := tagStrings(current())
	require.NotEmpty(t, tags)
	assert.Contains(t, tags, "en")
	assert.Contains(t, tags, "pt-BR")
}

func acceptLanguageRequest(acceptLanguage string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Accept-Language", acceptLanguage)
	return r
}

// ctxFor builds a context carrying the translator the current bundle resolves
// for prefs — the shape Locale produces, without the HTTP layer.
func ctxFor(prefs ...string) context.Context {
	return ctxForBundle(current(), prefs...)
}

// ctxForBundle is ctxFor over a bundle the test built, installed nowhere.
func ctxForBundle(b *bundle, prefs ...string) context.Context {
	return context.WithValue(context.Background(), ctxKeyLocalizer, b.localizerFor(prefs))
}

func tagStrings(b *bundle) []string {
	out := make([]string, 0, len(b.tags))
	for _, tag := range b.tags {
		out = append(out, tag.String())
	}
	return out
}

// overridesDir writes each name->content under a temp overrides directory's
// catalogs/ and answers the directory.
func overridesDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	cataDir := filepath.Join(dir, "catalogs")
	require.NoError(t, os.MkdirAll(cataDir, 0o755))
	for name, content := range files {
		require.NoError(t, os.WriteFile(filepath.Join(cataDir, name), []byte(content), 0o644))
	}
	return dir
}

// loadWithOverrides loads a bundle from a temp overrides directory holding files, installing
// nothing. The load error is returned rather than asserted so the refusal cases can read it.
func loadWithOverrides(t *testing.T, files map[string]string) (*bundle, error) {
	t.Helper()
	return load(overridesDir(t, files))
}

func TestT_KeyMissingInMatchedLocaleFallsBackToEnglish(t *testing.T) {
	// A self-hoster ships an fr catalog holding one key. Every other key must
	// render the English text, which is what guides/localization.mdx
	// promises; T used to render the key itself here (#273).
	b, err := loadWithOverrides(t, map[string]string{
		"active.fr.toml": "\"auth.pwd.title\" = \"Connexion\"\n",
	})
	require.NoError(t, err)

	ctx := ctxForBundle(b, "fr")
	assert.Equal(t, "Connexion", T(ctx, "auth.pwd.title"))
	assert.Equal(t, "Password", T(ctx, "auth.pwd.password_label"))
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

func TestT_TemplatedValueThatFailsToExecuteRendersTheKey(t *testing.T) {
	// A value that parses can still fail while evaluating its data: {{.x.Y}}
	// reaches for a field on an int. That is the fifth rendering outcome, and
	// it renders the key like the parse failure above rather than the half
	// string Execute wrote before it failed. Missing data is not this case —
	// missingkey=default renders <no value> and returns no error (#273).
	b, err := loadWithOverrides(t, map[string]string{
		"active.pt-BR.toml": "\"auth.pwd.title\" = \"{{.x.Y}}\"\n",
	})
	require.NoError(t, err)

	ctx := ctxForBundle(b, "pt-BR")
	assert.Equal(t, "auth.pwd.title", T(ctx, "auth.pwd.title", map[string]any{"x": 1}))
}

// TestLocalizerFor_MatchesAsGoI18nDid is the parity table for the matcher that
// replaced go-i18n's: every row was derived by running go-i18n's Localizer and
// this one side by side over the same input, and every row is self-contained
// here. The rows that decide it, because nothing else observes them: a later
// range winning
// ("fr-FR,pt;q=0.8"), a q=0 range being excluded, quality reordering the list,
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
		{[]string{"fr"}, en},
		{[]string{"fr-FR"}, en},
		{[]string{""}, en},
		{[]string{"pt-BR,en;q=0.9"}, pt},
		{[]string{"fr-FR,pt;q=0.8"}, pt},
		{[]string{"garbage!!"}, en},
		{[]string{"*"}, en},
		{[]string{"fr", "pt-BR"}, pt},
		{[]string{"xx", "pt-BR"}, pt},
		{[]string{"pt-BR;q=0"}, en},
		{[]string{"en;q=0.1,pt-BR;q=0.9"}, pt},
	} {
		assert.Equalf(t, tc.want, T(ctxFor(tc.prefs...), "auth.pwd.title"),
			"locale resolution moved for %q", tc.prefs)
	}
}

func TestOverrideDir_TableValueIsRefusedNamingFileAndKey(t *testing.T) {
	// A [section] table is how go-i18n spelled plural forms. The loader has
	// no plural machinery, so it refuses the file at startup rather than
	// rendering one form for every count (#273).
	_, err := loadWithOverrides(t, map[string]string{
		"active.pt-BR.toml": "[section]\nother = \"x\"\n",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "active.pt-BR.toml")
	assert.Contains(t, err.Error(), `"section"`)
}

func TestOverrideDir_EmptyValueRemovesTheTranslation(t *testing.T) {
	// A blanked line in an override file means "use English" — the key is
	// removed from that locale rather than shadowed with a blank (#273).
	b, err := loadWithOverrides(t, map[string]string{
		"active.pt-BR.toml": "\"auth.pwd.title\" = \"\"\n",
	})
	require.NoError(t, err)

	ctx := ctxForBundle(b, "pt-BR")
	assert.Equal(t, "Sign in", T(ctx, "auth.pwd.title"))
	// Neighbouring keys are untouched by the removal.
	assert.Equal(t, "Senha", T(ctx, "auth.pwd.password_label"))
}
