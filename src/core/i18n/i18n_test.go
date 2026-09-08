package i18n

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMain loads the embedded bundle once; subsequent tests share it.
// LoadBundle replaces the package-level default, so don't run tests in
// parallel against a different override directory without restoring it.
func TestMain(m *testing.M) {
	// Make sure GOIABADA_I18N_OVERRIDES_DIR is unset for the baseline tests;
	// the override-merge test sets it temporarily and unsets when done.
	_ = os.Unsetenv("GOIABADA_I18N_OVERRIDES_DIR")
	if _, err := LoadBundle(); err != nil {
		panic("i18n test bootstrap LoadBundle: " + err.Error())
	}
	os.Exit(m.Run())
}

func TestT_EnglishKeyResolves(t *testing.T) {
	ctx := context.Background()
	got := T(ctx, "auth.pwd.title")
	assert.Equal(t, "Login", got)
}

func TestT_PtBRKeyResolves(t *testing.T) {
	// Build a localizer that prefers pt-BR — exercising the loaded stub catalog.
	r := defaultBundle.localizerFor([]string{"pt-BR"})
	ctx := context.WithValue(context.Background(), ctxKeyLocalizer, r)
	assert.Equal(t, "Entrar", T(ctx, "auth.pwd.title"))
}

func TestT_UnknownLocaleFallsBackToEnglish(t *testing.T) {
	// "xx" is not a registered locale; the matcher falls back to the tag at
	// index 0, which is English.
	r := defaultBundle.localizerFor([]string{"xx"})
	ctx := context.WithValue(context.Background(), ctxKeyLocalizer, r)
	assert.Equal(t, "Login", T(ctx, "auth.pwd.title"))
}

func TestT_MissingKeyReturnsKey(t *testing.T) {
	// Visible-miss policy: missing-in-English keys surface the literal key
	// so the gap is obvious in dev.
	got := T(context.Background(), "nope.this.key.does.not.exist")
	assert.Equal(t, "nope.this.key.does.not.exist", got)
}

func TestLocalizer_NoCtxFallsBackToEnglish(t *testing.T) {
	loc := Localizer(context.Background())
	require.NotNil(t, loc)
	// T against an empty context resolves through the English fallback.
	assert.Equal(t, "Login", T(context.Background(), "auth.pwd.title"))
}

func TestOverrideDir_MergesOnTopOfEmbedded(t *testing.T) {
	// Build a minimal override layout in a temp dir, point the env var at it,
	// reload, and verify the override wins.
	dir := t.TempDir()
	cataDir := filepath.Join(dir, "catalogs")
	require.NoError(t, os.MkdirAll(cataDir, 0o755))
	// Override pt-BR's "auth.pwd.title" with a self-host-customized value.
	override := `"auth.pwd.title" = "Acesse"
`
	require.NoError(t, os.WriteFile(filepath.Join(cataDir, "active.pt-BR.toml"), []byte(override), 0o644))

	t.Setenv("GOIABADA_I18N_OVERRIDES_DIR", dir)
	t.Cleanup(func() {
		// Restore the embedded-only bundle for subsequent tests.
		_ = os.Unsetenv("GOIABADA_I18N_OVERRIDES_DIR")
		_, _ = LoadBundle()
	})

	_, err := LoadBundle()
	require.NoError(t, err)

	r := defaultBundle.localizerFor([]string{"pt-BR"})
	ctx := context.WithValue(context.Background(), ctxKeyLocalizer, r)
	assert.Equal(t, "Acesse", T(ctx, "auth.pwd.title"))

	// Untouched key still falls back to the embedded pt-BR catalog.
	assert.Equal(t, "Senha", T(ctx, "auth.pwd.password_label"))
}

func TestOverrideDir_NoCatalogsSubdir_IsNoOp(t *testing.T) {
	// An override dir without a catalogs/ subdir is valid — log + skip.
	dir := t.TempDir()
	t.Setenv("GOIABADA_I18N_OVERRIDES_DIR", dir)
	t.Cleanup(func() {
		_ = os.Unsetenv("GOIABADA_I18N_OVERRIDES_DIR")
		_, _ = LoadBundle()
	})

	_, err := LoadBundle()
	assert.NoError(t, err)
}

func TestOverrideOnlyLocale_AppearsInSupportedTags(t *testing.T) {
	// A self-hoster ships only an override file for a locale that isn't in
	// the embedded set. The bundle must surface that locale in
	// SupportedTags() so downstream consumers (locale pickers,
	// supported-locale validation) can see it.
	dir := t.TempDir()
	cataDir := filepath.Join(dir, "catalogs")
	require.NoError(t, os.MkdirAll(cataDir, 0o755))
	override := `"auth.pwd.title" = "Connexion"
`
	require.NoError(t, os.WriteFile(filepath.Join(cataDir, "active.fr.toml"), []byte(override), 0o644))

	t.Setenv("GOIABADA_I18N_OVERRIDES_DIR", dir)
	t.Cleanup(func() {
		_ = os.Unsetenv("GOIABADA_I18N_OVERRIDES_DIR")
		_, _ = LoadBundle()
	})

	_, err := LoadBundle()
	require.NoError(t, err)

	tagStrings := make([]string, 0)
	for _, tag := range defaultBundle.SupportedTags() {
		tagStrings = append(tagStrings, tag.String())
	}
	assert.Contains(t, tagStrings, "fr",
		"override-only locale 'fr' must appear in SupportedTags() so locale pickers see it")

	// Embedded locales must still be present too.
	assert.Contains(t, tagStrings, "en")
	assert.Contains(t, tagStrings, "pt-BR")

	// And the override translation actually works.
	r := defaultBundle.localizerFor([]string{"fr"})
	ctx := context.WithValue(context.Background(), ctxKeyLocalizer, r)
	assert.Equal(t, "Connexion", T(ctx, "auth.pwd.title"))
}

func TestSupportedTags_ContainsEnAndPtBR(t *testing.T) {
	tags := defaultBundle.SupportedTags()
	require.NotEmpty(t, tags)
	tagStrings := make([]string, 0, len(tags))
	for _, t := range tags {
		tagStrings = append(tagStrings, t.String())
	}
	assert.Contains(t, tagStrings, "en")
	assert.Contains(t, tagStrings, "pt-BR")
}

// ctxFor builds a context carrying the translator the default bundle resolves
// for prefs — the shape MiddlewareLocale produces, without the HTTP layer.
func ctxFor(prefs ...string) context.Context {
	return context.WithValue(context.Background(), ctxKeyLocalizer, defaultBundle.localizerFor(prefs))
}

// loadBundleWithOverrides writes each name->content under a temp overrides
// directory, reloads the package bundle from it, and restores the
// embedded-only bundle when the test ends. The load error is returned rather
// than asserted so the refusal cases can read it.
func loadBundleWithOverrides(t *testing.T, files map[string]string) error {
	t.Helper()
	dir := t.TempDir()
	cataDir := filepath.Join(dir, "catalogs")
	require.NoError(t, os.MkdirAll(cataDir, 0o755))
	for name, content := range files {
		require.NoError(t, os.WriteFile(filepath.Join(cataDir, name), []byte(content), 0o644))
	}

	t.Setenv("GOIABADA_I18N_OVERRIDES_DIR", dir)
	t.Cleanup(func() {
		_ = os.Unsetenv("GOIABADA_I18N_OVERRIDES_DIR")
		_, _ = LoadBundle()
	})

	_, err := LoadBundle()
	return err
}

func TestT_KeyMissingInMatchedLocaleFallsBackToEnglish(t *testing.T) {
	// A self-hoster ships an fr catalog holding one key. Every other key must
	// render the English text, which is what concepts/localization.mdx
	// promises; T used to render the key itself here (#273).
	require.NoError(t, loadBundleWithOverrides(t, map[string]string{
		"active.fr.toml": "\"auth.pwd.title\" = \"Connexion\"\n",
	}))

	ctx := ctxFor("fr")
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

// TestLocalizerFor_MatchesAsGoI18nDid holds every row of the parity table in
// docs/issue-273-retire-go-i18n/probe/matcher.out, which ran go-i18n's
// Localizer and this matcher side by side over the same inputs. The rows that
// decide it, because nothing else observes them: a later range winning
// ("fr-FR,pt;q=0.8"), a q=0 range being excluded, quality reordering the list,
// unparseable input falling to English, and the ui_locales shape where the
// first tag is unsupported.
func TestLocalizerFor_MatchesAsGoI18nDid(t *testing.T) {
	const (
		en = "Login"
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
	err := loadBundleWithOverrides(t, map[string]string{
		"active.pt-BR.toml": "[section]\nother = \"x\"\n",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "active.pt-BR.toml")
	assert.Contains(t, err.Error(), `"section"`)
}

func TestOverrideDir_EmptyValueRemovesTheTranslation(t *testing.T) {
	// A blanked line in an override file means "use English" — the key is
	// removed from that locale rather than shadowed with a blank (#273).
	require.NoError(t, loadBundleWithOverrides(t, map[string]string{
		"active.pt-BR.toml": "\"auth.pwd.title\" = \"\"\n",
	}))

	ctx := ctxFor("pt-BR")
	assert.Equal(t, "Login", T(ctx, "auth.pwd.title"))
	// Neighbouring keys are untouched by the removal.
	assert.Equal(t, "Senha", T(ctx, "auth.pwd.password_label"))
}
