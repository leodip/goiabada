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
	r := DefaultBundle().localizerFor([]string{"pt-BR"})
	ctx := context.WithValue(context.Background(), ctxKeyLocalizer, r)
	assert.Equal(t, "Entrar", T(ctx, "auth.pwd.title"))
}

func TestT_UnknownLocaleFallsBackToEnglish(t *testing.T) {
	// "xx" is not a registered locale; go-i18n falls back to the bundle's
	// default tag (English).
	r := DefaultBundle().localizerFor([]string{"xx"})
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

	r := DefaultBundle().localizerFor([]string{"pt-BR"})
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
	for _, tag := range DefaultBundle().SupportedTags() {
		tagStrings = append(tagStrings, tag.String())
	}
	assert.Contains(t, tagStrings, "fr",
		"override-only locale 'fr' must appear in SupportedTags() so locale pickers see it")

	// Embedded locales must still be present too.
	assert.Contains(t, tagStrings, "en")
	assert.Contains(t, tagStrings, "pt-BR")

	// And the override translation actually works.
	r := DefaultBundle().localizerFor([]string{"fr"})
	ctx := context.WithValue(context.Background(), ctxKeyLocalizer, r)
	assert.Equal(t, "Connexion", T(ctx, "auth.pwd.title"))
}

func TestSupportedTags_ContainsEnAndPtBR(t *testing.T) {
	tags := DefaultBundle().SupportedTags()
	require.NotEmpty(t, tags)
	tagStrings := make([]string, 0, len(tags))
	for _, t := range tags {
		tagStrings = append(tagStrings, t.String())
	}
	assert.Contains(t, tagStrings, "en")
	assert.Contains(t, tagStrings, "pt-BR")
}
