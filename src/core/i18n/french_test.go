package i18n

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFrench_RequestPreferencesAndRefusals(t *testing.T) {
	for _, tc := range []struct{ target, accept string }{
		{"/auth/pwd?ui_locales=fr", "en"},
		{"/auth/pwd", "fr-CA,fr;q=0.9,en;q=0.8"},
		{"/auth/pwd?ui_locales=fr-BE", "en"},
		{"/auth/pwd?ui_locales=fr-CH", "en"},
	} {
		t.Run(tc.target+tc.accept, func(t *testing.T) {
			req := httptest.NewRequest("GET", tc.target, nil)
			req.Header.Set("Accept-Language", tc.accept)
			ctx := throughLocaleMiddleware(t, req).Context()
			assert.Equal(t, "fr", CatalogTag(ctx))
			assert.Equal(t, "Connexion", T(ctx, "auth.pwd.title"))
			assert.Equal(t, "Échec de l’authentification.", NewLocalizedError(ErrCodeLoginAuthFailed, nil).Localize(ctx))
			assert.Equal(t, "Les adresses e-mail ne correspondent pas.", T(ctx, "adminconsole.refusal.account_email.confirmation_mismatch"))
			assert.Equal(t, "Utilisez au moins 15 caractères pour le mot de passe.", T(ctx, "validator.password.too_short", map[string]any{"min": 15}))
		})
	}
}

func TestFrench_RegionalTagsUseTheBuiltInCatalog(t *testing.T) {
	for _, locale := range []string{"fr", "fr-FR", "fr-CA", "fr-BE", "fr-CH"} {
		t.Run(locale, func(t *testing.T) {
			ctx := WithLocale(context.Background(), true, locale, "en")
			assert.Equal(t, "fr", CatalogTag(ctx))
			assert.Equal(t, locale, LocaleTag(ctx), "email copy selection retains the recipient’s regional tag")
			assert.Equal(t, "Mot de passe", T(ctx, "auth.pwd.password_label"))
		})
	}
}

func TestFrench_OperatorOverridesWinAndOmittedKeysNowReadFrench(t *testing.T) {
	b, err := loadWithOverrides(t, map[string]string{
		"active.fr.toml": `"auth.pwd.title" = "Accéder à votre espace"` + "\n",
	})
	require.NoError(t, err)
	ctx := ctxForBundle(b, "fr-CA")
	assert.Equal(t, "Accéder à votre espace", T(ctx, "auth.pwd.title"))
	assert.Equal(t, "Mot de passe", T(ctx, "auth.pwd.password_label"))
	assert.Equal(t, "Se connecter", T(ctx, "auth.pwd.button"))
}
