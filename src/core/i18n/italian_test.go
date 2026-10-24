package i18n

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestItalian_RequestPreferencesAndRefusals(t *testing.T) {
	for _, tc := range []struct{ target, accept string }{
		{"/auth/pwd?ui_locales=it", "en"},
		{"/auth/pwd", "it-CH,it;q=0.9,en;q=0.8"},
		{"/auth/pwd?ui_locales=it-SM", "en"},
		{"/auth/pwd?ui_locales=it-VA", "en"},
	} {
		t.Run(tc.target+tc.accept, func(t *testing.T) {
			req := httptest.NewRequest("GET", tc.target, nil)
			req.Header.Set("Accept-Language", tc.accept)
			ctx := throughLocaleMiddleware(t, req).Context()
			assert.Equal(t, "it", CatalogTag(ctx))
			assert.Equal(t, "Accedi", T(ctx, "auth.pwd.title"))
			assert.Equal(t, "Autenticazione non riuscita.", NewLocalizedError(ErrCodeLoginAuthFailed, nil).Localize(ctx))
			assert.Equal(t, "Gli indirizzi email non corrispondono.", T(ctx, "adminconsole.refusal.account_email.confirmation_mismatch"))
			assert.Equal(t, "Usa almeno 15 caratteri per la password.", T(ctx, "validator.password.too_short", map[string]any{"min": 15}))
		})
	}
}

func TestItalian_RegionalTagsUseTheBuiltInCatalog(t *testing.T) {
	for _, locale := range []string{"it", "it-IT", "it-CH", "it-SM", "it-VA"} {
		t.Run(locale, func(t *testing.T) {
			ctx := WithLocale(context.Background(), true, locale, "en")
			assert.Equal(t, "it", CatalogTag(ctx))
			assert.Equal(t, locale, LocaleTag(ctx), "email copy selection retains the recipient’s regional tag")
			assert.Equal(t, "Password", T(ctx, "auth.pwd.password_label"))
		})
	}
}

func TestItalian_OperatorOverridesWinAndOmittedKeysNowReadItalian(t *testing.T) {
	b, err := loadWithOverrides(t, map[string]string{
		"active.it.toml": `"auth.pwd.title" = "Entra nel tuo spazio"` + "\n" + `"auth.pwd.forgot_password" = ""` + "\n",
	})
	require.NoError(t, err)
	ctx := ctxForBundle(b, "it-CH")
	assert.Equal(t, "Entra nel tuo spazio", T(ctx, "auth.pwd.title"))
	assert.Equal(t, "Password", T(ctx, "auth.pwd.password_label"))
	assert.Equal(t, "Accedi", T(ctx, "auth.pwd.button"))
	assert.Equal(t, "Forgot your password?", T(ctx, "auth.pwd.forgot_password"), "an explicitly empty override keeps the English fallback")
}
