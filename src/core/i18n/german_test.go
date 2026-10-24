package i18n

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGerman_RequestPreferencesAndRefusals(t *testing.T) {
	for _, tc := range []struct{ target, accept string }{
		{"/auth/pwd?ui_locales=de", "en"},
		{"/auth/pwd", "de-AT,de;q=0.9,en;q=0.8"},
		{"/auth/pwd?ui_locales=de-CH", "en"},
		{"/auth/pwd?ui_locales=de-LI", "en"},
	} {
		t.Run(tc.target+tc.accept, func(t *testing.T) {
			req := httptest.NewRequest("GET", tc.target, nil)
			req.Header.Set("Accept-Language", tc.accept)
			ctx := throughLocaleMiddleware(t, req).Context()
			assert.Equal(t, "de", CatalogTag(ctx))
			assert.Equal(t, "Anmelden", T(ctx, "auth.pwd.title"))
			assert.Equal(t, "Anmeldung fehlgeschlagen.", NewLocalizedError(ErrCodeLoginAuthFailed, nil).Localize(ctx))
			assert.Equal(t, "Die E-Mail-Adressen stimmen nicht überein.", T(ctx, "adminconsole.refusal.account_email.confirmation_mismatch"))
			assert.Equal(t, "Verwenden Sie mindestens 15 Zeichen für das Passwort.", T(ctx, "validator.password.too_short", map[string]any{"min": 15}))
		})
	}
}

func TestGerman_RegionalTagsUseTheBuiltInCatalog(t *testing.T) {
	for _, locale := range []string{"de", "de-DE", "de-AT", "de-CH", "de-LI"} {
		t.Run(locale, func(t *testing.T) {
			ctx := WithLocale(context.Background(), true, locale, "en")
			assert.Equal(t, "de", CatalogTag(ctx))
			assert.Equal(t, locale, LocaleTag(ctx), "email copy selection retains the recipient’s regional tag")
			assert.Equal(t, "Passwort", T(ctx, "auth.pwd.password_label"))
		})
	}
}

func TestGerman_OperatorOverridesWinAndOmittedKeysNowReadGerman(t *testing.T) {
	b, err := loadWithOverrides(t, map[string]string{
		"active.de.toml": `"auth.pwd.title" = "Zum Konto"
"common.button.cancel" = ""` + "\n",
	})
	require.NoError(t, err)
	ctx := ctxForBundle(b, "de-AT")
	assert.Equal(t, "Zum Konto", T(ctx, "auth.pwd.title"))
	assert.Equal(t, "Passwort", T(ctx, "auth.pwd.password_label"))
	assert.Equal(t, "Anmelden", T(ctx, "auth.pwd.button"))
	assert.Equal(t, "Cancel", T(ctx, "common.button.cancel"))
}
