package i18n

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A request asking for Polish, through ui_locales or the browser's Accept-Language, reads the
// pages and the refusals in Polish (#665).
func TestPolish_RequestPreferencesAndRefusals(t *testing.T) {
	for _, tc := range []struct{ target, accept string }{
		{"/auth/pwd?ui_locales=pl", "en"},
		{"/auth/pwd?ui_locales=pl-PL", "en"},
		{"/auth/pwd", "pl-PL"},
		{"/auth/pwd", "pl-PL,pl;q=0.9,en;q=0.8"},
	} {
		t.Run(tc.target+tc.accept, func(t *testing.T) {
			req := httptest.NewRequest("GET", tc.target, nil)
			req.Header.Set("Accept-Language", tc.accept)
			ctx := throughLocaleMiddleware(t, req).Context()
			assert.Equal(t, "pl", CatalogTag(ctx))
			assert.Equal(t, "Zaloguj się", T(ctx, "auth.pwd.title"))
			assert.Equal(t, "Uwierzytelnianie nie powiodło się.", NewLocalizedError(ErrCodeLoginAuthFailed, nil).Localize(ctx))
			assert.Equal(t, "Adresy e-mail nie są takie same.", T(ctx, "adminconsole.refusal.account_email.confirmation_mismatch"))
			assert.Equal(t, "Minimalna liczba znaków hasła: 15.", T(ctx, "validator.password.too_short", map[string]any{"min": 15}))
		})
	}
}

func TestPolish_RegionalTagsUseTheBuiltInCatalog(t *testing.T) {
	for _, locale := range []string{"pl", "pl-PL"} {
		t.Run(locale, func(t *testing.T) {
			ctx := WithLocale(context.Background(), true, locale, "en")
			assert.Equal(t, "pl", CatalogTag(ctx))
			assert.Equal(t, locale, LocaleTag(ctx), "email copy selection retains the recipient’s regional tag")
			assert.Equal(t, "Hasło", T(ctx, "auth.pwd.password_label"))
		})
	}
}

// A known user whose page language is pl reads Polish over a request asking for German and
// Italian.
func TestPolish_ThePageLanguageWinsOverTheRequest(t *testing.T) {
	ctx := WithPageLanguage(throughLocale(t, nil, "/forgot-password?ui_locales=de", "it"), "pl")
	assert.Equal(t, "pl", CatalogTag(ctx))
	assert.Equal(t, "Zresetuj hasło", T(ctx, "forgot_password.title"))
}

// A recipient on Automatic whose Language and region is pl or pl-PL gets Polish, whatever the
// sender's request read; a recipient who chose pl gets it over their Language and region.
func TestPolish_TheRecipientReadsPolish(t *testing.T) {
	for _, tc := range []struct{ name, pageLanguage, locale string }{
		{"Automatic, pl-PL", "", "pl-PL"},
		{"Automatic, pl", "", "pl"},
		{"pl chosen over French", "pl", "fr"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sender := throughLocale(t, nil, "/forgot-password?ui_locales=de", "it")
			require.Equal(t, "Passwort zurücksetzen", T(sender, "forgot_password.title"))

			ctx := WithRecipientLanguage(sender, tc.pageLanguage, tc.locale)
			assert.Equal(t, "pl", CatalogTag(ctx))
			assert.Equal(t, "Zresetuj hasło", T(ctx, "forgot_password.title"))
		})
	}
}
