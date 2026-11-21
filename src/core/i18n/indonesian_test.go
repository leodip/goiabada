package i18n

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// A request asking for Indonesian, by id, a regional id-* tag or in, the tag older Android and Java
// systems send, reads the pages and refusals in Indonesian (#668).
func TestIndonesian_RequestPreferencesAndRefusals(t *testing.T) {
	for _, tc := range []struct{ target, accept string }{
		{"/auth/pwd?ui_locales=id", "en"},
		{"/auth/pwd", "id-ID,id;q=0.9,en;q=0.8"},
		{"/auth/pwd?ui_locales=id-ID", "en"},
		{"/auth/pwd?ui_locales=in", "en"},
		{"/auth/pwd", "in"},
	} {
		t.Run(tc.target+tc.accept, func(t *testing.T) {
			req := httptest.NewRequest("GET", tc.target, nil)
			req.Header.Set("Accept-Language", tc.accept)
			ctx := throughLocaleMiddleware(t, req).Context()
			assert.Equal(t, "id", CatalogTag(ctx))
			assert.Equal(t, "Masuk", T(ctx, "auth.pwd.title"))
			assert.Equal(t, "Gagal masuk.", NewLocalizedError(ErrCodeLoginAuthFailed, nil).Localize(ctx))
			assert.Equal(t, "Alamat email tidak cocok.", T(ctx, "adminconsole.refusal.account_email.confirmation_mismatch"))
			assert.Equal(t, "Gunakan minimal 15 karakter untuk kata sandi.", T(ctx, "validator.password.too_short", map[string]any{"min": 15}))
		})
	}
}

func TestIndonesian_RegionalTagsUseTheBuiltInCatalog(t *testing.T) {
	for _, locale := range []string{"id", "id-ID", "in", "in-ID"} {
		t.Run(locale, func(t *testing.T) {
			ctx := WithLocale(context.Background(), true, locale, "en")
			assert.Equal(t, "id", CatalogTag(ctx))
			assert.Equal(t, locale, LocaleTag(ctx), "email copy selection retains the recipient’s regional tag")
			assert.Equal(t, "Kata sandi", T(ctx, "auth.pwd.password_label"))
		})
	}
}
