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

// The console's ordinary labels read in Indonesian, as the other translations localize them, and
// the instructions to replace recovery codes use the wording of the button they lead to (#668).
func TestIndonesian_OrdinaryConsoleLabels(t *testing.T) {
	ctx := WithLocale(context.Background(), true, "id", "en")
	for key, want := range map[string]string{
		"adminconsole.admin_branding.list.default_tag":               "Bawaan",
		"adminconsole.admin_branding.brand.make_default_button":      "Jadikan bawaan",
		"adminconsole.admin_settings.turnstile.field.site_key":       "Kunci situs",
		"adminconsole.admin_settings.turnstile.field.secret_key":     "Kunci rahasia",
		"adminconsole.admin_settings.turnstile.clear_secret_key":     "Hapus kunci rahasia yang tersimpan",
		"handler.settings_turnstile.site_key_required":               "Masukkan kunci situs untuk mengaktifkan tantangan Turnstile.",
		"adminconsole.admin_settings.audit_log_viewer.filter_button": "Saring",
		"adminconsole.admin_settings.audit_log_viewer.clear_link":    "Hapus saringan",
		"adminconsole.account.otp.recovery_codes.new_set_button":     "Buat kode pemulihan baru",
		"adminconsole.account.otp.recovery_codes.new_set_lead":       "Jika kode Anda hilang atau sudah habis terpakai, buat kode pemulihan baru. Masukkan kata sandi Anda untuk memastikan bahwa ini memang Anda.",
		"adminconsole.account.otp.recovery_codes.remaining.none":     "Anda tidak memiliki kode pemulihan yang belum digunakan. Buat kode pemulihan baru, agar Anda tetap dapat masuk jika aplikasi autentikator Anda hilang.",
		"auth.recovery_codes.shown_lead":                             "Kode ini hanya ditampilkan sekali. Jika Anda belum menyimpannya, buat kode pemulihan baru di konsol admin, di Akun, Autentikasi dua faktor.",
	} {
		assert.Equal(t, want, T(ctx, key), key)
	}
}
