package render

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/emailtemplate"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/web"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The sign-in page reads in Indonesian for a ui_locales asking for id and for a browser asking for
// id-ID, or for in, the tag older Android and Java systems send (#668), its refusal included.
func TestIndonesian_SignInPageUsesQueryOrRegionalHeader(t *testing.T) {
	for _, tc := range []struct{ target, accept string }{
		{"/auth/pwd?ui_locales=id", "en"},
		{"/auth/pwd", "id-ID"},
		{"/auth/pwd", "in"},
	} {
		t.Run(tc.target+tc.accept, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.target, nil)
			req.Header.Set("Accept-Language", tc.accept)
			req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{AppName: "Test"}))
			req = req.WithContext(i18n.ResolveRequestLocale(req.Context(), req))
			buf, err := New(web.TemplateFS(), web.StaticFS(), nil).RenderTemplateToBuffer(req,
				"layouts/auth_layout.html", "auth_pwd.html", map[string]interface{}{
					"error": i18n.NewLocalizedError(i18n.ErrCodeLoginAuthFailed, nil).Localize(req.Context()),
				})
			require.NoError(t, err)
			assert.Contains(t, buf.String(), `<html lang="id"`)
			assert.Contains(t, buf.String(), `>Masuk</h1>`)
			assert.Contains(t, buf.String(), `>Masuk</button>`)
			assert.Contains(t, buf.String(), `for="password">Kata sandi</label>`)
			assert.Contains(t, buf.String(), "Gagal masuk.")
		})
	}
}

// Every email, sent from its built-in definition (#818), follows a recipient reading Indonesian, by
// id, id-ID or in: the subject, the language the email is marked with, and a sentence of the body,
// the activation link's and the verification code's saying how long they last, and the recovery code
// notice's giving the codes left. The password reset link, the nineteenth, is held by
// TestRenderEmail_ThePasswordResetLinkFollowsTheRecipient's id-ID and in rows.
func TestIndonesian_EveryDefinedEmailFollowsTheRecipient(t *testing.T) {
	assertDefinedEmailsFollowTheRecipient(t, []string{"id", "id-ID", "in"}, "id", []definedEmail{
		{emailtemplate.ActivationLink, "Aktifkan akun Anda", "Tautan ini kedaluwarsa dalam 5 menit."},
		{emailtemplate.RegistrationExistingAccount, "Anda sudah memiliki akun", "jadi tidak ada akun baru yang dibuat."},
		{emailtemplate.Welcome, "Selamat datang!", "Akun Anda telah dibuat."},
		{emailtemplate.VerificationCode, "Verifikasi email - kode 482915", "Kode ini kedaluwarsa dalam 5 menit."},
		{emailtemplate.NewUserSetup, "Acme Portal - buat kata sandi untuk akun baru Anda", "Anda dapat membuat kata sandi Anda melalui tautan di bawah ini:"},
		{emailtemplate.TestEmail, "Acme Portal - email uji coba", "Ini adalah email uji coba dari Acme Portal."},
		{emailtemplate.EmailAddressChanged, "Alamat email Anda telah diubah", "Jika bukan Anda, orang lain mungkin mengetahui kata sandi Anda."},
		{emailtemplate.PasswordChanged, "Kata sandi Anda telah diubah", "Jika bukan Anda, orang lain mungkin sedang menggunakan akun Anda."},
		{emailtemplate.PasswordChangedByAdministrator, "Administrator telah mengubah kata sandi Anda", "Jika Anda tidak mengharapkannya, hubungi administrator Anda."},
		{emailtemplate.PasswordReset, "Kata sandi Anda telah diatur ulang", "Jika bukan Anda, orang lain mungkin dapat membaca email Anda dan menggunakan akun Anda."},
		{emailtemplate.OTPEnabled, "Autentikasi dua faktor telah disiapkan", "Bersamaan dengan itu dibuat satu set kode pemulihan baru"},
		{emailtemplate.OTPDisabled, "Autentikasi dua faktor telah dinonaktifkan", "lalu masuk dan siapkan kembali autentikasi dua faktor"},
		{emailtemplate.OTPDisabledByAdministrator, "Administrator telah menonaktifkan autentikasi dua faktor Anda", "Anda dapat menyiapkan aplikasi autentikator baru di pengaturan akun Anda."},
		{emailtemplate.RecoveryCodeUsed, "Kode pemulihan digunakan untuk masuk", "Sisa kode pemulihan yang belum digunakan: 3."},
		{emailtemplate.RecoveryCodesReplaced, "Kode pemulihan Anda telah diganti", "Kode pemulihan Anda sebelumnya tidak lagi berlaku"},
		{emailtemplate.OTPLockout, "Aplikasi autentikator Anda dinonaktifkan setelah terlalu banyak kode salah", "Masuk dengan salah satu kode pemulihan Anda"},
		{emailtemplate.AccountDeleted, "Akun Anda telah dihapus", "Jika bukan Anda, orang lain mengetahui kata sandi Anda."},
		{emailtemplate.AccountDeletedByAdministrator, "Administrator telah menghapus akun Anda", "Administrator telah menghapus akun Acme Portal Anda."},
	})
}
