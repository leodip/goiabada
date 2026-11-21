package render

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/authserver/internal/emailtemplate"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/web"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolish_SignInPageUsesQueryOrPolishHeader(t *testing.T) {
	for _, tc := range []struct{ target, accept string }{
		{"/auth/pwd?ui_locales=pl", "en"},
		{"/auth/pwd?ui_locales=pl-PL", "en"},
		{"/auth/pwd", "pl-PL"},
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
			assert.Contains(t, buf.String(), `<html lang="pl"`)
			assert.Contains(t, buf.String(), `>Zaloguj się</h1>`)
			assert.Contains(t, buf.String(), `>Zaloguj się</button>`)
			assert.Contains(t, buf.String(), `for="email">Adres e-mail</label>`) //nolint:misspell // the pl catalog's text: "adres" is Polish, not a misspelling of "address"
			assert.Contains(t, buf.String(), "Uwierzytelnianie nie powiodło się.")
		})
	}
}

// Every email, sent from its built-in definition (#818), follows a recipient reading Polish, in
// either tag: the subject, the language the email is marked with, and a sentence of the body, the
// activation link's and the verification code's saying how long they last, and the recovery code
// notice's giving the codes left.
func TestPolish_EveryDefinedEmailFollowsTheRecipient(t *testing.T) {
	assertDefinedEmailsFollowTheRecipient(t, []string{"pl", "pl-PL"}, "pl", []definedEmail{
		{emailtemplate.ActivationLink, "Aktywuj konto", "Link wygaśnie za 5 minut."},
		{emailtemplate.RegistrationExistingAccount, "Masz już konto", "Ten adres ma już konto, więc nie utworzono nowego."}, //nolint:misspell // the pl catalog's text: "adres" is Polish, not a misspelling of "address"
		{emailtemplate.Welcome, "Witamy!", "Twoje konto zostało utworzone."},
		{emailtemplate.VerificationCode, "Weryfikacja adresu e-mail – kod 482915", "Kod wygaśnie za 5 minut."},
		{emailtemplate.NewUserSetup, "Acme Portal – utwórz hasło do nowego konta", "Aby utworzyć hasło, kliknij poniższy link:"},
		{emailtemplate.TestEmail, "Acme Portal – testowa wiadomość e-mail", "To jest testowa wiadomość e-mail z Acme Portal."},
		{emailtemplate.EmailAddressChanged, "Zmieniono Twój adres e-mail", "Jeśli nie, ktoś inny może znać Twoje hasło."}, //nolint:misspell // the pl catalog's text: "adres" is Polish, not a misspelling of "address"
		{emailtemplate.PasswordChanged, "Zmieniono Twoje hasło", "Jeśli nie, ktoś inny może korzystać z Twojego konta."},
		{emailtemplate.PasswordChangedByAdministrator, "Administrator zmienił Twoje hasło", "Administrator zmienił hasło do Twojego konta w Acme Portal."},
		{emailtemplate.PasswordReset, "Zresetowano Twoje hasło", "ktoś inny może mieć dostęp do Twojej poczty e-mail i korzystać z Twojego konta."},
		{emailtemplate.OTPEnabled, "Skonfigurowano uwierzytelnianie dwuskładnikowe", "utworzono nowy zestaw kodów odzyskiwania"},
		{emailtemplate.OTPDisabled, "Wyłączono uwierzytelnianie dwuskładnikowe", "ponownie skonfiguruj uwierzytelnianie dwuskładnikowe"},
		{emailtemplate.OTPDisabledByAdministrator, "Administrator wyłączył Twoje uwierzytelnianie dwuskładnikowe", "Nową aplikację uwierzytelniającą możesz skonfigurować w ustawieniach konta."},
		{emailtemplate.RecoveryCodeUsed, "Do logowania użyto kodu odzyskiwania", "Pozostałe nieużyte kody odzyskiwania: 3."},
		{emailtemplate.RecoveryCodesReplaced, "Zastąpiono Twoje kody odzyskiwania", "Poprzednie kody odzyskiwania już nie działają"},
		{emailtemplate.OTPLockout, "Zablokowano Twoją aplikację uwierzytelniającą po zbyt wielu błędnych kodach", "Zaloguj się jednym z kodów odzyskiwania"},
		{emailtemplate.AccountDeleted, "Usunięto Twoje konto", "Jeśli nie, ktoś inny znał Twoje hasło."},
		{emailtemplate.AccountDeletedByAdministrator, "Administrator usunął Twoje konto", "Administrator usunął Twoje konto w Acme Portal."},
		{emailtemplate.PasswordResetLink, "Resetowanie hasła", "Aby zresetować hasło, kliknij poniższy link:"},
	})
}

// A recipient whose page language is Automatic and whose Language and region is pl-PL gets the
// Polish email, whatever the sender's request read, with {{expiry}} written in the accusative the
// expiry sentences take: minutę and godzinę for 1, minuty and godziny for 2 to 4 and 22 to 24, minut
// and godzin for 5 to 21 (#665 decision 3).
func TestPolish_ARecipientReadingPlPLGetsTheExpiryInItsForm(t *testing.T) {
	for _, tc := range []struct {
		expiry time.Duration
		unit   string
	}{
		{time.Minute, "1 minutę"},
		{2 * time.Minute, "2 minuty"},
		{5 * time.Minute, "5 minut"},
		{time.Hour, "1 godzinę"},
		{5 * time.Hour, "5 godzin"},
		{24 * time.Hour, "24 godziny"},
	} {
		for _, email := range []struct {
			email             *emailtemplate.Email
			subject, greeting string
			sentence          string
		}{
			{emailtemplate.ActivationLink, "Aktywuj konto", "Dzień dobry,", "Link wygaśnie za " + tc.unit + "."},
			{emailtemplate.PasswordResetLink, "Resetowanie hasła", "Dzień dobry Ana,", "Link wygaśnie za " + tc.unit + "."},
			{emailtemplate.VerificationCode, "Weryfikacja adresu e-mail – kod 482915", "Dzień dobry Ana,", "Kod wygaśnie za " + tc.unit + "."},
			{emailtemplate.NewUserSetup, "Acme Portal – utwórz hasło do nowego konta", "Dzień dobry Ana,", "Link jest ważny przez " + tc.unit + "."},
		} {
			t.Run(email.email.ID+"/"+tc.expiry.String(), func(t *testing.T) {
				ctx := reqctx.WithSettings(context.Background(), &record.Settings{AppName: "Acme Portal"})
				sender := httptest.NewRequest(http.MethodPost, "/forgot-password?ui_locales=de", nil).WithContext(ctx)
				sender.Header.Set("Accept-Language", "it")
				ctx = i18n.WithRecipientLanguage(i18n.ResolveRequestLocale(ctx, sender), "", "pl-PL")
				values := definitionValues
				values.Expiry = tc.expiry

				message, err := New(web.TemplateFS(), web.StaticFS(), nil).WithBaseURL(emailBaseURL).
					RenderEmail(sender.WithContext(ctx), email.email, values)
				require.NoError(t, err)

				assert.Equal(t, email.subject, message.Subject)
				doc, err := goquery.NewDocumentFromReader(strings.NewReader(message.HTML))
				require.NoError(t, err)
				lang, _ := doc.Find("html").Attr("lang")
				assert.Equal(t, "pl", lang)
				body := doc.Find("main").Text()
				assert.Contains(t, body, email.greeting)
				assert.Contains(t, body, email.sentence)
				assert.Contains(t, body, "Pozdrawiamy")
				assert.NotContains(t, message.HTML, "{{")
			})
		}
	}
}
