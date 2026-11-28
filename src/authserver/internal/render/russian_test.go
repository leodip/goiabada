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

func TestRussian_SignInPageUsesQueryOrRussianHeader(t *testing.T) {
	for _, tc := range []struct{ target, accept string }{
		{"/auth/pwd?ui_locales=ru", "en"},
		{"/auth/pwd?ui_locales=ru-RU", "en"},
		{"/auth/pwd", "ru-RU"},
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
			assert.Contains(t, buf.String(), `<html lang="ru"`)
			assert.Contains(t, buf.String(), `>Вход</h1>`)
			assert.Contains(t, buf.String(), `>Войти</button>`)
			assert.Contains(t, buf.String(), `for="email">Электронная почта</label>`)
			assert.Contains(t, buf.String(), "Ошибка аутентификации.")
		})
	}
}

// Every email, sent from its built-in definition (#818), follows a recipient reading Russian, in
// its own tag and in regional ones: the subject, the language the email is marked with, and a
// sentence of the body, the activation link's and the verification code's saying how long they
// last, and the recovery code notice's giving the codes left.
func TestRussian_EveryDefinedEmailFollowsTheRecipient(t *testing.T) {
	assertDefinedEmailsFollowTheRecipient(t, []string{"ru", "ru-RU", "ru-KZ"}, "ru", []definedEmail{
		{emailtemplate.ActivationLink, "Активируйте аккаунт", "Срок действия ссылки истечет через 5 минут."},
		{emailtemplate.RegistrationExistingAccount, "У вас уже есть аккаунт", "С этим адресом уже связан аккаунт, поэтому новый аккаунт не создан."},
		{emailtemplate.Welcome, "Добро пожаловать!", "Поздравляем! Ваш аккаунт создан."},
		{emailtemplate.VerificationCode, "Подтверждение адреса электронной почты — код 482915", "Срок действия кода истечет через 5 минут."},
		{emailtemplate.NewUserSetup, "Acme Portal — создайте пароль для нового аккаунта", "Чтобы создать пароль, перейдите по ссылке ниже:"},
		{emailtemplate.TestEmail, "Acme Portal — тестовое письмо", "Это тестовое письмо от Acme Portal."},
		{emailtemplate.EmailAddressChanged, "Ваш адрес электронной почты изменен", "Если нет, возможно, ваш пароль известен кому-то еще."},
		{emailtemplate.PasswordChanged, "Ваш пароль изменен", "Если нет, возможно, вашим аккаунтом пользуется кто-то другой."},
		{emailtemplate.PasswordChangedByAdministrator, "Администратор изменил ваш пароль", "Администратор изменил пароль вашего аккаунта в Acme Portal."},
		{emailtemplate.PasswordReset, "Ваш пароль сброшен", "кто-то другой может читать вашу почту и пользоваться вашим аккаунтом."},
		{emailtemplate.OTPEnabled, "Двухфакторная аутентификация настроена", "создан новый набор кодов восстановления"},
		{emailtemplate.OTPDisabled, "Двухфакторная аутентификация отключена", "снова настройте двухфакторную аутентификацию"},
		{emailtemplate.OTPDisabledByAdministrator, "Администратор отключил вашу двухфакторную аутентификацию", "Новое приложение-аутентификатор можно подключить в настройках аккаунта."},
		{emailtemplate.RecoveryCodeUsed, "Для входа использован код восстановления", "Осталось неиспользованных кодов восстановления: 3."},
		{emailtemplate.RecoveryCodesReplaced, "Ваши коды восстановления заменены", "Прежние коды восстановления больше не действуют"},
		{emailtemplate.OTPLockout, "Приложение-аутентификатор отключено из-за слишком большого числа неверных кодов", "Войдите с одним из кодов восстановления"},
		{emailtemplate.AccountDeleted, "Ваш аккаунт удален", "значит, ваш пароль был известен кому-то еще."},
		{emailtemplate.AccountDeletedByAdministrator, "Администратор удалил ваш аккаунт", "Администратор удалил ваш аккаунт в Acme Portal."},
		{emailtemplate.PasswordResetLink, "Сброс пароля", "Чтобы сбросить пароль, перейдите по ссылке ниже:"},
	})
}

// A recipient whose page language is Automatic and whose Language and region is ru-RU gets the
// Russian email, whatever the sender's request read, with {{expiry}} written in the accusative the
// expiry sentences take: минуту and час for 1 and 21, минуты and часа for 2 to 4 and 22 to 24, минут
// and часов for 5 to 20 (#666 decision 5).
func TestRussian_ARecipientReadingRuRUGetsTheExpiryInItsForm(t *testing.T) {
	for _, tc := range []struct {
		expiry time.Duration
		unit   string
	}{
		{time.Minute, "1 минуту"},
		{2 * time.Minute, "2 минуты"},
		{5 * time.Minute, "5 минут"},
		{21 * time.Minute, "21 минуту"},
		{time.Hour, "1 час"},
		{5 * time.Hour, "5 часов"},
		{24 * time.Hour, "24 часа"},
	} {
		for _, email := range []struct {
			email             *emailtemplate.Email
			subject, greeting string
			sentence          string
		}{
			{emailtemplate.ActivationLink, "Активируйте аккаунт", "Здравствуйте!", "Срок действия ссылки истечет через " + tc.unit + "."},
			{emailtemplate.PasswordResetLink, "Сброс пароля", "Здравствуйте, Ana!", "Срок действия ссылки истечет через " + tc.unit + "."},
			{emailtemplate.VerificationCode, "Подтверждение адреса электронной почты — код 482915", "Здравствуйте, Ana!", "Срок действия кода истечет через " + tc.unit + "."},
			{emailtemplate.NewUserSetup, "Acme Portal — создайте пароль для нового аккаунта", "Здравствуйте, Ana!", "Ссылка действует " + tc.unit + "."},
		} {
			t.Run(email.email.ID+"/"+tc.expiry.String(), func(t *testing.T) {
				ctx := reqctx.WithSettings(context.Background(), &record.Settings{AppName: "Acme Portal"})
				sender := httptest.NewRequest(http.MethodPost, "/forgot-password?ui_locales=de", nil).WithContext(ctx)
				sender.Header.Set("Accept-Language", "it")
				ctx = i18n.WithRecipientLanguage(i18n.ResolveRequestLocale(ctx, sender), "", "ru-RU")
				values := definitionValues
				values.Expiry = tc.expiry

				message, err := New(web.TemplateFS(), web.StaticFS(), nil).WithBaseURL(emailBaseURL).
					RenderEmail(sender.WithContext(ctx), email.email, values)
				require.NoError(t, err)

				assert.Equal(t, email.subject, message.Subject)
				doc, err := goquery.NewDocumentFromReader(strings.NewReader(message.HTML))
				require.NoError(t, err)
				lang, _ := doc.Find("html").Attr("lang")
				assert.Equal(t, "ru", lang)
				body := doc.Find("main").Text()
				assert.Contains(t, body, email.greeting)
				assert.Contains(t, body, email.sentence)
				assert.Contains(t, body, "С уважением,")
				assert.NotContains(t, message.HTML, "{{")
			})
		}
	}
}
