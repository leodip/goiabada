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

func TestSpanish_SignInPageFromRequestPreferences(t *testing.T) {
	for _, tc := range []struct{ target, header string }{
		{"/auth/pwd?ui_locales=es", "en"},
		{"/auth/pwd", "es-MX"},
	} {
		t.Run(tc.target+tc.header, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, tc.target, nil)
			r.Header.Set("Accept-Language", tc.header)
			r = r.WithContext(reqctx.WithSettings(r.Context(), &record.Settings{AppName: "Acme", SMTPEnabled: true}))
			w := httptest.NewRecorder()
			var renderErr error
			i18n.Locale(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				renderErr = New(web.TemplateFS(), web.StaticFS(), nil).RenderTemplate(w, r,
					"layouts/auth_layout.html", "auth_pwd.html", map[string]interface{}{"registrationAvailable": true})
			})).ServeHTTP(w, r)
			require.NoError(t, renderErr)
			assert.Equal(t, http.StatusOK, w.Code)
			assert.Contains(t, w.Body.String(), `<html lang="es"`)
			assert.Contains(t, w.Body.String(), "Iniciar sesión")
			assert.Contains(t, w.Body.String(), "Contraseña")
			assert.Contains(t, w.Body.String(), "Crear una cuenta")
		})
	}
}

func TestSpanish_RegionalRecipientsGetEverySubjectAndBody(t *testing.T) {
	for _, tc := range []struct{ body, key, subject, sentence string }{
		{"email_address_changed", "address_changed", "Tu dirección de correo electrónico ha cambiado", "puede que otra persona conozca tu contraseña."},
		{"email_password_changed", "password_changed", "Tu contraseña ha cambiado", "puede que otra persona esté usando tu cuenta."},
		{"email_password_changed_by_administrator", "password_changed_by_administrator", "Un administrador ha cambiado tu contraseña", "Si no lo esperabas, contacta con tu administrador."},
		{"email_password_reset", "password_reset", "Tu contraseña se ha restablecido", "puede que otra persona lea tu correo y esté usando tu cuenta."},
		{"email_otp_enabled", "otp_enabled", "Se ha configurado la autenticación de dos factores", "Viene con un nuevo conjunto de códigos de recuperación"},                                                    //nolint:misspell // the es catalog's text: "factores" is Spanish, not a misspelling of "factors"
		{"email_otp_disabled", "otp_disabled", "Se ha desactivado la autenticación de dos factores", "vuelve a configurar la autenticación de dos factores"},                                                    //nolint:misspell // the es catalog's text: "factores" is Spanish, not a misspelling of "factors"
		{"email_otp_disabled_by_administrator", "otp_disabled_by_administrator", "Un administrador ha desactivado tu autenticación de dos factores", "Puedes configurar una nueva aplicación de autenticación"}, //nolint:misspell // the es catalog's text: "factores" is Spanish, not a misspelling of "factors"
		{"email_recovery_code_used", "recovery_code_used", "Se ha usado un código de recuperación para iniciar sesión", "Te quedan 3 códigos de recuperación sin usar."},
		{"email_recovery_codes_replaced", "recovery_codes_replaced", "Se han sustituido tus códigos de recuperación", "Tus códigos de recuperación anteriores ya no sirven"},
		{"email_otp_lockout", "otp_lockout", "Tu aplicación de autenticación se ha bloqueado tras demasiados códigos incorrectos", "Inicia sesión con uno de tus códigos de recuperación"},
		{"email_account_deleted", "account_deleted", "Se ha eliminado tu cuenta", "Si no has sido tú, otra persona conocía tu contraseña."},
		{"email_account_deleted_by_administrator", "account_deleted_by_administrator", "Un administrador ha eliminado tu cuenta", "Si no lo esperabas, contacta con tu administrador."},
	} {
		for _, locale := range []string{"es", "es-MX", "es-419"} {
			t.Run(tc.body+" "+locale, func(t *testing.T) {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r = r.WithContext(reqctx.WithSettings(r.Context(), &record.Settings{AppName: "Acme"}))
				r = r.WithContext(i18n.WithLocale(r.Context(), true, locale, "en"))
				assert.Equal(t, tc.subject, i18n.T(r.Context(), "email."+tc.key+".subject", map[string]any{"code": "123456", "appName": "Acme"}))
				buf, err := New(web.TemplateFS(), web.StaticFS(), nil).RenderTemplateToBuffer(r,
					"layouts/email_layout.html", "emails/"+tc.body+".html", map[string]interface{}{
						"name": "Ana", "link": "https://example.com/continue", "remaining": 3,
					})
				require.NoError(t, err)
				assert.Contains(t, buf.String(), `<html lang="es">`)
				assert.Contains(t, buf.String(), tc.sentence)
				assert.Contains(t, buf.String(), "Acme")
				// A notice of a change carries no link.
				assert.NotContains(t, buf.String(), "href")
			})
		}
	}
}

// The emails sent from their built-in definitions (#818) follow a recipient reading Spanish, in any
// region, as the template emails do: the subject, the language the email is marked with, and a
// sentence of the body, the activation link's and the verification code's saying how long they last.
func TestSpanish_EveryDefinedEmailFollowsTheRecipient(t *testing.T) {
	assertDefinedEmailsFollowTheRecipient(t, []string{"es", "es-MX", "es-419"}, "es", []definedEmail{
		{emailtemplate.ActivationLink, "Activa tu cuenta", "El enlace caduca en 5 minutos."},
		{emailtemplate.RegistrationExistingAccount, "Ya tienes una cuenta", "Tu cuenta no ha cambiado."},
		{emailtemplate.Welcome, "¡Te damos la bienvenida!", "¡Tu cuenta ya está creada!"},
		{emailtemplate.VerificationCode, "Verificación del correo - código 482915", "El código caduca en 5 minutos."},
		{emailtemplate.NewUserSetup, "Acme Portal - crea una contraseña para tu nueva cuenta", "Para crear tu contraseña, abre este enlace:"},
		{emailtemplate.TestEmail, "Acme Portal - correo de prueba", "Este es un correo de prueba enviado por Acme Portal."},
	})
}
