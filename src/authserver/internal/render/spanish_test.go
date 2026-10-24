package render

import (
	"net/http"
	"net/http/httptest"
	"testing"

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
			i18n.Locale(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				err := New(web.TemplateFS(), web.StaticFS()).RenderTemplate(w, r,
					"layouts/auth_layout.html", "auth_pwd.html", map[string]interface{}{"registrationAvailable": true})
				require.NoError(t, err)
			})).ServeHTTP(w, r)
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
		{"email_forgot_password", "forgot_password", "Restablecimiento de contraseña", "Para restablecer tu contraseña"},
		{"email_register_activate", "register_activate", "Activa tu cuenta", "El enlace caduca a los 5 minutos."},
		{"email_register_existing_account", "register_existing_account", "Ya tienes una cuenta", "Tu cuenta no ha cambiado."},
		{"email_register_confirmation", "register_confirmation", "¡Te damos la bienvenida!", "¡Tu cuenta ya está creada!"},
		{"email_newuser_set_password", "newuser_set_password", "Acme - crea una contraseña para tu nueva cuenta", "El enlace es válido durante 24 horas."},
		{"email_verification", "verification", "Verificación del correo - código 123456", "Este es tu código de verificación"},
		{"email_address_changed", "address_changed", "Tu dirección de correo electrónico ha cambiado", "puede que otra persona conozca tu contraseña."},
	} {
		for _, locale := range []string{"es", "es-MX", "es-419"} {
			t.Run(tc.body+" "+locale, func(t *testing.T) {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r = r.WithContext(reqctx.WithSettings(r.Context(), &record.Settings{AppName: "Acme"}))
				r = r.WithContext(i18n.WithLocale(r.Context(), true, locale, "en"))
				assert.Equal(t, tc.subject, i18n.T(r.Context(), "email."+tc.key+".subject", map[string]any{"code": "123456", "appName": "Acme"}))
				buf, err := New(web.TemplateFS(), web.StaticFS()).RenderTemplateToBuffer(r,
					"layouts/email_layout.html", "emails/"+tc.body+".html", map[string]interface{}{
						"name": "Ana", "link": "https://example.com/continue", "verificationCode": "123456",
					})
				require.NoError(t, err)
				assert.Contains(t, buf.String(), `<html lang="es">`)
				assert.Contains(t, buf.String(), tc.sentence)
				assert.Contains(t, buf.String(), "Acme")
				if tc.body != "email_address_changed" {
					assert.Contains(t, buf.String(), `href="https://example.com/continue"`)
				}
				if tc.body == "email_verification" {
					assert.Contains(t, buf.String(), "123456")
				}
			})
		}
	}
}
