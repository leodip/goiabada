package render

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/leodip/goiabada/adminconsole/web"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSpanish_AdminPageFromRequestPreferences(t *testing.T) {
	for _, tc := range []struct{ target, header string }{
		{"/admin/clients?ui_locales=es", "en"},
		{"/admin/clients", "es-MX"},
	} {
		t.Run(tc.target+tc.header, func(t *testing.T) {
			r := newRequest(http.MethodGet, tc.target, nil)
			r.Header.Set("Accept-Language", tc.header)
			w := httptest.NewRecorder()
			var renderErr error
			i18n.Locale(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				renderErr = New(web.TemplateFS(), web.StaticFS()).RenderTemplate(w, r,
					"layouts/menu_layout.html", "admin_clients.html", nil)
			})).ServeHTTP(w, r)
			require.NoError(t, renderErr)
			assert.Equal(t, http.StatusOK, w.Code)
			assert.Contains(t, w.Body.String(), `<html lang="es"`)
			assert.Contains(t, w.Body.String(), `data-catalog-lang="es"`)
			assert.Contains(t, w.Body.String(), "Nuevo cliente")
			assert.Contains(t, w.Body.String(), "Todavía no hay clientes.") //nolint:misspell // the es catalog's text: "clientes" is Spanish, not a misspelling of "clients"
		})
	}
}

func TestSpanish_DatesAndRelativeTimes(t *testing.T) {
	ctx := localeCtx("es-MX")
	instant := timeFmtInstant
	assert.Equal(t, "14/09/2026 21:03", formatDateTime(ctx, &instant))
	for _, tc := range []struct {
		age  time.Duration
		want string
	}{
		{0, "ahora mismo"},
		{time.Second, "hace 1 segundo"}, {2 * time.Second, "hace 2 segundos"},
		{time.Minute, "hace 1 minuto"}, {2 * time.Minute, "hace 2 minutos"},
		{time.Hour, "hace 1 hora"}, {2 * time.Hour, "hace 2 horas"},
		{24 * time.Hour, "hace 1 día"}, {48 * time.Hour, "hace 2 días"},
	} {
		then := instant.Add(-tc.age)
		assert.Equal(t, tc.want, formatSince(ctx, &then, instant))
	}
}
