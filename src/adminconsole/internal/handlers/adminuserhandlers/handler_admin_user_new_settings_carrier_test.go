package adminuserhandlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
)

// The new-user page is this package's only reader of the settings reqctx carries, and that value is
// api.PublicSettingsResponse rather than a record.Settings the settings-cache middleware filled four
// fields of (#350). The type is held at compile time by reqctx's typed accessors since #440; what
// this case still holds is that the page reads the value the middleware wrote rather than one of
// its own.
//
// Both values of the flag, because the page draws a different password control for each and a
// handler that stopped reading the carrier would otherwise pass on one of them.
func TestHandleNewGet_BindsSMTPEnabledFromTheSettingsCarrier(t *testing.T) {
	for _, smtpEnabled := range []bool{true, false} {
		t.Run(map[bool]string{true: "smtp enabled", false: "smtp disabled"}[smtpEnabled], func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_users_new.html").Once()

			req := handlertest.Request(http.MethodGet, "/admin/users/new",
				handlertest.WithSettings(&api.PublicSettingsResponse{
					AppName:     "Goiabada",
					UITheme:     "dark",
					SMTPEnabled: smtpEnabled,
					Issuer:      "https://issuer.example",
				}))

			HandleNewGet(httpHelper).ServeHTTP(httptest.NewRecorder(), req)

			assert.Equal(t, smtpEnabled, handlertest.Bind(t, httpHelper)["smtpEnabled"],
				"the page's smtpEnabled comes from the carrier the middleware wrote")
		})
	}
}
