package adminuserhandlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	mocks_handlerhelpers "github.com/leodip/goiabada/adminconsole/internal/handlerhelpers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
)

// The new-user page is this package's only reader of constants.ContextKeySettings, and the value on
// that key is api.PublicSettingsResponse rather than a models.Settings the settings-cache middleware
// filled four fields of (#350). The key is a context key, so the type is an interface at every
// reader and the match between what the middleware writes and what a handler asserts is checked
// nowhere at compile time. This is what checks it: move either end alone and the handler panics on
// a live request.
//
// Both values of the flag, because the page draws a different password control for each and a
// handler that stopped reading the carrier would otherwise pass on one of them.
func TestHandleAdminUserNewGet_BindsSMTPEnabledFromTheSettingsCarrier(t *testing.T) {
	for _, smtpEnabled := range []bool{true, false} {
		t.Run(map[bool]string{true: "smtp enabled", false: "smtp disabled"}[smtpEnabled], func(t *testing.T) {
			httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_users_new.html").Once()

			req := handlertest.Request(http.MethodGet, "/admin/users/new",
				handlertest.WithSettings(&api.PublicSettingsResponse{
					AppName:     "Goiabada",
					UITheme:     "dark",
					SMTPEnabled: smtpEnabled,
					Issuer:      "https://issuer.example",
				}))

			HandleAdminUserNewGet(httpHelper).ServeHTTP(httptest.NewRecorder(), req)

			assert.Equal(t, smtpEnabled, handlertest.Bind(t, httpHelper)["smtpEnabled"],
				"the page's smtpEnabled comes from the carrier the middleware wrote")
		})
	}
}
