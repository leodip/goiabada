package accounthandlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
	mocks_handler_helpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
)

// The value on constants.ContextKeySettings is api.PublicSettingsResponse, the same four-field
// wire type the console decoded from /api/public/settings, rather than a models.Settings the
// settings-cache middleware filled four fields of and left the other 28 at their zero values
// (#350).
//
// Nothing about that is visible at compile time from here: the key is a context key, so its value
// is an interface, and every reader of it is a type assertion that either matches what the
// middleware wrote or panics on a live request. These cases are what holds the two ends together.
// Put the carrier back to a persistence model on either side alone and the handlers below panic,
// which is exactly what a visitor would meet.
//
// Each handler is driven with the flag both ways, so a handler that stopped reading the carrier and
// bound a constant fails too.

// settingsCarrierApiClient answers the one call these pages make before they read the settings.
type settingsCarrierApiClient struct {
	apiclient.ApiClient
}

func (settingsCarrierApiClient) GetAccountProfile(string) (*api.UserResponse, error) {
	return &api.UserResponse{Id: 11, Email: "someone@example.com", EmailVerified: true}, nil
}

// publicSettings is what the settings-cache middleware puts on the context in production.
func publicSettings(smtpEnabled bool) *api.PublicSettingsResponse {
	return &api.PublicSettingsResponse{
		AppName:     "Goiabada",
		UITheme:     "dark",
		SMTPEnabled: smtpEnabled,
		Issuer:      "https://issuer.example",
	}
}

func TestHandleAccountEmailGet_BindsSMTPEnabledFromTheSettingsCarrier(t *testing.T) {
	for _, smtpEnabled := range []bool{true, false} {
		t.Run(map[bool]string{true: "smtp enabled", false: "smtp disabled"}[smtpEnabled], func(t *testing.T) {
			httpHelper := mocks_handler_helpers.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/account_email.html").Once()

			req := handlertest.Request(http.MethodGet, "/account/email",
				handlertest.WithAccessToken(),
				handlertest.WithSettings(publicSettings(smtpEnabled)))

			HandleAccountEmailGet(httpHelper, newFlashTestStore(), settingsCarrierApiClient{}).
				ServeHTTP(httptest.NewRecorder(), req)

			assert.Equal(t, smtpEnabled, handlertest.Bind(t, httpHelper)["smtpEnabled"],
				"the page's smtpEnabled comes from the carrier the middleware wrote")
		})
	}
}

func TestHandleAccountEmailVerificationGet_BindsSMTPEnabledFromTheSettingsCarrier(t *testing.T) {
	httpHelper := mocks_handler_helpers.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper,
		"/layouts/menu_layout.html", "/account_email_verification.html").Once()

	req := handlertest.Request(http.MethodGet, "/account/email-verification",
		handlertest.WithAccessToken(),
		handlertest.WithSettings(publicSettings(true)))

	HandleAccountEmailVerificationGet(httpHelper, newFlashTestStore(), settingsCarrierApiClient{}).
		ServeHTTP(httptest.NewRecorder(), req)

	assert.Equal(t, true, handlertest.Bind(t, httpHelper)["smtpEnabled"])
}

// The other arm of the same read: this page refuses outright when the auth server reports SMTP off,
// because there is nothing to send a verification with. Without this row the case above is
// satisfied by a handler that read the carrier once and ignored what it said.
func TestHandleAccountEmailVerificationGet_RefusesWhenTheCarrierReportsSMTPOff(t *testing.T) {
	httpHelper := mocks_handler_helpers.NewHttpHelper(t)
	var refusedWith error
	httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { refusedWith, _ = args.Get(2).(error) }).Once()

	req := handlertest.Request(http.MethodGet, "/account/email-verification",
		handlertest.WithAccessToken(),
		handlertest.WithSettings(publicSettings(false)))

	HandleAccountEmailVerificationGet(httpHelper, newFlashTestStore(), settingsCarrierApiClient{}).
		ServeHTTP(httptest.NewRecorder(), req)

	require.Error(t, refusedWith, "the page must refuse rather than render a form it cannot send from")
	assert.Contains(t, refusedWith.Error(), "SMTP")
}
