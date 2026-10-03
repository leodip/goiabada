package accounthandlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	mocks_handlers "github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
)

// The settings value reqctx carries is api.PublicSettingsResponse, the same four-field
// wire type the console decoded from /api/public/settings, rather than a record.Settings the
// settings-cache middleware filled four fields of and left the other 28 at their zero values
// (#350).
//
// The type is held at compile time by reqctx's typed accessors since #440; what these cases still
// hold is that the page reads the value the middleware wrote rather than one of its own.
//
// Each handler is driven with the flag both ways, so a handler that stopped reading the carrier and
// bound a constant fails too.

// settingsCarrierApiClient answers the one call these pages make before they read the settings.
type settingsCarrierApiClient struct {
}

func (settingsCarrierApiClient) GetAccountProfile(context.Context, string) (*api.UserResponse, error) {
	return &api.UserResponse{Id: 11, Email: "someone@example.com", EmailVerified: true}, nil
}

// The rest of the ports settingsCarrierApiClient is passed to, which no test here reaches.

func (settingsCarrierApiClient) SendAccountEmailVerification(context.Context, string) (*api.AccountEmailVerificationSendResponse, error) {
	panic("unexpected call to SendAccountEmailVerification")
}

func (settingsCarrierApiClient) UpdateAccountEmail(context.Context, string, *api.UpdateAccountEmailRequest) (*api.UserResponse, error) {
	panic("unexpected call to UpdateAccountEmail")
}

func (settingsCarrierApiClient) VerifyAccountEmail(context.Context, string, *api.VerifyAccountEmailRequest) (*api.UserResponse, error) {
	panic("unexpected call to VerifyAccountEmail")
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

func TestHandleEmailGet_BindsSMTPEnabledFromTheSettingsCarrier(t *testing.T) {
	for _, smtpEnabled := range []bool{true, false} {
		t.Run(map[bool]string{true: "smtp enabled", false: "smtp disabled"}[smtpEnabled], func(t *testing.T) {
			httpHelper := mocks_handlers.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/account_email.html").Once()

			req := handlertest.Request(http.MethodGet, "/account/email",
				handlertest.WithAccessToken(),
				handlertest.WithSettings(publicSettings(smtpEnabled)))

			HandleEmailGet(httpHelper, newFlashTestStore(), settingsCarrierApiClient{}).
				ServeHTTP(httptest.NewRecorder(), req)

			assert.Equal(t, smtpEnabled, handlertest.Bind(t, httpHelper)["smtpEnabled"],
				"the page's smtpEnabled comes from the carrier the middleware wrote")
		})
	}
}

func TestHandleEmailVerificationGet_BindsSMTPEnabledFromTheSettingsCarrier(t *testing.T) {
	httpHelper := mocks_handlers.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper,
		"/layouts/menu_layout.html", "/account_email_verification.html").Once()

	req := handlertest.Request(http.MethodGet, "/account/email-verification",
		handlertest.WithAccessToken(),
		handlertest.WithSettings(publicSettings(true)))

	HandleEmailVerificationGet(httpHelper, newFlashTestStore(), settingsCarrierApiClient{}).
		ServeHTTP(httptest.NewRecorder(), req)

	assert.Equal(t, true, handlertest.Bind(t, httpHelper)["smtpEnabled"])
}

// The other arm of the same read: this page refuses outright when the auth server reports SMTP off,
// because there is nothing to send a verification with. Without this row the case above is
// satisfied by a handler that read the carrier once and ignored what it said.
func TestHandleEmailVerificationGet_RefusesWhenTheCarrierReportsSMTPOff(t *testing.T) {
	httpHelper := mocks_handlers.NewHttpHelper(t)
	var refusedWith error
	httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { refusedWith, _ = args.Get(2).(error) }).Once()

	req := handlertest.Request(http.MethodGet, "/account/email-verification",
		handlertest.WithAccessToken(),
		handlertest.WithSettings(publicSettings(false)))

	HandleEmailVerificationGet(httpHelper, newFlashTestStore(), settingsCarrierApiClient{}).
		ServeHTTP(httptest.NewRecorder(), req)

	require.Error(t, refusedWith, "the page must refuse rather than render a form it cannot send from")
	assert.Contains(t, refusedWith.Error(), "SMTP")
}

// verificationRefusingApiClient answers the profile the verification page reads first, then
// refuses the code with err.
type verificationRefusingApiClient struct {
	settingsCarrierApiClient
	err error
}

func (c verificationRefusingApiClient) VerifyAccountEmail(context.Context, string, *api.VerifyAccountEmailRequest) (*api.UserResponse, error) {
	return nil, c.err
}

// The rest of the ports verificationRefusingApiClient is passed to, which no test here reaches.

func (verificationRefusingApiClient) SendAccountEmailVerification(context.Context, string) (*api.AccountEmailVerificationSendResponse, error) {
	panic("unexpected call to SendAccountEmailVerification")
}

// A page that reads the settings and finds none answers the sentinel reqctx declares instead of
// the panic a type assertion on a nil interface was: every application route is mounted under the
// settings middleware, so only a wiring defect reaches these, and the 500 page with a request id
// is what one is answered with (#440).
func TestAccountEmailPages_AbsentSettingsAreAnsweredWithTheSentinel(t *testing.T) {
	verificationForm := handlertest.WithForm(url.Values{"verificationCode": {"123456"}})
	testCases := []struct {
		name    string
		build   func(httpHelper *mocks_handlers.HttpHelper) http.HandlerFunc
		request *http.Request
	}{
		{
			name: "HandleEmailGet",
			build: func(h *mocks_handlers.HttpHelper) http.HandlerFunc {
				return HandleEmailGet(h, newFlashTestStore(), settingsCarrierApiClient{})
			},
			request: handlertest.Request(http.MethodGet, "/account/email", handlertest.WithAccessToken()),
		},
		{
			name: "HandleEmailVerificationGet",
			build: func(h *mocks_handlers.HttpHelper) http.HandlerFunc {
				return HandleEmailVerificationGet(h, newFlashTestStore(), settingsCarrierApiClient{})
			},
			request: handlertest.Request(http.MethodGet, "/account/email-verification", handlertest.WithAccessToken()),
		},
		{
			name: "HandleEmailVerificationPost, a code the API calls expired",
			build: func(h *mocks_handlers.HttpHelper) http.HandlerFunc {
				return HandleEmailVerificationPost(h, newFlashTestStore(), verificationRefusingApiClient{
					err: &apiclient.APIError{Code: "INVALID_OR_EXPIRED_VERIFICATION_CODE", Message: "Expired.", StatusCode: http.StatusBadRequest},
				}, consoleBaseURL)
			},
			request: handlertest.Request(http.MethodPost, "/account/email-verification",
				handlertest.WithAccessToken(), verificationForm),
		},
		{
			name: "HandleEmailVerificationPost, any other refusal",
			build: func(h *mocks_handlers.HttpHelper) http.HandlerFunc {
				return HandleEmailVerificationPost(h, newFlashTestStore(), verificationRefusingApiClient{
					err: &apiclient.APIError{Code: "SOMETHING_ELSE", Message: "No.", StatusCode: http.StatusBadRequest},
				}, consoleBaseURL)
			},
			request: handlertest.Request(http.MethodPost, "/account/email-verification",
				handlertest.WithAccessToken(), verificationForm),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := mocks_handlers.NewHttpHelper(t)
			var refusedWith error
			httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).
				Run(func(args mock.Arguments) { refusedWith, _ = args.Get(2).(error) }).Once()

			tc.build(httpHelper).ServeHTTP(httptest.NewRecorder(), tc.request)

			assert.True(t, errors.Is(refusedWith, reqctx.ErrNoSettings), "answered with %v", refusedWith)
			httpHelper.AssertNotCalled(t, "RenderTemplate", mock.Anything, mock.Anything, mock.Anything,
				mock.Anything, mock.Anything)
		})
	}
}
