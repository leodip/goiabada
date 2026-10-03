package accounthandlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	mocks_handlers "github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
)

// A request reaching an account page with no token set on its context is a wiring defect: every
// one of these routes is mounted under RequiresScope. Each handler answers it with the one
// sentinel reqctx declares, through whichever writer its route answers with, and consults the API
// with nothing (#440). The logout page is not here: an absent token set is its unauthenticated arm.
// Neither is the change-password page's GET, which reads no token.
func TestAccountHandlers_AnAbsentTokenSetIsAnsweredWithTheSentinel(t *testing.T) {
	testCases := []struct {
		name    string
		build   func(httpHelper *mocks_handlers.HttpHelper, apiClient *ctxRecordingApiClient) http.HandlerFunc
		request *http.Request
	}{
		{"HandleAccountAddressGet", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAccountAddressGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/account/address")},
		{"HandleAccountAddressPost", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAccountAddressPost(h, nil, c, consoleBaseURL)
		}, handlertest.Request(http.MethodPost, "/account/address", handlertest.WithForm(url.Values{}))},
		{"HandleAccountChangePasswordPost", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAccountChangePasswordPost(h, nil, c, consoleBaseURL)
		}, handlertest.Request(http.MethodPost, "/account/change-password", handlertest.WithForm(url.Values{
			"currentPassword":         {"P4ss!word"},
			"newPassword":             {"N3w!P4ssword"},
			"newPasswordConfirmation": {"N3w!P4ssword"},
		}))},
		{"HandleAccountEmailGet", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAccountEmailGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/account/email")},
		{"HandleAccountEmailPost", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAccountEmailPost(h, nil, c, consoleBaseURL)
		}, handlertest.Request(http.MethodPost, "/account/email",
			handlertest.WithForm(url.Values{"email": {"jane@example.com"}}))},
		{"HandleAccountEmailSendVerificationPost", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAccountEmailSendVerificationPost(h, c)
		}, handlertest.Request(http.MethodPost, "/account/email-send-verification")},
		{"HandleAccountEmailVerificationGet", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAccountEmailVerificationGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/account/email-verification")},
		{"HandleAccountEmailVerificationPost", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAccountEmailVerificationPost(h, nil, c, consoleBaseURL)
		}, handlertest.Request(http.MethodPost, "/account/email-verification",
			handlertest.WithForm(url.Values{"verificationCode": {"123456"}}))},
		{"HandleAccountManageConsentsGet", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAccountManageConsentsGet(h, c)
		}, handlertest.Request(http.MethodGet, "/account/manage-consents")},
		{"HandleAccountManageConsentsRevokePost", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAccountManageConsentsRevokePost(h, c)
		}, handlertest.Request(http.MethodPost, "/account/manage-consents",
			handlertest.WithBody(strings.NewReader(`{"consentId":13}`)), handlertest.WithContentType("application/json"))},
		{"HandleAccountOtpGet", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAccountOtpGet(h, c)
		}, handlertest.Request(http.MethodGet, "/account/otp")},
		{"HandleAccountOtpPost", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAccountOtpPost(h, c, consoleBaseURL)
		}, handlertest.Request(http.MethodPost, "/account/otp", handlertest.WithForm(url.Values{
			"password": {"P4ss!word"}, "otp": {"123456"},
		}))},
		{"HandleAccountPhoneGet", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAccountPhoneGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/account/phone")},
		{"HandleAccountPhonePost", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAccountPhonePost(h, nil, c, consoleBaseURL)
		}, handlertest.Request(http.MethodPost, "/account/phone", handlertest.WithForm(url.Values{}))},
		{"HandleAccountPictureGet", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAccountPictureGet(h, c)
		}, handlertest.Request(http.MethodGet, "/account/picture")},
		{"HandleAccountProfilePicturePost", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAccountProfilePicturePost(h, c)
		}, handlertest.Request(http.MethodPost, "/account/picture")},
		{"HandleAccountProfilePictureDelete", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAccountProfilePictureDelete(h, c)
		}, handlertest.Request(http.MethodDelete, "/account/picture")},
		{"HandleAccountProfileGet", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAccountProfileGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/account/profile")},
		{"HandleAccountProfilePost", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAccountProfilePost(h, nil, c, consoleBaseURL)
		}, handlertest.Request(http.MethodPost, "/account/profile", handlertest.WithForm(url.Values{}))},
		{"HandleAccountSessionsGet", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAccountSessionsGet(h, c)
		}, handlertest.Request(http.MethodGet, "/account/sessions")},
		{"HandleAccountSessionsEndSessionPost", func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAccountSessionsEndSessionPost(h, c)
		}, handlertest.Request(http.MethodPost, "/account/sessions",
			handlertest.WithBody(strings.NewReader(`{"userSessionId":31}`)), handlertest.WithContentType("application/json"))},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := mocks_handlers.NewHttpHelper(t)
			var answered []error
			record := func(args mock.Arguments) { answered = append(answered, args.Get(2).(error)) }
			httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Run(record).Maybe()
			httpHelper.On("JsonError", mock.Anything, mock.Anything, mock.Anything).Run(record).Maybe()

			apiClient := &ctxRecordingApiClient{}
			tc.build(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), tc.request)

			require.Len(t, answered, 1, "the handler answers once")
			assert.True(t, errors.Is(answered[0], reqctx.ErrNoJwtInfo), "answered with %v", answered[0])
			assert.Empty(t, apiClient.seen, "nothing is asked of the API without a token")
		})
	}
}
