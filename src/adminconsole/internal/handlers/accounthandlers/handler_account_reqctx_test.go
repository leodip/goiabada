package accounthandlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
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
		build   func(httpHelper *handlersmocks.HttpHelper, apiClient *ctxRecordingApiClient) http.HandlerFunc
		request *http.Request
	}{
		{"HandleAddressGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAddressGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/account/address")},
		{"HandleAddressPost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleAddressPost(h, nil, c, consoleBaseURL)
		}, handlertest.Request(http.MethodPost, "/account/address", handlertest.WithForm(url.Values{}))},
		{"HandleChangePasswordPost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleChangePasswordPost(h, nil, c, consoleBaseURL)
		}, handlertest.Request(http.MethodPost, "/account/change-password", handlertest.WithForm(url.Values{
			"currentPassword":         {"P4ss!word"},
			"newPassword":             {"N3w!P4ssword"},
			"newPasswordConfirmation": {"N3w!P4ssword"},
		}))},
		{"HandleEmailGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleEmailGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/account/email")},
		{"HandleEmailPost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleEmailPost(h, nil, c, consoleBaseURL)
		}, handlertest.Request(http.MethodPost, "/account/email",
			handlertest.WithForm(url.Values{"email": {"jane@example.com"}}))},
		{"HandleEmailSendVerificationPost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleEmailSendVerificationPost(h, c)
		}, handlertest.Request(http.MethodPost, "/account/email-send-verification")},
		{"HandleEmailVerificationGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleEmailVerificationGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/account/email-verification")},
		{"HandleEmailVerificationPost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleEmailVerificationPost(h, nil, c, consoleBaseURL)
		}, handlertest.Request(http.MethodPost, "/account/email-verification",
			handlertest.WithForm(url.Values{"verificationCode": {"123456"}}))},
		{"HandleManageConsentsGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleManageConsentsGet(h, c)
		}, handlertest.Request(http.MethodGet, "/account/manage-consents")},
		{"HandleManageConsentsRevokePost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleManageConsentsRevokePost(h, c)
		}, handlertest.Request(http.MethodPost, "/account/manage-consents",
			handlertest.WithBody(strings.NewReader(`{"consentId":13}`)), handlertest.WithContentType("application/json"))},
		{"HandleOtpGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleOtpGet(h, c)
		}, handlertest.Request(http.MethodGet, "/account/otp")},
		{"HandleOtpPost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleOtpPost(h, c, consoleBaseURL)
		}, handlertest.Request(http.MethodPost, "/account/otp", handlertest.WithForm(url.Values{
			"password": {"P4ss!word"}, "otp": {"123456"},
		}))},
		{"HandlePhoneGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandlePhoneGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/account/phone")},
		{"HandlePhonePost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandlePhonePost(h, nil, c, consoleBaseURL)
		}, handlertest.Request(http.MethodPost, "/account/phone", handlertest.WithForm(url.Values{}))},
		{"HandlePictureGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandlePictureGet(h, c)
		}, handlertest.Request(http.MethodGet, "/account/picture")},
		{"HandleProfilePicturePost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleProfilePicturePost(h, c)
		}, handlertest.Request(http.MethodPost, "/account/picture")},
		{"HandleProfilePictureDelete", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleProfilePictureDelete(h, c)
		}, handlertest.Request(http.MethodDelete, "/account/picture")},
		{"HandleProfileGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleProfileGet(h, nil, c)
		}, handlertest.Request(http.MethodGet, "/account/profile")},
		{"HandleProfilePost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleProfilePost(h, nil, c, consoleBaseURL)
		}, handlertest.Request(http.MethodPost, "/account/profile", handlertest.WithForm(url.Values{}))},
		{"HandleSessionsGet", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleSessionsGet(h, c)
		}, handlertest.Request(http.MethodGet, "/account/sessions")},
		{"HandleSessionsEndSessionPost", func(h *handlersmocks.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
			return HandleSessionsEndSessionPost(h, c)
		}, handlertest.Request(http.MethodPost, "/account/sessions",
			handlertest.WithBody(strings.NewReader(`{"userSessionId":31}`)), handlertest.WithContentType("application/json"))},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			var answered []error
			record := func(args mock.Arguments) { answered = append(answered, args.Get(2).(error)) }
			httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Run(record).Maybe()
			httpHelper.On("JSONError", mock.Anything, mock.Anything, mock.Anything).Run(record).Maybe()

			apiClient := &ctxRecordingApiClient{}
			tc.build(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), tc.request)

			require.Len(t, answered, 1, "the handler answers once")
			require.ErrorIs(t, answered[0], reqctx.ErrNoJwtInfo, "answered with %v", answered[0])
			assert.Empty(t, apiClient.seen, "nothing is asked of the API without a token")
		})
	}
}
