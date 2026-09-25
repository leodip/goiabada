package accounthandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	mocks_handlerhelpers "github.com/leodip/goiabada/adminconsole/internal/handlerhelpers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
)

// Seam 4 for the account pages (#386).
//
// It owns one thing: every handler here consults its API client with the request's own context,
// and answers when the client refuses. It cannot own more -- the executor's table lives in
// apiclient and the wire shapes in wire_characterization_table_test.go -- and repeating either
// here would break on every refactor while proving nothing.
//
// The context matters because nothing else can see it. The compiler accepts context.Background()
// where r.Context() belongs, so a handler that stopped carrying the request's cancellation would
// compile, pass every other test, and quietly hold a goroutine open against an auth server that
// had stopped answering. The marker below is the whole assertion.

type ctxMarkerKey struct{}

// ctxRecordingApiClient records the context every stage-10 method is called with and then refuses,
// so the handler takes its error path in the same pass. It embeds ApiClient, so a method a handler
// calls that is not stubbed here panics on a nil interface rather than passing silently.
type ctxRecordingApiClient struct {
	apiclient.ApiClient
	seen []context.Context
}

func (s *ctxRecordingApiClient) record(ctx context.Context) error {
	s.seen = append(s.seen, ctx)
	return errs.New("the auth server refused")
}

func (s *ctxRecordingApiClient) GetAccountProfile(ctx context.Context, _ string) (*api.UserResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) UpdateAccountProfile(ctx context.Context, _ string, _ *api.UpdateUserProfileRequest) (*api.UserResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) UpdateAccountEmail(ctx context.Context, _ string, _ *api.UpdateAccountEmailRequest) (*api.UserResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) UpdateAccountPhone(ctx context.Context, _ string, _ *api.UpdateAccountPhoneRequest) (*api.UserResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) UpdateAccountAddress(ctx context.Context, _ string, _ *api.UpdateUserAddressRequest) (*api.UserResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) UpdateAccountPassword(ctx context.Context, _ string, _ *api.UpdateAccountPasswordRequest) (*api.UserResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) SendAccountEmailVerification(ctx context.Context, _ string) (*api.AccountEmailVerificationSendResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) VerifyAccountEmail(ctx context.Context, _ string, _ *api.VerifyAccountEmailRequest) (*api.UserResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) GetAccountOTPEnrollment(ctx context.Context, _ string) (*api.AccountOTPEnrollmentResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) UpdateAccountOTP(ctx context.Context, _ string, _ *api.UpdateAccountOTPRequest) (*api.UserResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) CreateAccountLogoutRequest(ctx context.Context, _ string, _ *api.AccountLogoutRequest) (*api.AccountLogoutFormPostResponse, *api.AccountLogoutRedirectResponse, error) {
	return nil, nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) GetAccountConsents(ctx context.Context, _ string) ([]api.UserConsentResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) RevokeAccountConsent(ctx context.Context, _ string, _ int64) error {
	return s.record(ctx)
}

func (s *ctxRecordingApiClient) GetAccountProfilePicture(ctx context.Context, _ string) (*apiclient.ProfilePictureInfo, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) UploadAccountProfilePicture(ctx context.Context, _ string, _ []byte, _ string) (*apiclient.ProfilePictureUploadResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) DeleteAccountProfilePicture(ctx context.Context, _ string) error {
	return s.record(ctx)
}

func (s *ctxRecordingApiClient) GetPhoneCountries(ctx context.Context, _ string) ([]api.PhoneCountryResponse, error) {
	return nil, s.record(ctx)
}

// The two session methods are stage 11's. GetAccountSessions records and succeeds rather than
// refusing, because the delete below it is reached only through the list it answers.
func (s *ctxRecordingApiClient) GetAccountSessions(ctx context.Context, _ string) ([]api.UserSessionDetailResponse, error) {
	s.seen = append(s.seen, ctx)
	return []api.UserSessionDetailResponse{{Id: 31}}, nil
}

func (s *ctxRecordingApiClient) DeleteAccountSession(ctx context.Context, _ string, _ int64) error {
	return s.record(ctx)
}

func TestAccountHandlers_EveryHandlerConsultsTheApiClientWithTheRequestsContext(t *testing.T) {
	testCases := []struct {
		name    string
		build   func(httpHelper *mocks_handlerhelpers.HttpHelper, apiClient apiclient.ApiClient) http.HandlerFunc
		request *http.Request
	}{
		{
			name: "HandleAccountAddressGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAccountAddressGet(h, nil, c)
			},
			request: handlertest.Request(http.MethodGet, "/account/address", handlertest.WithAccessToken()),
		},
		{
			name: "HandleAccountAddressPost",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAccountAddressPost(h, nil, c)
			},
			request: handlertest.Request(http.MethodPost, "/account/address",
				handlertest.WithAccessToken(), handlertest.WithForm(url.Values{})),
		},
		{
			name: "HandleAccountChangePasswordPost",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAccountChangePasswordPost(h, nil, c)
			},
			request: handlertest.Request(http.MethodPost, "/account/change-password",
				handlertest.WithAccessToken(), handlertest.WithForm(url.Values{
					"currentPassword":         {"P4ss!word"},
					"newPassword":             {"N3w!P4ssword"},
					"newPasswordConfirmation": {"N3w!P4ssword"},
				})),
		},
		{
			name: "HandleAccountEmailGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAccountEmailGet(h, nil, c)
			},
			request: handlertest.Request(http.MethodGet, "/account/email", handlertest.WithAccessToken()),
		},
		{
			name: "HandleAccountEmailPost",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAccountEmailPost(h, nil, c)
			},
			request: handlertest.Request(http.MethodPost, "/account/email",
				handlertest.WithAccessToken(), handlertest.WithForm(url.Values{"email": {"jane@example.com"}})),
		},
		{
			name: "HandleAccountEmailSendVerificationPost",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAccountEmailSendVerificationPost(h, c)
			},
			request: handlertest.Request(http.MethodPost, "/account/email/send-verification",
				handlertest.WithAccessToken()),
		},
		{
			name: "HandleAccountEmailVerificationGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAccountEmailVerificationGet(h, nil, c)
			},
			request: handlertest.Request(http.MethodGet, "/account/email/verification",
				handlertest.WithAccessToken()),
		},
		{
			name: "HandleAccountEmailVerificationPost",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAccountEmailVerificationPost(h, nil, c)
			},
			request: handlertest.Request(http.MethodPost, "/account/email/verification",
				handlertest.WithAccessToken(), handlertest.WithForm(url.Values{"verificationCode": {"123456"}})),
		},
		{
			name: "HandleAccountLogoutGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				// The one row needing a real store: this handler clears the console's own
				// session before it asks the auth server to end the upstream one.
				return HandleAccountLogoutGet(h, newFlashTestStore(), c)
			},
			// The logout page reads the verified ID token beside the bearer string, and takes its
			// unauthenticated arm without both of them.
			request: handlertest.Request(http.MethodGet, "/account/logout",
				handlertest.WithJwtInfo(oauthclient.JwtInfo{
					TokenResponse: oauth.TokenResponse{AccessToken: handlertest.AccessToken},
					IdToken:       &oauth.JwtToken{TokenBase64: "the.id.token"},
				})),
		},
		{
			name: "HandleAccountManageConsentsGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAccountManageConsentsGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/account/manage-consents",
				handlertest.WithAccessToken()),
		},
		{
			name: "HandleAccountManageConsentsRevokePost",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAccountManageConsentsRevokePost(h, c)
			},
			request: handlertest.Request(http.MethodPost, "/account/manage-consents/revoke",
				handlertest.WithAccessToken(), handlertest.WithBody(strings.NewReader(`{"consentId":13}`)),
				handlertest.WithContentType("application/json")),
		},
		{
			name: "HandleAccountOtpGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAccountOtpGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/account/otp", handlertest.WithAccessToken()),
		},
		{
			name: "HandleAccountOtpPost",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAccountOtpPost(h, c)
			},
			request: handlertest.Request(http.MethodPost, "/account/otp",
				handlertest.WithAccessToken(), handlertest.WithForm(url.Values{
					"password": {"P4ss!word"}, "otp": {"123456"},
				})),
		},
		{
			name: "HandleAccountPhoneGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAccountPhoneGet(h, nil, c)
			},
			request: handlertest.Request(http.MethodGet, "/account/phone", handlertest.WithAccessToken()),
		},
		{
			name: "HandleAccountPhonePost",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAccountPhonePost(h, nil, c)
			},
			request: handlertest.Request(http.MethodPost, "/account/phone",
				handlertest.WithAccessToken(), handlertest.WithForm(url.Values{})),
		},
		{
			name: "HandleAccountPictureGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAccountPictureGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/account/picture", handlertest.WithAccessToken()),
		},
		{
			name: "HandleAccountProfileGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAccountProfileGet(h, nil, c)
			},
			request: handlertest.Request(http.MethodGet, "/account/profile", handlertest.WithAccessToken()),
		},
		{
			name: "HandleAccountProfilePost",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAccountProfilePost(h, nil, c)
			},
			request: handlertest.Request(http.MethodPost, "/account/profile",
				handlertest.WithAccessToken(), handlertest.WithForm(url.Values{})),
		},
		{
			name: "HandleAccountSessionsGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAccountSessionsGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/account/sessions", handlertest.WithAccessToken()),
		},
		{
			name: "HandleAccountSessionsEndSesssionPost",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAccountSessionsEndSesssionPost(h, c)
			},
			request: handlertest.Request(http.MethodPost, "/account/sessions",
				handlertest.WithAccessToken(),
				handlertest.WithBody(strings.NewReader(`{"userSessionId":31}`)),
				handlertest.WithContentType("application/json")),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
			// Every writer is admitted: which one a handler picks is pattern 7's decision and is
			// held by TestHandlers_AjaxHandlersDoNotUsePageWriters and the classifier guard, not
			// here. What this case needs is only that the handler answered rather than carrying on.
			httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Maybe()
			httpHelper.On("JsonError", mock.Anything, mock.Anything, mock.Anything).Maybe()
			httpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.Anything).Maybe()
			httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, mock.Anything,
				mock.Anything, mock.Anything).Return(nil).Maybe()

			apiClient := &ctxRecordingApiClient{}

			marked := tc.request.WithContext(
				context.WithValue(tc.request.Context(), ctxMarkerKey{}, tc.name))

			tc.build(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), marked)

			require.NotEmpty(t, apiClient.seen, "the handler must consult its API client")
			for i, seen := range apiClient.seen {
				assert.Equal(t, tc.name, seen.Value(ctxMarkerKey{}),
					"call %d carried a context that is not the request's", i)
			}
		})
	}
}

// The two picture handlers are built apart: one needs a multipart submission to reach its upload
// and the other is the only DELETE here.
func TestAccountHandlers_ThePictureHandlersCarryTheRequestsContext(t *testing.T) {
	t.Run("HandleAccountProfilePictureDelete", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpHelper.On("JsonError", mock.Anything, mock.Anything, mock.Anything).Maybe()
		httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Maybe()
		httpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.Anything).Maybe()

		apiClient := &ctxRecordingApiClient{}
		request := handlertest.Request(http.MethodDelete, "/account/profile-picture",
			handlertest.WithAccessToken())
		marked := request.WithContext(context.WithValue(request.Context(), ctxMarkerKey{}, "delete"))

		HandleAccountProfilePictureDelete(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), marked)

		require.Len(t, apiClient.seen, 1)
		assert.Equal(t, "delete", apiClient.seen[0].Value(ctxMarkerKey{}))
	})
}
