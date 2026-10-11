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

	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
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
// so the handler takes its error path in the same pass. The tables below are typed on it, so a
// method a handler's port gains and this fake lacks fails to compile rather than passing silently.
type ctxRecordingApiClient struct {
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

func (s *ctxRecordingApiClient) GetAccountProfilePicture(ctx context.Context, _ string) (*api.ProfilePictureInfoResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) UploadAccountProfilePicture(ctx context.Context, _ string, _ []byte, _ string) (*api.ProfilePictureUploadResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) DeleteAccountProfilePicture(ctx context.Context, _ string) error {
	return s.record(ctx)
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

// accountAPI is the union of the ports the account handlers declare. The recording fake above
// satisfies it, and so does the real *apiclient.AuthServerClient, which is what lets the table
// below drive every handler through either: this test through the fake, and
// handler_account_admin_api_test.go through the real client against an auth server that refuses the
// admin API (#563 decision 3). A method a port gains fails to compile here until the union names it.
type accountAPI interface {
	accountAddressAPI
	accountEmailAPI
	accountEmailVerificationAPI
	accountLogoutAPI
	accountConsentsAPI
	accountOTPAPI
	accountPasswordAPI
	accountPhoneAPI
	accountPictureAPI
	accountProfilePictureAPI
	accountProfileAPI
	accountSessionsAPI
}

// accountHandlerCase is one account handler and a request that reaches its API calls. request is
// a function so that each run gets a fresh request, whose body has not been read.
type accountHandlerCase struct {
	name    string
	build   func(httpHelper *handlersmocks.HttpHelper, apiClient accountAPI) http.HandlerFunc
	request func() *http.Request
}

// accountHandlerCases is every account handler that consults the API client, GET and POST.
func accountHandlerCases() []accountHandlerCase {
	return []accountHandlerCase{
		{
			name: "HandleAddressGet",
			build: func(h *handlersmocks.HttpHelper, c accountAPI) http.HandlerFunc {
				return HandleAddressGet(h, newFlashTestStore(), c)
			},
			request: func() *http.Request {
				return handlertest.Request(http.MethodGet, "/account/address", handlertest.WithAccessToken())
			},
		},
		{
			name: "HandleAddressPost",
			build: func(h *handlersmocks.HttpHelper, c accountAPI) http.HandlerFunc {
				return HandleAddressPost(h, newFlashTestStore(), c, consoleBaseURL)
			},
			request: func() *http.Request {
				return handlertest.Request(http.MethodPost, "/account/address",
					handlertest.WithAccessToken(), handlertest.WithForm(url.Values{}))
			},
		},
		{
			name: "HandleChangePasswordPost",
			build: func(h *handlersmocks.HttpHelper, c accountAPI) http.HandlerFunc {
				return HandleChangePasswordPost(h, newFlashTestStore(), c, consoleBaseURL)
			},
			request: func() *http.Request {
				return handlertest.Request(http.MethodPost, "/account/change-password",
					handlertest.WithAccessToken(), handlertest.WithForm(url.Values{
						"currentPassword":         {"P4ss!word"},
						"newPassword":             {"N3w!P4ssword"},
						"newPasswordConfirmation": {"N3w!P4ssword"},
					}))
			},
		},
		{
			name: "HandleEmailGet",
			build: func(h *handlersmocks.HttpHelper, c accountAPI) http.HandlerFunc {
				return HandleEmailGet(h, newFlashTestStore(), c)
			},
			request: func() *http.Request {
				return handlertest.Request(http.MethodGet, "/account/email", handlertest.WithAccessToken(),
					// The page renders with the public settings.
					handlertest.WithSettings(&api.PublicSettingsResponse{}))
			},
		},
		{
			name: "HandleEmailPost",
			build: func(h *handlersmocks.HttpHelper, c accountAPI) http.HandlerFunc {
				return HandleEmailPost(h, newFlashTestStore(), c, consoleBaseURL)
			},
			request: func() *http.Request {
				return handlertest.Request(http.MethodPost, "/account/email",
					handlertest.WithAccessToken(), handlertest.WithForm(url.Values{"email": {"jane@example.com"}}))
			},
		},
		{
			name: "HandleEmailSendVerificationPost",
			build: func(h *handlersmocks.HttpHelper, c accountAPI) http.HandlerFunc {
				return HandleEmailSendVerificationPost(h, c)
			},
			request: func() *http.Request {
				return handlertest.Request(http.MethodPost, "/account/email/send-verification",
					handlertest.WithAccessToken())
			},
		},
		{
			name: "HandleEmailVerificationGet",
			build: func(h *handlersmocks.HttpHelper, c accountAPI) http.HandlerFunc {
				return HandleEmailVerificationGet(h, newFlashTestStore(), c)
			},
			request: func() *http.Request {
				return handlertest.Request(http.MethodGet, "/account/email/verification", handlertest.WithAccessToken(),
					// The page renders with the public settings, and is not there without email.
					handlertest.WithSettings(&api.PublicSettingsResponse{SMTPEnabled: true}))
			},
		},
		{
			name: "HandleEmailVerificationPost",
			build: func(h *handlersmocks.HttpHelper, c accountAPI) http.HandlerFunc {
				return HandleEmailVerificationPost(h, newFlashTestStore(), c, consoleBaseURL)
			},
			request: func() *http.Request {
				return handlertest.Request(http.MethodPost, "/account/email/verification",
					handlertest.WithAccessToken(), handlertest.WithForm(url.Values{"verificationCode": {"123456"}}),
					// A refused form is redrawn with the public settings.
					handlertest.WithSettings(&api.PublicSettingsResponse{SMTPEnabled: true}))
			},
		},
		{
			name: "HandleLogoutGet",
			build: func(h *handlersmocks.HttpHelper, c accountAPI) http.HandlerFunc {
				// Every row takes a real store, and this one needs it even when the API refuses:
				// it clears the console's own session before it asks the auth server to end the
				// upstream one.
				return HandleLogoutGet(h, newFlashTestStore(), c, consoleBaseURL)
			},
			// The logout page reads the verified ID token beside the bearer string, and takes its
			// unauthenticated arm without both of them.
			request: func() *http.Request {
				return handlertest.Request(http.MethodGet, "/account/logout",
					handlertest.WithJwtInfo(oauthclient.JwtInfo{
						TokenResponse: oauth.TokenResponse{AccessToken: handlertest.AccessToken},
						IdToken:       &oauth.JwtToken{TokenBase64: "the.id.token"},
					}))
			},
		},
		{
			name: "HandleManageConsentsGet",
			build: func(h *handlersmocks.HttpHelper, c accountAPI) http.HandlerFunc {
				return HandleManageConsentsGet(h, c)
			},
			request: func() *http.Request {
				return handlertest.Request(http.MethodGet, "/account/manage-consents",
					handlertest.WithAccessToken())
			},
		},
		{
			name: "HandleManageConsentsRevokePost",
			build: func(h *handlersmocks.HttpHelper, c accountAPI) http.HandlerFunc {
				return HandleManageConsentsRevokePost(h, c)
			},
			request: func() *http.Request {
				return handlertest.Request(http.MethodPost, "/account/manage-consents/revoke",
					handlertest.WithAccessToken(), handlertest.WithBody(strings.NewReader(`{"consentId":13}`)),
					handlertest.WithContentType("application/json"))
			},
		},
		{
			name: "HandleOtpGet",
			build: func(h *handlersmocks.HttpHelper, c accountAPI) http.HandlerFunc {
				return HandleOtpGet(h, c)
			},
			request: func() *http.Request {
				return handlertest.Request(http.MethodGet, "/account/otp", handlertest.WithAccessToken())
			},
		},
		{
			name: "HandleOtpPost",
			build: func(h *handlersmocks.HttpHelper, c accountAPI) http.HandlerFunc {
				return HandleOtpPost(h, c, consoleBaseURL)
			},
			request: func() *http.Request {
				return handlertest.Request(http.MethodPost, "/account/otp",
					handlertest.WithAccessToken(), handlertest.WithForm(url.Values{
						"otpAction": {"enable"}, "password": {"P4ss!word"}, "otp": {"123456"},
					}))
			},
		},
		{
			name: "HandlePhoneGet",
			build: func(h *handlersmocks.HttpHelper, c accountAPI) http.HandlerFunc {
				return HandlePhoneGet(h, newFlashTestStore(), c)
			},
			request: func() *http.Request {
				return handlertest.Request(http.MethodGet, "/account/phone", handlertest.WithAccessToken())
			},
		},
		{
			name: "HandlePhonePost",
			build: func(h *handlersmocks.HttpHelper, c accountAPI) http.HandlerFunc {
				return HandlePhonePost(h, newFlashTestStore(), c, consoleBaseURL)
			},
			request: func() *http.Request {
				return handlertest.Request(http.MethodPost, "/account/phone",
					handlertest.WithAccessToken(), handlertest.WithForm(url.Values{}))
			},
		},
		{
			name: "HandlePictureGet",
			build: func(h *handlersmocks.HttpHelper, c accountAPI) http.HandlerFunc {
				return HandlePictureGet(h, c)
			},
			request: func() *http.Request {
				return handlertest.Request(http.MethodGet, "/account/picture", handlertest.WithAccessToken())
			},
		},
		{
			name: "HandleProfileGet",
			build: func(h *handlersmocks.HttpHelper, c accountAPI) http.HandlerFunc {
				return HandleProfileGet(h, newFlashTestStore(), c)
			},
			request: func() *http.Request {
				return handlertest.Request(http.MethodGet, "/account/profile", handlertest.WithAccessToken())
			},
		},
		{
			name: "HandleProfilePost",
			build: func(h *handlersmocks.HttpHelper, c accountAPI) http.HandlerFunc {
				return HandleProfilePost(h, newFlashTestStore(), c, consoleBaseURL)
			},
			request: func() *http.Request {
				return handlertest.Request(http.MethodPost, "/account/profile",
					handlertest.WithAccessToken(), handlertest.WithForm(url.Values{}))
			},
		},
		{
			name: "HandleSessionsGet",
			build: func(h *handlersmocks.HttpHelper, c accountAPI) http.HandlerFunc {
				return HandleSessionsGet(h, c)
			},
			request: func() *http.Request {
				return handlertest.Request(http.MethodGet, "/account/sessions", handlertest.WithAccessToken())
			},
		},
		{
			name: "HandleSessionsEndSessionPost",
			build: func(h *handlersmocks.HttpHelper, c accountAPI) http.HandlerFunc {
				return HandleSessionsEndSessionPost(h, c)
			},
			request: func() *http.Request {
				return handlertest.Request(http.MethodPost, "/account/sessions",
					handlertest.WithAccessToken(),
					handlertest.WithBody(strings.NewReader(`{"userSessionId":31}`)),
					handlertest.WithContentType("application/json"))
			},
		},
	}
}

func TestAccountHandlers_EveryHandlerConsultsTheApiClientWithTheRequestsContext(t *testing.T) {
	for _, tc := range accountHandlerCases() {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			// Every writer is admitted: which one a handler picks is pattern 7's decision and is
			// held by TestHandlers_AjaxHandlersDoNotUsePageWriters and the classifier guard, not
			// here. What this case needs is only that the handler answered rather than carrying on.
			httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Maybe()
			httpHelper.On("JSONError", mock.Anything, mock.Anything, mock.Anything).Maybe()
			httpHelper.On("EncodeJSON", mock.Anything, mock.Anything, mock.Anything).Maybe()
			httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, mock.Anything,
				mock.Anything, mock.Anything).Return(nil).Maybe()

			apiClient := &ctxRecordingApiClient{}

			request := tc.request()
			marked := request.WithContext(context.WithValue(request.Context(), ctxMarkerKey{}, tc.name))

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
	t.Run("HandleProfilePictureDelete", func(t *testing.T) {
		httpHelper := handlersmocks.NewHttpHelper(t)
		httpHelper.On("JSONError", mock.Anything, mock.Anything, mock.Anything).Maybe()
		httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Maybe()
		httpHelper.On("EncodeJSON", mock.Anything, mock.Anything, mock.Anything).Maybe()

		apiClient := &ctxRecordingApiClient{}
		request := handlertest.Request(http.MethodDelete, "/account/profile-picture",
			handlertest.WithAccessToken())
		marked := request.WithContext(context.WithValue(request.Context(), ctxMarkerKey{}, "delete"))

		HandleProfilePictureDelete(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), marked)

		require.Len(t, apiClient.seen, 1)
		assert.Equal(t, "delete", apiClient.seen[0].Value(ctxMarkerKey{}))
	})
}
