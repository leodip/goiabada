package adminuserhandlers

import (
	"bytes"
	"context"
	"mime/multipart"
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
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

// Seam 4 for the user pages (#386). See accounthandlers' file of the same name for what this owns
// and why the context is the assertion.

type userCtxMarkerKey struct{}

type ctxRecordingApiClient struct {
	seen []context.Context
}

func (s *ctxRecordingApiClient) record(ctx context.Context) error {
	s.seen = append(s.seen, ctx)
	return errs.New("the auth server refused")
}

func (s *ctxRecordingApiClient) GetUserPermissions(ctx context.Context, _ string, _ int64) (*api.UserResponse, []api.PermissionResponse, error) {
	return nil, nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) UpdateUserPermissions(ctx context.Context, _ string, _ int64, _ *api.UpdateUserPermissionsRequest) error {
	return s.record(ctx)
}

func (s *ctxRecordingApiClient) UpdateUserPhone(ctx context.Context, _ string, _ int64, _ *api.UpdateUserPhoneRequest) (*api.UserResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) GetPhoneCountries(ctx context.Context, _ string) ([]api.PhoneCountryResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) SearchUsersPaginated(ctx context.Context, _, _ string, _, _ int) ([]api.UserResponse, int, error) {
	return nil, 0, s.record(ctx)
}

func (s *ctxRecordingApiClient) GetUserById(ctx context.Context, _ string, _ int64) (*api.UserResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) UpdateUserEnabled(ctx context.Context, _ string, _ int64, _ bool) (*api.UserResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) UpdateUserProfile(ctx context.Context, _ string, _ int64, _ *api.UpdateUserProfileRequest) (*api.UserResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) UpdateUserAddress(ctx context.Context, _ string, _ int64, _ *api.UpdateUserAddressRequest) (*api.UserResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) UpdateUserEmail(ctx context.Context, _ string, _ int64, _ *api.UpdateUserEmailRequest) (*api.UserResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) CreateUserAdmin(ctx context.Context, _ string, _ *api.CreateUserAdminRequest) (*api.UserResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) DeleteUser(ctx context.Context, _ string, _ int64) error {
	return s.record(ctx)
}

func (s *ctxRecordingApiClient) UploadUserProfilePicture(ctx context.Context, _ string, _ int64, _ []byte, _ string) (*api.ProfilePictureUploadResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) DeleteUserProfilePicture(ctx context.Context, _ string, _ int64) error {
	return s.record(ctx)
}

func (s *ctxRecordingApiClient) UpdateUserGroups(ctx context.Context, _ string, _ int64, _ *api.UpdateUserGroupsRequest) (*api.UserResponse, []api.GroupResponse, error) {
	return nil, nil, s.record(ctx)
}

// GetUserGroups is the group page's first call, ahead of the user read every other page makes.
func (s *ctxRecordingApiClient) GetUserGroups(ctx context.Context, _ string, _ int64) (*api.UserResponse, []api.GroupResponse, error) {
	return nil, nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) CreateUserAttribute(ctx context.Context, _ string, _ *api.CreateUserAttributeRequest) (*api.UserAttributeResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) DeleteUserAttribute(ctx context.Context, _ string, _ int64) error {
	return s.record(ctx)
}

func (s *ctxRecordingApiClient) DeleteUserConsent(ctx context.Context, _ string, _ int64) error {
	return s.record(ctx)
}

func (s *ctxRecordingApiClient) DeleteUserSessionById(ctx context.Context, _ string, _ int64) error {
	return s.record(ctx)
}

func (s *ctxRecordingApiClient) GetAllGroups(ctx context.Context, _ string) ([]api.GroupResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) GetAllResources(ctx context.Context, _ string) ([]api.ResourceResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) GetUserAttributeById(ctx context.Context, _ string, _ int64) (*api.UserAttributeResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) GetUserAttributesByUserId(ctx context.Context, _ string, _ int64) ([]api.UserAttributeResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) GetUserConsents(ctx context.Context, _ string, _ int64) ([]api.UserConsentResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) GetUserProfilePicture(ctx context.Context, _ string, _ int64) (*api.ProfilePictureInfoResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) GetUserSessionsByUserId(ctx context.Context, _ string, _ int64) ([]api.UserSessionDetailResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) UpdateUserAttribute(ctx context.Context, _ string, _ int64, _ *api.UpdateUserAttributeRequest) (*api.UserAttributeResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) UpdateUserOTP(ctx context.Context, _ string, _ int64, _ *api.UpdateUserOTPRequest) (*api.UserResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingApiClient) UpdateUserPassword(ctx context.Context, _ string, _ int64, _ *api.UpdateUserPasswordRequest) (*api.UserResponse, error) {
	return nil, s.record(ctx)
}

func TestAdminUserHandlers_EveryHandlerConsultsTheApiClientWithTheRequestsContext(t *testing.T) {
	// Every one of these reaches a stage-11 method on its first API call, so the recording client
	// refuses there and the handler answers. The handlers taking a session store reach it only
	// after the API answered, so nil is never dereferenced.
	const userId = "42"

	testCases := []struct {
		name    string
		build   func(httpHelper *mocks_handlers.HttpHelper, apiClient *ctxRecordingApiClient) http.HandlerFunc
		request *http.Request
	}{
		{
			name: "HandleAdminUsersGet",
			build: func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleAdminUsersGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/users", handlertest.WithAccessToken()),
		},
		{
			name: "HandleAdminUserNewPost",
			build: func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleAdminUserNewPost(h, nil, c, consoleBaseURL)
			},
			request: handlertest.Request(http.MethodPost, "/admin/users/new",
				handlertest.WithAccessToken(),
				handlertest.WithSettings(&api.PublicSettingsResponse{}),
				handlertest.WithForm(url.Values{"email": {"jane@example.com"}, "password": {"N3w!word"}})),
		},
		{
			name: "HandleAdminUserPermissionsGet",
			build: func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleAdminUserPermissionsGet(h, nil, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/users/42/permissions",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("userId", userId)),
		},
		{
			name: "HandleAdminUserDetailsGet",
			build: func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleAdminUserDetailsGet(h, nil, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/users/42/details",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("userId", userId)),
		},
		{
			name: "HandleAdminUserDetailsPost",
			build: func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleAdminUserDetailsPost(h, nil, c, consoleBaseURL)
			},
			request: handlertest.Request(http.MethodPost, "/admin/users/42/details",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("userId", userId),
				handlertest.WithForm(url.Values{"enabled": {"on"}})),
		},
		{
			name: "HandleAdminUserProfileGet",
			build: func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleAdminUserProfileGet(h, nil, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/users/42/profile",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("userId", userId)),
		},
		{
			name: "HandleAdminUserProfilePost",
			build: func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleAdminUserProfilePost(h, nil, c, consoleBaseURL)
			},
			request: handlertest.Request(http.MethodPost, "/admin/users/42/profile",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("userId", userId),
				handlertest.WithForm(url.Values{"username": {"jdoe"}})),
		},
		{
			name: "HandleAdminUserEmailGet",
			build: func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleAdminUserEmailGet(h, nil, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/users/42/email",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("userId", userId)),
		},
		{
			name: "HandleAdminUserEmailPost",
			build: func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleAdminUserEmailPost(h, nil, c, consoleBaseURL)
			},
			request: handlertest.Request(http.MethodPost, "/admin/users/42/email",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("userId", userId),
				handlertest.WithForm(url.Values{"email": {"jane@example.com"}})),
		},
		{
			name: "HandleAdminUserAddressGet",
			build: func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleAdminUserAddressGet(h, nil, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/users/42/address",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("userId", userId)),
		},
		{
			name: "HandleAdminUserAddressPost",
			build: func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleAdminUserAddressPost(h, nil, c, consoleBaseURL)
			},
			request: handlertest.Request(http.MethodPost, "/admin/users/42/address",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("userId", userId),
				handlertest.WithForm(url.Values{})),
		},
		{
			name: "HandleAdminUserPhoneGet",
			build: func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleAdminUserPhoneGet(h, nil, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/users/42/phone",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("userId", userId)),
		},
		{
			name: "HandleAdminUserAuthenticationGet",
			build: func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleAdminUserAuthenticationGet(h, nil, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/users/42/authentication",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("userId", userId)),
		},
		{
			name: "HandleAdminUserAuthenticationPost",
			build: func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleAdminUserAuthenticationPost(h, nil, c, consoleBaseURL)
			},
			request: handlertest.Request(http.MethodPost, "/admin/users/42/authentication",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("userId", userId),
				handlertest.WithForm(url.Values{})),
		},
		{
			name: "HandleAdminUserPictureGet",
			build: func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleAdminUserPictureGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/users/42/picture",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("userId", userId)),
		},
		{
			name: "HandleAdminUserProfilePicturePost",
			build: func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleAdminUserProfilePicturePost(h, c)
			},
			request: pictureUpload(userId),
		},
		{
			name: "HandleAdminUserProfilePictureDelete",
			build: func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleAdminUserProfilePictureDelete(h, c)
			},
			request: handlertest.Request(http.MethodDelete, "/admin/users/42/profile-picture",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("userId", userId)),
		},
		{
			name: "HandleAdminUserGroupsGet",
			build: func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleAdminUserGroupsGet(h, nil, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/users/42/groups",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("userId", userId)),
		},
		{
			name: "HandleAdminUserGroupsPost",
			build: func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleAdminUserGroupsPost(h, nil, c)
			},
			request: handlertest.Request(http.MethodPost, "/admin/users/42/groups",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("userId", userId),
				handlertest.WithBody(strings.NewReader(`{"assignedGroupsIds":[5]}`)),
				handlertest.WithContentType("application/json")),
		},
		{
			name: "HandleAdminUserAttributesGet",
			build: func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleAdminUserAttributesGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/users/42/attributes",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("userId", userId)),
		},
		{
			name: "HandleAdminUserAttributesRemovePost",
			build: func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleAdminUserAttributesRemovePost(h, c)
			},
			request: handlertest.Request(http.MethodPost, "/admin/users/42/attributes/21/remove",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("userId", userId),
				handlertest.WithRouteParam("attributeId", "21")),
		},
		{
			name: "HandleAdminUserAttributesAddGet",
			build: func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleAdminUserAttributesAddGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/users/42/attributes/add",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("userId", userId)),
		},
		{
			name: "HandleAdminUserAttributesAddPost",
			build: func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleAdminUserAttributesAddPost(h, c, consoleBaseURL)
			},
			request: handlertest.Request(http.MethodPost, "/admin/users/42/attributes/add",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("userId", userId),
				handlertest.WithForm(url.Values{"attributeKey": {"k"}, "attributeValue": {"v"}})),
		},
		{
			name: "HandleAdminUserAttributesEditGet",
			build: func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleAdminUserAttributesEditGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/users/42/attributes/21/edit",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("userId", userId),
				handlertest.WithRouteParam("attributeId", "21")),
		},
		{
			name: "HandleAdminUserAttributesEditPost",
			build: func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleAdminUserAttributesEditPost(h, c, consoleBaseURL)
			},
			request: handlertest.Request(http.MethodPost, "/admin/users/42/attributes/21/edit",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("userId", userId),
				handlertest.WithRouteParam("attributeId", "21"),
				handlertest.WithForm(url.Values{"attributeKey": {"k"}, "attributeValue": {"v"}})),
		},
		{
			name: "HandleAdminUserConsentsGet",
			build: func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleAdminUserConsentsGet(h, nil, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/users/42/consents",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("userId", userId)),
		},
		{
			name: "HandleAdminUserConsentsPost",
			build: func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleAdminUserConsentsPost(h, c)
			},
			request: handlertest.Request(http.MethodPost, "/admin/users/42/consents",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("userId", userId),
				handlertest.WithBody(strings.NewReader(`{"consentId":13}`)),
				handlertest.WithContentType("application/json")),
		},
		{
			name: "HandleAdminUserSessionsGet",
			build: func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleAdminUserSessionsGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/users/42/sessions",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("userId", userId)),
		},
		{
			name: "HandleAdminUserSessionsPost",
			build: func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleAdminUserSessionsPost(h, c)
			},
			request: handlertest.Request(http.MethodPost, "/admin/users/42/sessions",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("userId", userId),
				handlertest.WithBody(strings.NewReader(`{"userSessionId":31}`)),
				handlertest.WithContentType("application/json")),
		},
		{
			name: "HandleAdminUserDeleteGet",
			build: func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleAdminUserDeleteGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/users/42/delete",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("userId", userId)),
		},
		{
			name: "HandleAdminUserDeletePost",
			build: func(h *mocks_handlers.HttpHelper, c *ctxRecordingApiClient) http.HandlerFunc {
				return HandleAdminUserDeletePost(h, c, consoleBaseURL)
			},
			request: handlertest.Request(http.MethodPost, "/admin/users/42/delete",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("userId", userId),
				handlertest.WithForm(url.Values{})),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			httpHelper := mocks_handlers.NewHttpHelper(t)
			// Every writer is admitted: which one a handler picks is pattern 7's decision and is
			// held by TestHandlers_AjaxHandlersDoNotUsePageWriters and the classifier guard, not
			// here. What this case needs is only that the handler answered rather than carrying on.
			httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Maybe()
			httpHelper.On("JSONError", mock.Anything, mock.Anything, mock.Anything).Maybe()
			httpHelper.On("EncodeJSON", mock.Anything, mock.Anything, mock.Anything).Maybe()
			httpHelper.On("NotFound", mock.Anything, mock.Anything).Maybe()
			httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, mock.Anything,
				mock.Anything, mock.Anything).Return(nil).Maybe()

			apiClient := &ctxRecordingApiClient{}

			marked := testCase.request.WithContext(
				context.WithValue(testCase.request.Context(), userCtxMarkerKey{}, testCase.name))

			testCase.build(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), marked)

			require.NotEmpty(t, apiClient.seen, "the handler must consult its API client")
			for i, seen := range apiClient.seen {
				assert.Equal(t, testCase.name, seen.Value(userCtxMarkerKey{}),
					"call %d carried a context that is not the request's", i)
			}
		})
	}
}

func TestAdminUserHandlers_ThePhoneWriteCarriesTheRequestsContext(t *testing.T) {
	httpHelper := mocks_handlers.NewHttpHelper(t)
	httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Maybe()
	httpHelper.On("JSONError", mock.Anything, mock.Anything, mock.Anything).Maybe()
	httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything).Return(nil).Maybe()

	// The user read this page makes first refuses like everything else, so this case builds a
	// client whose GetUserById succeeds and leaves the rest recording.
	apiClient := &phoneWriteApiClient{}

	request := handlertest.Request(http.MethodPost, "/admin/users/42/phone",
		handlertest.WithAccessToken(), handlertest.WithRouteParam("userId", "42"),
		handlertest.WithForm(url.Values{"phoneCountryUniqueId": {"BRA_0"}, "phoneNumber": {"5551234"}}))
	marked := request.WithContext(context.WithValue(request.Context(), userCtxMarkerKey{}, "phone"))

	HandleAdminUserPhonePost(httpHelper, nil, apiClient, consoleBaseURL).ServeHTTP(httptest.NewRecorder(), marked)

	require.NotEmpty(t, apiClient.seen, "the handler must consult its API client")
	for i, seen := range apiClient.seen {
		assert.Equal(t, "phone", seen.Value(userCtxMarkerKey{}),
			"call %d carried a context that is not the request's", i)
	}
}

// phoneWriteApiClient answers the user read so the phone write below it is reached at all.
type phoneWriteApiClient struct {
	ctxRecordingApiClient
}

func (s *phoneWriteApiClient) GetUserById(_ context.Context, _ string, userId int64) (*api.UserResponse, error) {
	return &api.UserResponse{Id: userId, Username: "jdoe"}, nil
}

// pictureUpload is the one request here that is not form-encoded: the upload handler reads a
// multipart "picture" part and refuses anything else before it reaches the API.
func pictureUpload(userId string) *http.Request {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, err := writer.CreateFormFile("picture", "face.png")
	if err == nil {
		_, _ = part.Write([]byte("the-picture-bytes"))
	}
	_ = writer.Close()

	return handlertest.Request(http.MethodPost, "/admin/users/"+userId+"/profile-picture",
		handlertest.WithAccessToken(), handlertest.WithRouteParam("userId", userId),
		handlertest.WithContentType(writer.FormDataContentType()),
		handlertest.WithBody(bytes.NewReader(buf.Bytes())))
}
