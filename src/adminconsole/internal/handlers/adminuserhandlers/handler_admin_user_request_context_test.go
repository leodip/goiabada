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

	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

// Seam 4 for the user pages (#386). See accounthandlers' file of the same name for what this owns
// and why the context is the assertion.

type userCtxMarkerKey struct{}

type ctxRecordingAPIClient struct {
	seen []context.Context
}

func (s *ctxRecordingAPIClient) record(ctx context.Context) error {
	s.seen = append(s.seen, ctx)
	return errs.New("the auth server refused")
}

func (s *ctxRecordingAPIClient) GetUserPermissions(ctx context.Context, _ string, _ int64) (*api.UserResponse, []api.PermissionResponse, error) {
	return nil, nil, s.record(ctx)
}

func (s *ctxRecordingAPIClient) UpdateUserPermissions(ctx context.Context, _ string, _ int64, _ *api.UpdateUserPermissionsRequest) error {
	return s.record(ctx)
}

func (s *ctxRecordingAPIClient) UpdateUserPhone(ctx context.Context, _ string, _ int64, _ *api.UpdateUserPhoneRequest) (*api.UserResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingAPIClient) SearchUsersPaginated(ctx context.Context, _, _ string, _, _ int) ([]api.UserResponse, int, error) {
	return nil, 0, s.record(ctx)
}

func (s *ctxRecordingAPIClient) GetUserByID(ctx context.Context, _ string, _ int64) (*api.UserResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingAPIClient) UpdateUserEnabled(ctx context.Context, _ string, _ int64, _ bool) (*api.UserResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingAPIClient) UpdateUserProfile(ctx context.Context, _ string, _ int64, _ *api.UpdateUserProfileRequest) (*api.UserResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingAPIClient) UpdateUserAddress(ctx context.Context, _ string, _ int64, _ *api.UpdateUserAddressRequest) (*api.UserResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingAPIClient) UpdateUserEmail(ctx context.Context, _ string, _ int64, _ *api.UpdateUserEmailRequest) (*api.UserResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingAPIClient) CreateUserAdmin(ctx context.Context, _ string, _ *api.CreateUserAdminRequest) (*api.CreateUserResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingAPIClient) DeleteUser(ctx context.Context, _ string, _ int64) error {
	return s.record(ctx)
}

func (s *ctxRecordingAPIClient) UploadUserProfilePicture(ctx context.Context, _ string, _ int64, _ []byte, _ string) (*api.ProfilePictureUploadResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingAPIClient) DeleteUserProfilePicture(ctx context.Context, _ string, _ int64) error {
	return s.record(ctx)
}

func (s *ctxRecordingAPIClient) UpdateUserGroups(ctx context.Context, _ string, _ int64, _ *api.UpdateUserGroupsRequest) (*api.UserResponse, []api.GroupResponse, error) {
	return nil, nil, s.record(ctx)
}

// GetUserGroups is the group page's first call, ahead of the user read every other page makes.
func (s *ctxRecordingAPIClient) GetUserGroups(ctx context.Context, _ string, _ int64) (*api.UserResponse, []api.GroupResponse, error) {
	return nil, nil, s.record(ctx)
}

func (s *ctxRecordingAPIClient) CreateUserAttribute(ctx context.Context, _ string, _ *api.CreateUserAttributeRequest) (*api.UserAttributeResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingAPIClient) DeleteUserAttribute(ctx context.Context, _ string, _ int64) error {
	return s.record(ctx)
}

func (s *ctxRecordingAPIClient) DeleteUserSessionByID(ctx context.Context, _ string, _ int64) error {
	return s.record(ctx)
}

func (s *ctxRecordingAPIClient) GetAllGroups(ctx context.Context, _ string) ([]api.GroupResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingAPIClient) GetAllResources(ctx context.Context, _ string) ([]api.ResourceResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingAPIClient) GetUserAttributeByID(ctx context.Context, _ string, _ int64) (*api.UserAttributeResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingAPIClient) GetUserAttributesByUserID(ctx context.Context, _ string, _ int64) ([]api.UserAttributeResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingAPIClient) GetUserConnectedClients(ctx context.Context, _ string, _ int64) ([]api.ConnectedClientResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingAPIClient) DisconnectUserClient(ctx context.Context, _ string, _, _ int64) error {
	return s.record(ctx)
}

func (s *ctxRecordingAPIClient) GetUserProfilePicture(ctx context.Context, _ string, _ int64) (*api.ProfilePictureInfoResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingAPIClient) GetUserSessionsByUserID(ctx context.Context, _ string, _ int64) ([]api.UserSessionDetailResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingAPIClient) UpdateUserAttribute(ctx context.Context, _ string, _ int64, _ *api.UpdateUserAttributeRequest) (*api.UserAttributeResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingAPIClient) UpdateUserOTP(ctx context.Context, _ string, _ int64, _ *api.UpdateUserOTPRequest) (*api.UserResponse, error) {
	return nil, s.record(ctx)
}

func (s *ctxRecordingAPIClient) UpdateUserPassword(ctx context.Context, _ string, _ int64, _ *api.UpdateUserPasswordRequest) (*api.UserResponse, error) {
	return nil, s.record(ctx)
}

func TestAdminUserHandlers_EveryHandlerConsultsTheAPIClientWithTheRequestsContext(t *testing.T) {
	// Every one of these reaches a stage-11 method on its first API call, so the recording client
	// refuses there and the handler answers. The handlers taking a session store reach it only
	// after the API answered, so nil is never dereferenced.
	const userID = "42"

	testCases := []struct {
		name    string
		build   func(httpHelper *handlersmocks.HTTPHelper, apiClient *ctxRecordingAPIClient) http.HandlerFunc
		request *http.Request
	}{
		{
			name: "HandleListGet",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleListGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/users", handlertest.WithAccessToken()),
		},
		{
			name: "HandleNewPost",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleNewPost(h, nil, c, consoleBaseURL)
			},
			request: handlertest.Request(http.MethodPost, "/admin/users/new",
				handlertest.WithAccessToken(),
				handlertest.WithSettings(&api.PublicSettingsResponse{}),
				handlertest.WithForm(url.Values{"email": {"jane@example.com"}, "password": {"N3w!word"}})),
		},
		{
			name: "HandlePermissionsGet",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandlePermissionsGet(h, nil, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/users/42/permissions",
				handlertest.WithAccessToken(), handlertest.WithPathValue("userId", userID)),
		},
		{
			name: "HandleDetailsGet",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleDetailsGet(h, nil, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/users/42/details",
				handlertest.WithAccessToken(), handlertest.WithPathValue("userId", userID)),
		},
		{
			name: "HandleDetailsPost",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleDetailsPost(h, nil, c, consoleBaseURL)
			},
			request: handlertest.Request(http.MethodPost, "/admin/users/42/details",
				handlertest.WithAccessToken(), handlertest.WithPathValue("userId", userID),
				handlertest.WithForm(url.Values{"enabled": {"on"}})),
		},
		{
			name: "HandleProfileGet",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleProfileGet(h, nil, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/users/42/profile",
				handlertest.WithAccessToken(), handlertest.WithPathValue("userId", userID)),
		},
		{
			name: "HandleProfilePost",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleProfilePost(h, nil, c, consoleBaseURL)
			},
			request: handlertest.Request(http.MethodPost, "/admin/users/42/profile",
				handlertest.WithAccessToken(), handlertest.WithPathValue("userId", userID),
				handlertest.WithForm(url.Values{"username": {"jdoe"}})),
		},
		{
			name: "HandleEmailGet",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleEmailGet(h, nil, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/users/42/email",
				handlertest.WithAccessToken(), handlertest.WithPathValue("userId", userID)),
		},
		{
			name: "HandleEmailPost",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleEmailPost(h, nil, c, consoleBaseURL)
			},
			request: handlertest.Request(http.MethodPost, "/admin/users/42/email",
				handlertest.WithAccessToken(), handlertest.WithPathValue("userId", userID),
				handlertest.WithForm(url.Values{"email": {"jane@example.com"}})),
		},
		{
			name: "HandleAddressGet",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleAddressGet(h, nil, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/users/42/address",
				handlertest.WithAccessToken(), handlertest.WithPathValue("userId", userID)),
		},
		{
			name: "HandleAddressPost",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleAddressPost(h, nil, c, consoleBaseURL)
			},
			request: handlertest.Request(http.MethodPost, "/admin/users/42/address",
				handlertest.WithAccessToken(), handlertest.WithPathValue("userId", userID),
				handlertest.WithForm(url.Values{})),
		},
		{
			name: "HandlePhoneGet",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandlePhoneGet(h, nil, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/users/42/phone",
				handlertest.WithAccessToken(), handlertest.WithPathValue("userId", userID)),
		},
		{
			name: "HandleAuthenticationGet",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleAuthenticationGet(h, nil, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/users/42/authentication",
				handlertest.WithAccessToken(), handlertest.WithPathValue("userId", userID)),
		},
		{
			name: "HandleAuthenticationPost",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleAuthenticationPost(h, nil, c, consoleBaseURL)
			},
			request: handlertest.Request(http.MethodPost, "/admin/users/42/authentication",
				handlertest.WithAccessToken(), handlertest.WithPathValue("userId", userID),
				handlertest.WithForm(url.Values{})),
		},
		{
			name: "HandlePictureGet",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandlePictureGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/users/42/picture",
				handlertest.WithAccessToken(), handlertest.WithPathValue("userId", userID)),
		},
		{
			name: "HandleProfilePicturePost",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleProfilePicturePost(h, c)
			},
			request: pictureUpload(userID),
		},
		{
			name: "HandleProfilePictureDelete",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleProfilePictureDelete(h, c)
			},
			request: handlertest.Request(http.MethodDelete, "/admin/users/42/profile-picture",
				handlertest.WithAccessToken(), handlertest.WithPathValue("userId", userID)),
		},
		{
			name: "HandleGroupsGet",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleGroupsGet(h, nil, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/users/42/groups",
				handlertest.WithAccessToken(), handlertest.WithPathValue("userId", userID)),
		},
		{
			name: "HandleGroupsPost",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleGroupsPost(h, nil, c)
			},
			request: handlertest.Request(http.MethodPost, "/admin/users/42/groups",
				handlertest.WithAccessToken(), handlertest.WithPathValue("userId", userID),
				handlertest.WithBody(strings.NewReader(`{"assignedGroupsIds":[5]}`)),
				handlertest.WithContentType("application/json")),
		},
		{
			name: "HandleAttributesGet",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleAttributesGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/users/42/attributes",
				handlertest.WithAccessToken(), handlertest.WithPathValue("userId", userID)),
		},
		{
			name: "HandleAttributesRemovePost",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleAttributesRemovePost(h, c)
			},
			request: handlertest.Request(http.MethodPost, "/admin/users/42/attributes/21/remove",
				handlertest.WithAccessToken(), handlertest.WithPathValue("userId", userID),
				handlertest.WithPathValue("attributeId", "21")),
		},
		{
			name: "HandleAttributesAddGet",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleAttributesAddGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/users/42/attributes/add",
				handlertest.WithAccessToken(), handlertest.WithPathValue("userId", userID)),
		},
		{
			name: "HandleAttributesAddPost",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleAttributesAddPost(h, c, consoleBaseURL)
			},
			request: handlertest.Request(http.MethodPost, "/admin/users/42/attributes/add",
				handlertest.WithAccessToken(), handlertest.WithPathValue("userId", userID),
				handlertest.WithForm(url.Values{"attributeKey": {"k"}, "attributeValue": {"v"}})),
		},
		{
			name: "HandleAttributesEditGet",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleAttributesEditGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/users/42/attributes/21/edit",
				handlertest.WithAccessToken(), handlertest.WithPathValue("userId", userID),
				handlertest.WithPathValue("attributeId", "21")),
		},
		{
			name: "HandleAttributesEditPost",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleAttributesEditPost(h, c, consoleBaseURL)
			},
			request: handlertest.Request(http.MethodPost, "/admin/users/42/attributes/21/edit",
				handlertest.WithAccessToken(), handlertest.WithPathValue("userId", userID),
				handlertest.WithPathValue("attributeId", "21"),
				handlertest.WithForm(url.Values{"attributeKey": {"k"}, "attributeValue": {"v"}})),
		},
		{
			name: "HandleConnectedClientsGet",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleConnectedClientsGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/users/42/connected-clients",
				handlertest.WithAccessToken(), handlertest.WithPathValue("userId", userID)),
		},
		{
			name: "HandleConnectedClientsDisconnectPost",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleConnectedClientsDisconnectPost(h, c)
			},
			request: handlertest.Request(http.MethodPost, "/admin/users/42/connected-clients",
				handlertest.WithAccessToken(), handlertest.WithPathValue("userId", userID),
				handlertest.WithBody(strings.NewReader(`{"clientId":13}`)),
				handlertest.WithContentType("application/json")),
		},
		{
			name: "HandleSessionsGet",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleSessionsGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/users/42/sessions",
				handlertest.WithAccessToken(), handlertest.WithPathValue("userId", userID)),
		},
		{
			name: "HandleSessionsPost",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleSessionsPost(h, c)
			},
			request: handlertest.Request(http.MethodPost, "/admin/users/42/sessions",
				handlertest.WithAccessToken(), handlertest.WithPathValue("userId", userID),
				handlertest.WithBody(strings.NewReader(`{"userSessionId":31}`)),
				handlertest.WithContentType("application/json")),
		},
		{
			name: "HandleDeleteGet",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleDeleteGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/users/42/delete",
				handlertest.WithAccessToken(), handlertest.WithPathValue("userId", userID)),
		},
		{
			name: "HandleDeletePost",
			build: func(h *handlersmocks.HTTPHelper, c *ctxRecordingAPIClient) http.HandlerFunc {
				return HandleDeletePost(h, c, consoleBaseURL)
			},
			request: handlertest.Request(http.MethodPost, "/admin/users/42/delete",
				handlertest.WithAccessToken(), handlertest.WithPathValue("userId", userID),
				handlertest.WithForm(url.Values{})),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHTTPHelper(t)
			// Every writer is admitted: which one a handler picks is pattern 7's decision and is
			// held by TestHandlers_AjaxHandlersDoNotUsePageWriters and the classifier guard, not
			// here. What this case needs is only that the handler answered rather than carrying on.
			httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Maybe()
			httpHelper.On("JSONError", mock.Anything, mock.Anything, mock.Anything).Maybe()
			httpHelper.On("EncodeJSON", mock.Anything, mock.Anything, mock.Anything).Maybe()
			httpHelper.On("NotFound", mock.Anything, mock.Anything).Maybe()
			httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, mock.Anything,
				mock.Anything, mock.Anything).Return(nil).Maybe()

			apiClient := &ctxRecordingAPIClient{}

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
	httpHelper := handlersmocks.NewHTTPHelper(t)
	httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Maybe()
	httpHelper.On("JSONError", mock.Anything, mock.Anything, mock.Anything).Maybe()
	httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything).Return(nil).Maybe()

	// The write is the one call this POST makes, since its country list is core's (#563). Before,
	// the list's read came first and refused, and the write below it was never reached.
	apiClient := &ctxRecordingAPIClient{}

	request := handlertest.Request(http.MethodPost, "/admin/users/42/phone",
		handlertest.WithAccessToken(), handlertest.WithPathValue("userId", "42"),
		handlertest.WithForm(url.Values{"phoneCountryUniqueId": {"BRA_0"}, "phoneNumber": {"5551234"}}))
	marked := request.WithContext(context.WithValue(request.Context(), userCtxMarkerKey{}, "phone"))

	HandlePhonePost(httpHelper, nil, apiClient, consoleBaseURL).ServeHTTP(httptest.NewRecorder(), marked)

	require.Len(t, apiClient.seen, 1, "the handler must consult its API client for the write")
	assert.Equal(t, "phone", apiClient.seen[0].Value(userCtxMarkerKey{}),
		"the write carried a context that is not the request's")
}

// pictureUpload is the one request here that is not form-encoded: the upload handler reads a
// multipart "picture" part and refuses anything else before it reaches the API.
func pictureUpload(userID string) *http.Request {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, err := writer.CreateFormFile("picture", "face.png")
	if err == nil {
		_, _ = part.Write([]byte("the-picture-bytes"))
	}
	_ = writer.Close()

	return handlertest.Request(http.MethodPost, "/admin/users/"+userID+"/profile-picture",
		handlertest.WithAccessToken(), handlertest.WithPathValue("userId", userID),
		handlertest.WithContentType(writer.FormDataContentType()),
		handlertest.WithBody(bytes.NewReader(buf.Bytes())))
}
