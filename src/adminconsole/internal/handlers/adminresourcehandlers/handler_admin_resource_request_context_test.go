package adminresourcehandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	mocks_handlerhelpers "github.com/leodip/goiabada/adminconsole/internal/handlerhelpers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

// Seam 4 for the resource pages (#386 stages 11 and 12). See admingrouphandlers' file of the same
// name for what this owns and why the context is the assertion.
//
// GetResourceById and GetPermissionsByResource record and then succeed rather than refusing,
// because most of this package's pages read one or both of them first and everything below would
// otherwise be unreachable.

type resourceCtxMarkerKey struct{}

type resourceCtxRecordingApiClient struct {
	apiclient.ApiClient

	// permissions is what the resource has. Empty is the arm of the Get that reads every group;
	// one permission is the arm that asks the auth server to annotate them.
	permissions []api.PermissionResponse
	seen        []context.Context
}

func (s *resourceCtxRecordingApiClient) record(ctx context.Context) error {
	s.seen = append(s.seen, ctx)
	return errs.New("the auth server refused")
}

func (s *resourceCtxRecordingApiClient) GetResourceById(ctx context.Context, _ string, resourceId int64) (*api.ResourceResponse, error) {
	s.seen = append(s.seen, ctx)
	return &api.ResourceResponse{Id: resourceId, ResourceIdentifier: "some-resource"}, nil
}

func (s *resourceCtxRecordingApiClient) GetPermissionsByResource(ctx context.Context, _ string, _ int64) ([]api.PermissionResponse, error) {
	s.seen = append(s.seen, ctx)
	return s.permissions, nil
}

func (s *resourceCtxRecordingApiClient) GetAllResources(ctx context.Context, _ string) ([]api.ResourceResponse, error) {
	return nil, s.record(ctx)
}

func (s *resourceCtxRecordingApiClient) UpdateResource(ctx context.Context, _ string, _ int64, _ *api.UpdateResourceRequest) (*api.ResourceResponse, error) {
	return nil, s.record(ctx)
}

func (s *resourceCtxRecordingApiClient) DeleteResource(ctx context.Context, _ string, _ int64) error {
	return s.record(ctx)
}

func (s *resourceCtxRecordingApiClient) UpdateResourcePermissions(ctx context.Context, _ string, _ int64, _ *api.UpdateResourcePermissionsRequest) error {
	return s.record(ctx)
}

func (s *resourceCtxRecordingApiClient) GetUsersByPermission(ctx context.Context, _ string, _ int64, _, _ int) ([]api.UserResponse, int, error) {
	return nil, 0, s.record(ctx)
}

func (s *resourceCtxRecordingApiClient) SearchUsersWithPermissionAnnotation(ctx context.Context, _ string, _ int64, _ string, _, _ int) ([]api.UserWithPermissionResponse, int, error) {
	return nil, 0, s.record(ctx)
}

func (s *resourceCtxRecordingApiClient) GetUserPermissions(ctx context.Context, _ string, _ int64) (*api.UserResponse, []api.PermissionResponse, error) {
	return nil, nil, s.record(ctx)
}

func (s *resourceCtxRecordingApiClient) GetAllGroups(ctx context.Context, _ string) ([]api.GroupResponse, error) {
	return nil, s.record(ctx)
}

func (s *resourceCtxRecordingApiClient) SearchGroupsWithPermissionAnnotation(ctx context.Context, _ string, _ int64, _, _ int) ([]api.GroupWithPermissionResponse, int, error) {
	return nil, 0, s.record(ctx)
}

func (s *resourceCtxRecordingApiClient) GetGroupPermissions(ctx context.Context, _ string, _ int64) (*api.GroupResponse, []api.PermissionResponse, error) {
	return nil, nil, s.record(ctx)
}

func TestAdminResourceHandlers_TheMovedCallsCarryTheRequestsContext(t *testing.T) {
	testCases := []struct {
		name        string
		permissions []api.PermissionResponse
		build       func(httpHelper *mocks_handlerhelpers.HttpHelper, apiClient apiclient.ApiClient) http.HandlerFunc
		request     *http.Request
	}{
		{
			name: "HandleAdminResourcesGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminResourcesGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/resources", handlertest.WithAccessToken()),
		},
		{
			name: "HandleAdminResourceSettingsGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminResourceSettingsGet(h, testStore(), c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/resources/3/settings",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("resourceId", "3")),
		},
		{
			name: "HandleAdminResourceDeleteGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminResourceDeleteGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/resources/3/delete",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("resourceId", "3")),
		},
		{
			name: "HandleAdminResourcePermissionsGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminResourcePermissionsGet(h, testStore(), c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/resources/3/permissions",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("resourceId", "3")),
		},
		{
			name:        "HandleAdminResourceUsersWithPermissionGet",
			permissions: []api.PermissionResponse{{Id: 8, PermissionIdentifier: "read"}},
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminResourceUsersWithPermissionGet(h, testStore(), c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/resources/3/users-with-permission",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("resourceId", "3")),
		},
		{
			name: "HandleAdminResourceGroupsWithPermissionGet, no permission to annotate",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminResourceGroupsWithPermissionGet(h, testStore(), c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/resources/3/groups-with-permission",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("resourceId", "3")),
		},
		{
			name:        "HandleAdminResourceGroupsWithPermissionGet, one to annotate",
			permissions: []api.PermissionResponse{{Id: 8, PermissionIdentifier: "read"}},
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminResourceGroupsWithPermissionGet(h, testStore(), c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/resources/3/groups-with-permission",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("resourceId", "3")),
		},
		{
			name: "HandleAdminResourceGroupsWithPermissionAddPermissionPost",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminResourceGroupsWithPermissionAddPermissionPost(h, c)
			},
			request: handlertest.Request(http.MethodPost, "/admin/resources/3/groups-with-permission/5/add/8",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("resourceId", "3"),
				handlertest.WithRouteParam("groupId", "5"), handlertest.WithRouteParam("permissionId", "8")),
		},
		{
			name: "HandleAdminResourceGroupsWithPermissionRemovePermissionPost",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminResourceGroupsWithPermissionRemovePermissionPost(h, c)
			},
			request: handlertest.Request(http.MethodPost, "/admin/resources/3/groups-with-permission/5/remove/8",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("resourceId", "3"),
				handlertest.WithRouteParam("groupId", "5"), handlertest.WithRouteParam("permissionId", "8")),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
			httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Maybe()
			httpHelper.On("JsonError", mock.Anything, mock.Anything, mock.Anything).Maybe()
			httpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.Anything).Maybe()
			httpHelper.On("NotFound", mock.Anything, mock.Anything).Maybe()
			httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, mock.Anything,
				mock.Anything, mock.Anything).Return(nil).Maybe()

			apiClient := &resourceCtxRecordingApiClient{permissions: testCase.permissions}

			marked := testCase.request.WithContext(
				context.WithValue(testCase.request.Context(), resourceCtxMarkerKey{}, testCase.name))

			testCase.build(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), marked)

			require.NotEmpty(t, apiClient.seen, "the handler must consult its API client")
			for i, seen := range apiClient.seen {
				assert.Equal(t, testCase.name, seen.Value(resourceCtxMarkerKey{}),
					"call %d carried a context that is not the request's", i)
			}
		})
	}
}
