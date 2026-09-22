package admingrouphandlers

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
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

// Seam 4 for the group pages (#386 stage 11).
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

type groupCtxMarkerKey struct{}

// groupCtxRecordingApiClient records the context every stage-11 group method is called with and
// then refuses, so the handler takes its error path in the same pass. It embeds ApiClient, so a
// method a handler calls that is not stubbed here panics on a nil interface rather than passing
// silently.
type groupCtxRecordingApiClient struct {
	apiclient.ApiClient
	seen []context.Context
}

func (s *groupCtxRecordingApiClient) record(ctx context.Context) error {
	s.seen = append(s.seen, ctx)
	return errs.New("the auth server refused")
}

// GetAllResources is the permissions page's first call and is #386 stage 12's. It is here rather
// than in the resource package because this is the handler that makes it.
func (s *groupCtxRecordingApiClient) GetAllResources(ctx context.Context, _ string) ([]api.ResourceResponse, error) {
	return nil, s.record(ctx)
}

func (s *groupCtxRecordingApiClient) GetAllGroups(ctx context.Context, _ string) ([]api.GroupResponse, error) {
	return nil, s.record(ctx)
}

func (s *groupCtxRecordingApiClient) CreateGroup(ctx context.Context, _ string, _ *api.CreateGroupRequest) (*api.GroupResponse, error) {
	return nil, s.record(ctx)
}

func (s *groupCtxRecordingApiClient) GetGroupById(ctx context.Context, _ string, _ int64) (*api.GroupResponse, error) {
	return nil, s.record(ctx)
}

func (s *groupCtxRecordingApiClient) UpdateGroup(ctx context.Context, _ string, _ int64, _ *api.UpdateGroupRequest) (*api.GroupResponse, error) {
	return nil, s.record(ctx)
}

func (s *groupCtxRecordingApiClient) DeleteGroup(ctx context.Context, _ string, _ int64) error {
	return s.record(ctx)
}

func (s *groupCtxRecordingApiClient) GetGroupMembers(ctx context.Context, _ string, _ int64, _, _ int) ([]api.UserResponse, int, error) {
	return nil, 0, s.record(ctx)
}

func (s *groupCtxRecordingApiClient) AddUserToGroup(ctx context.Context, _ string, _ int64, _ int64) error {
	return s.record(ctx)
}

func (s *groupCtxRecordingApiClient) RemoveUserFromGroup(ctx context.Context, _ string, _ int64, _ int64) error {
	return s.record(ctx)
}

func (s *groupCtxRecordingApiClient) SearchUsersWithGroupAnnotation(ctx context.Context, _, _ string, _ int64, _, _ int) ([]api.UserWithGroupMembershipResponse, int, error) {
	return nil, 0, s.record(ctx)
}

func (s *groupCtxRecordingApiClient) GetGroupPermissions(ctx context.Context, _ string, _ int64) (*api.GroupResponse, []api.PermissionResponse, error) {
	return nil, nil, s.record(ctx)
}

func (s *groupCtxRecordingApiClient) UpdateGroupPermissions(ctx context.Context, _ string, _ int64, _ *api.UpdateGroupPermissionsRequest) error {
	return s.record(ctx)
}

func (s *groupCtxRecordingApiClient) GetGroupAttributesByGroupId(ctx context.Context, _ string, _ int64) ([]api.GroupAttributeResponse, error) {
	return nil, s.record(ctx)
}

func (s *groupCtxRecordingApiClient) GetGroupAttributeById(ctx context.Context, _ string, _ int64) (*api.GroupAttributeResponse, error) {
	return nil, s.record(ctx)
}

func (s *groupCtxRecordingApiClient) CreateGroupAttribute(ctx context.Context, _ string, _ *api.CreateGroupAttributeRequest) (*api.GroupAttributeResponse, error) {
	return nil, s.record(ctx)
}

func (s *groupCtxRecordingApiClient) UpdateGroupAttribute(ctx context.Context, _ string, _ int64, _ *api.UpdateGroupAttributeRequest) (*api.GroupAttributeResponse, error) {
	return nil, s.record(ctx)
}

func (s *groupCtxRecordingApiClient) DeleteGroupAttribute(ctx context.Context, _ string, _ int64) error {
	return s.record(ctx)
}

func TestAdminGroupHandlers_EveryHandlerConsultsTheApiClientWithTheRequestsContext(t *testing.T) {
	// The handlers taking a session store reach it only after the API answered, and the client
	// here always refuses, so nil is never dereferenced.
	testCases := []struct {
		name    string
		build   func(httpHelper *mocks_handlerhelpers.HttpHelper, apiClient apiclient.ApiClient) http.HandlerFunc
		request *http.Request
	}{
		{
			name: "HandleAdminGroupsGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminGroupsGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/groups", handlertest.WithAccessToken()),
		},
		{
			name: "HandleAdminGroupNewPost",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminGroupNewPost(h, c)
			},
			request: handlertest.Request(http.MethodPost, "/admin/groups/new",
				handlertest.WithAccessToken(),
				handlertest.WithForm(url.Values{"groupIdentifier": {"support"}})),
		},
		{
			name: "HandleAdminGroupPermissionsGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminGroupPermissionsGet(h, nil, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/groups/5/permissions",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("groupId", "5")),
		},
		{
			name: "HandleAdminGroupSettingsGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminGroupSettingsGet(h, nil, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/groups/5/settings",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("groupId", "5")),
		},
		{
			name: "HandleAdminGroupSettingsPost",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminGroupSettingsPost(h, nil, c)
			},
			request: handlertest.Request(http.MethodPost, "/admin/groups/5/settings",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("groupId", "5"),
				handlertest.WithForm(url.Values{"groupIdentifier": {"support"}})),
		},
		{
			name: "HandleAdminGroupDeleteGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminGroupDeleteGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/groups/5/delete",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("groupId", "5")),
		},
		{
			name: "HandleAdminGroupDeletePost",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminGroupDeletePost(h, c)
			},
			request: handlertest.Request(http.MethodPost, "/admin/groups/5/delete",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("groupId", "5"),
				handlertest.WithForm(url.Values{"groupIdentifier": {"support"}})),
		},
		{
			name: "HandleAdminGroupMembersGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminGroupMembersGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/groups/5/members",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("groupId", "5")),
		},
		{
			name: "HandleAdminGroupMembersAddGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminGroupMembersAddGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/groups/5/members/add",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("groupId", "5")),
		},
		{
			name: "HandleAdminGroupMembersSearchGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminGroupMembersSearchGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/groups/5/members/search?query=jane",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("groupId", "5")),
		},
		{
			name: "HandleAdminGroupMembersAddPost",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminGroupMembersAddPost(h, c)
			},
			request: handlertest.Request(http.MethodPost, "/admin/groups/5/members/add?userId=42",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("groupId", "5")),
		},
		{
			name: "HandleAdminGroupMembersRemoveUserPost",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminGroupMembersRemoveUserPost(h, c)
			},
			request: handlertest.Request(http.MethodPost, "/admin/groups/5/members/42/remove",
				handlertest.WithAccessToken(),
				handlertest.WithRouteParam("groupId", "5"), handlertest.WithRouteParam("userId", "42")),
		},
		{
			name: "HandleAdminGroupPermissionsGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminGroupPermissionsGet(h, nil, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/groups/5/permissions",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("groupId", "5")),
		},
		{
			name: "HandleAdminGroupPermissionsPost",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminGroupPermissionsPost(h, nil, c)
			},
			request: handlertest.Request(http.MethodPost, "/admin/groups/5/permissions",
				handlertest.WithAccessToken(),
				handlertest.WithBody(strings.NewReader(`{"groupId":5,"assignedPermissionsIds":[8]}`)),
				handlertest.WithContentType("application/json")),
		},
		{
			name: "HandleAdminGroupAttributesGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminGroupAttributesGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/groups/5/attributes",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("groupId", "5")),
		},
		{
			name: "HandleAdminGroupAttributesRemovePost",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminGroupAttributesRemovePost(h, c)
			},
			request: handlertest.Request(http.MethodPost, "/admin/groups/5/attributes/11/remove",
				handlertest.WithAccessToken(),
				handlertest.WithRouteParam("groupId", "5"), handlertest.WithRouteParam("attributeId", "11")),
		},
		{
			name: "HandleAdminGroupAttributesAddGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminGroupAttributesAddGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/groups/5/attributes/add",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("groupId", "5")),
		},
		{
			name: "HandleAdminGroupAttributesAddPost",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminGroupAttributesAddPost(h, c)
			},
			request: handlertest.Request(http.MethodPost, "/admin/groups/5/attributes/add",
				handlertest.WithAccessToken(), handlertest.WithRouteParam("groupId", "5"),
				handlertest.WithForm(url.Values{"attributeKey": {"k"}, "attributeValue": {"v"}})),
		},
		{
			name: "HandleAdminGroupAttributesEditGet",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminGroupAttributesEditGet(h, c)
			},
			request: handlertest.Request(http.MethodGet, "/admin/groups/5/attributes/11/edit",
				handlertest.WithAccessToken(),
				handlertest.WithRouteParam("groupId", "5"), handlertest.WithRouteParam("attributeId", "11")),
		},
		{
			name: "HandleAdminGroupAttributesEditPost",
			build: func(h *mocks_handlerhelpers.HttpHelper, c apiclient.ApiClient) http.HandlerFunc {
				return HandleAdminGroupAttributesEditPost(h, c)
			},
			request: handlertest.Request(http.MethodPost, "/admin/groups/5/attributes/11/edit",
				handlertest.WithAccessToken(),
				handlertest.WithRouteParam("groupId", "5"), handlertest.WithRouteParam("attributeId", "11"),
				handlertest.WithForm(url.Values{"attributeKey": {"k"}, "attributeValue": {"v"}})),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
			// Every writer is admitted: which one a handler picks is pattern 7's decision and is
			// held by TestHandlers_AjaxHandlersDoNotUsePageWriters and the classifier guard, not
			// here. What this case needs is only that the handler answered rather than carrying on.
			httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Maybe()
			httpHelper.On("JsonError", mock.Anything, mock.Anything, mock.Anything).Maybe()
			httpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.Anything).Maybe()
			httpHelper.On("NotFound", mock.Anything, mock.Anything).Maybe()
			httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, mock.Anything,
				mock.Anything, mock.Anything).Return(nil).Maybe()

			apiClient := &groupCtxRecordingApiClient{}

			marked := testCase.request.WithContext(
				context.WithValue(testCase.request.Context(), groupCtxMarkerKey{}, testCase.name))

			testCase.build(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(), marked)

			require.NotEmpty(t, apiClient.seen, "the handler must consult its API client")
			for i, seen := range apiClient.seen {
				assert.Equal(t, testCase.name, seen.Value(groupCtxMarkerKey{}),
					"call %d carried a context that is not the request's", i)
			}
		})
	}
}
