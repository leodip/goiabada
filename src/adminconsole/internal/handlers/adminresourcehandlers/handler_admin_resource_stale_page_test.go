package adminresourcehandlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/logging/logtest"
)

// stalePageApiClient is grantOneApiClient, whose resource holds permission 7 alone, with the
// permissions save recorded too, so every case below can say nothing was written.
type stalePageApiClient struct {
	grantOneApiClient
	sentPermissions *api.UpdateResourcePermissionsRequest
}

func (c *stalePageApiClient) UpdateResourcePermissions(_ context.Context, _ string, _ int64, request *api.UpdateResourcePermissionsRequest) error {
	c.sentPermissions = request
	return nil
}

// The rest of the ports stalePageApiClient is passed to, which no test here reaches.

func (*stalePageApiClient) GetAllGroups(context.Context, string) ([]api.GroupResponse, error) {
	panic("unexpected call to GetAllGroups")
}

func (*stalePageApiClient) GetUsersByPermission(context.Context, string, int64, int, int) ([]api.UserResponse, int, error) {
	panic("unexpected call to GetUsersByPermission")
}

func (*stalePageApiClient) SearchGroupsWithPermissionAnnotation(context.Context, string, int64, int, int) ([]api.GroupWithPermissionResponse, int, error) {
	panic("unexpected call to SearchGroupsWithPermissionAnnotation")
}

func (*stalePageApiClient) SearchUsersWithPermissionAnnotation(context.Context, string, int64, string, int, int) ([]api.UserWithPermissionResponse, int, error) {
	panic("unexpected call to SearchUsersWithPermissionAnnotation")
}

// A click on a page loaded before another administrator's change is not a server fault, and is
// no longer answered as one with a stack in the log (#440 decision 6):
//
//   - a permission the resource no longer holds names nothing here: 404, as JSONNotFound answers
//     every such id;
//   - granting what the user or group already holds, or revoking what it no longer holds, is
//     another administrator's change winning between the load and the click: 409, the answer the
//     auth server's own list saves give the same race (#428);
//   - a permissions save whose body names another resource than its URL is a body the console's
//     own script never sends: 400.
//
// The real writer, because the claim is the answer on the wire and the log it does not leave.
func TestAdminResourceHandlers_AStalePageIsAnsweredWithoutAServerFault(t *testing.T) {
	grantRoute := func(subject, permissionId string) []handlertest.Option {
		return []handlertest.Option{
			handlertest.WithAccessToken(),
			handlertest.WithRouteParam("resourceId", "2"),
			handlertest.WithRouteParam(subject, "5"),
			handlertest.WithRouteParam("permissionId", permissionId),
		}
	}

	type build func(h *render.Renderer, c *stalePageApiClient) http.HandlerFunc
	usersAdd := func(h *render.Renderer, c *stalePageApiClient) http.HandlerFunc {
		return HandleAdminResourceUsersWithPermissionAddPermissionPost(h, c)
	}
	usersRemove := func(h *render.Renderer, c *stalePageApiClient) http.HandlerFunc {
		return HandleAdminResourceUsersWithPermissionRemovePermissionPost(h, c)
	}
	groupsAdd := func(h *render.Renderer, c *stalePageApiClient) http.HandlerFunc {
		return HandleAdminResourceGroupsWithPermissionAddPermissionPost(h, c)
	}
	groupsRemove := func(h *render.Renderer, c *stalePageApiClient) http.HandlerFunc {
		return HandleAdminResourceGroupsWithPermissionRemovePermissionPost(h, c)
	}

	testCases := []struct {
		name       string
		build      build
		current    []api.PermissionResponse
		options    []handlertest.Option
		wantStatus int
		wantCode   string
	}{
		{
			name: "granting a user a permission the resource no longer holds", build: usersAdd,
			options:    grantRoute("userId", "9"),
			wantStatus: http.StatusNotFound, wantCode: "not_found",
		},
		{
			name: "revoking from a user a permission the resource no longer holds", build: usersRemove,
			current:    []api.PermissionResponse{{Id: 9}},
			options:    grantRoute("userId", "9"),
			wantStatus: http.StatusNotFound, wantCode: "not_found",
		},
		{
			name: "granting a group a permission the resource no longer holds", build: groupsAdd,
			options:    grantRoute("groupId", "9"),
			wantStatus: http.StatusNotFound, wantCode: "not_found",
		},
		{
			name: "revoking from a group a permission the resource no longer holds", build: groupsRemove,
			current:    []api.PermissionResponse{{Id: 9}},
			options:    grantRoute("groupId", "9"),
			wantStatus: http.StatusNotFound, wantCode: "not_found",
		},
		{
			name: "granting a user a permission it already holds", build: usersAdd,
			current:    []api.PermissionResponse{{Id: 3}, {Id: 7}},
			options:    grantRoute("userId", "7"),
			wantStatus: http.StatusConflict, wantCode: "concurrent_update",
		},
		{
			name: "revoking from a user a permission it no longer holds", build: usersRemove,
			current:    []api.PermissionResponse{{Id: 3}},
			options:    grantRoute("userId", "7"),
			wantStatus: http.StatusConflict, wantCode: "concurrent_update",
		},
		{
			name: "granting a group a permission it already holds", build: groupsAdd,
			current:    []api.PermissionResponse{{Id: 7}},
			options:    grantRoute("groupId", "7"),
			wantStatus: http.StatusConflict, wantCode: "concurrent_update",
		},
		{
			name: "revoking from a group a permission it no longer holds", build: groupsRemove,
			current:    nil,
			options:    grantRoute("groupId", "7"),
			wantStatus: http.StatusConflict, wantCode: "concurrent_update",
		},
		{
			name: "saving permissions with a body naming another resource",
			build: func(h *render.Renderer, c *stalePageApiClient) http.HandlerFunc {
				return HandleAdminResourcePermissionsPost(h, testStore(), c)
			},
			options: []handlertest.Option{
				handlertest.WithAccessToken(),
				handlertest.WithRouteParam("resourceId", "2"),
				handlertest.WithBody(strings.NewReader(
					`{"resourceId":3,"permissions":[],"expectedPermissions":[]}`)),
				handlertest.WithContentType("application/json"),
			},
			wantStatus: http.StatusBadRequest, wantCode: "invalid_request_body",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logs := logtest.CaptureSlog(t)
			apiClient := &stalePageApiClient{grantOneApiClient: grantOneApiClient{current: tc.current}}

			recorder := httptest.NewRecorder()
			tc.build(render.New(fstest.MapFS{}), apiClient).ServeHTTP(recorder,
				handlertest.Request(http.MethodPost, "/admin/resources/2", tc.options...))

			assert.Equal(t, tc.wantStatus, recorder.Code, recorder.Body.String())
			var body map[string]string
			require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
			assert.Equal(t, tc.wantCode, body["error"])
			assert.NotEmpty(t, body["error_description"])
			assert.Nil(t, apiClient.sentUser, "nothing is saved")
			assert.Nil(t, apiClient.sentGroup, "nothing is saved")
			assert.Nil(t, apiClient.sentPermissions, "nothing is saved")
			assert.Empty(t, logs.Records(), "a stale page is not a server fault")
		})
	}
}
