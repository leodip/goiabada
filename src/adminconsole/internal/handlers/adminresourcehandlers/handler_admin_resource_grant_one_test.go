package adminresourcehandlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/core/api"
)

// grantOneApiClient answers the reads the four grant-one handlers make, holding the user's or
// group's current grants, and records the save each hands the API.
type grantOneApiClient struct {
	current   []api.PermissionResponse
	sentUser  *api.UpdateUserPermissionsRequest
	sentGroup *api.UpdateGroupPermissionsRequest
}

func (c *grantOneApiClient) GetResourceById(_ context.Context, _ string, resourceId int64) (*api.ResourceResponse, error) {
	return &api.ResourceResponse{Id: resourceId, ResourceIdentifier: "some-resource"}, nil
}

func (c *grantOneApiClient) GetPermissionsByResource(_ context.Context, _ string, _ int64) ([]api.PermissionResponse, error) {
	return []api.PermissionResponse{{Id: 7, PermissionIdentifier: "read"}}, nil
}

func (c *grantOneApiClient) GetUserPermissions(_ context.Context, _ string, userId int64) (*api.UserResponse, []api.PermissionResponse, error) {
	return &api.UserResponse{Id: userId}, c.current, nil
}

func (c *grantOneApiClient) GetGroupPermissions(_ context.Context, _ string, groupId int64) (*api.GroupResponse, []api.PermissionResponse, error) {
	return &api.GroupResponse{Id: groupId}, c.current, nil
}

func (c *grantOneApiClient) UpdateUserPermissions(_ context.Context, _ string, _ int64, request *api.UpdateUserPermissionsRequest) error {
	c.sentUser = request
	return nil
}

func (c *grantOneApiClient) UpdateGroupPermissions(_ context.Context, _ string, _ int64, request *api.UpdateGroupPermissionsRequest) error {
	c.sentGroup = request
	return nil
}

// The rest of the ports grantOneApiClient is passed to, which no test here reaches.

func (*grantOneApiClient) GetAllGroups(context.Context, string) ([]api.GroupResponse, error) {
	panic("unexpected call to GetAllGroups")
}

func (*grantOneApiClient) GetUsersByPermission(context.Context, string, int64, int, int) ([]api.UserResponse, int, error) {
	panic("unexpected call to GetUsersByPermission")
}

func (*grantOneApiClient) SearchGroupsWithPermissionAnnotation(context.Context, string, int64, int, int) ([]api.GroupWithPermissionResponse, int, error) {
	panic("unexpected call to SearchGroupsWithPermissionAnnotation")
}

func (*grantOneApiClient) SearchUsersWithPermissionAnnotation(context.Context, string, int64, string, int, int) ([]api.UserWithPermissionResponse, int, error) {
	panic("unexpected call to SearchUsersWithPermissionAnnotation")
}

// The resource pages grant or revoke one permission by reading the user's or group's grants,
// changing one, and saving the whole set. The save carries the set it read as the loaded one, so
// the auth server refuses it with 409 when another save changed the grants in between, where
// writing the whole set would undo that change (#428). A read with no grants is sent as [], not the
// null the save refuses.
func TestResourceGrantOneHandlers_SendTheGrantsTheyRead(t *testing.T) {
	testCases := []struct {
		name         string
		target       string
		build        func(httpHelper *render.Renderer, apiClient *grantOneApiClient) http.HandlerFunc
		current      []api.PermissionResponse
		group        bool
		wantWanted   []int64
		wantExpected []int64
	}{
		{
			name:   "revoking from a user",
			target: "/admin/resources/2/users-with-permission/remove/5/7",
			build: func(h *render.Renderer, c *grantOneApiClient) http.HandlerFunc {
				return HandleUsersWithPermissionRemovePermissionPost(h, c)
			},
			current:      []api.PermissionResponse{{Id: 3}, {Id: 7}},
			wantWanted:   []int64{3},
			wantExpected: []int64{3, 7},
		},
		{
			name:   "granting to a user with no grants",
			target: "/admin/resources/2/users-with-permission/add/5/7",
			build: func(h *render.Renderer, c *grantOneApiClient) http.HandlerFunc {
				return HandleUsersWithPermissionAddPermissionPost(h, c)
			},
			current:      nil,
			wantWanted:   []int64{7},
			wantExpected: []int64{},
		},
		{
			name:   "revoking from a group",
			target: "/admin/resources/2/groups-with-permission/remove/5/7",
			build: func(h *render.Renderer, c *grantOneApiClient) http.HandlerFunc {
				return HandleGroupsWithPermissionRemovePermissionPost(h, c)
			},
			current:      []api.PermissionResponse{{Id: 7}, {Id: 3}},
			group:        true,
			wantWanted:   []int64{3},
			wantExpected: []int64{7, 3},
		},
		{
			name:   "granting to a group with no grants",
			target: "/admin/resources/2/groups-with-permission/add/5/7",
			build: func(h *render.Renderer, c *grantOneApiClient) http.HandlerFunc {
				return HandleGroupsWithPermissionAddPermissionPost(h, c)
			},
			current:      nil,
			group:        true,
			wantWanted:   []int64{7},
			wantExpected: []int64{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := render.New(nil, nil)
			apiClient := &grantOneApiClient{current: tc.current}
			// Every target names resource 2, subject 5 and permission 7, which are the path values
			// the route binds from it.
			subject := "userId"
			if tc.group {
				subject = "groupId"
			}
			rec := httptest.NewRecorder()
			tc.build(httpHelper, apiClient).ServeHTTP(rec, handlertest.Request(http.MethodPost, tc.target,
				handlertest.WithAccessToken(),
				handlertest.WithPathValue("resourceId", "2"),
				handlertest.WithPathValue(subject, "5"),
				handlertest.WithPathValue("permissionId", "7")))

			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			var wanted, expected []int64
			var sent any
			if tc.group {
				require.NotNil(t, apiClient.sentGroup)
				wanted, expected, sent = apiClient.sentGroup.PermissionIds, apiClient.sentGroup.ExpectedPermissionIds, apiClient.sentGroup
			} else {
				require.NotNil(t, apiClient.sentUser)
				wanted, expected, sent = apiClient.sentUser.PermissionIds, apiClient.sentUser.ExpectedPermissionIds, apiClient.sentUser
			}
			assert.Equal(t, tc.wantWanted, wanted)
			assert.Equal(t, tc.wantExpected, expected)
			if len(tc.wantExpected) == 0 {
				wire, err := json.Marshal(sent)
				require.NoError(t, err)
				assert.Contains(t, string(wire), `"expectedPermissionIds":[]`)
			}
		})
	}
}
