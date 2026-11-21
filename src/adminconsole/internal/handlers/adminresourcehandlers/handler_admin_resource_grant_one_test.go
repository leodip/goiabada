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

// grantOneAPIClient answers the reads the four grant-one handlers make, holding the user's or
// group's current grants, and records the save each hands the API.
type grantOneAPIClient struct {
	current   []api.PermissionResponse
	sentUser  *api.UpdateUserPermissionsRequest
	sentGroup *api.UpdateGroupPermissionsRequest
}

func (c *grantOneAPIClient) GetResourceByID(_ context.Context, _ string, resourceID int64) (*api.ResourceResponse, error) {
	return &api.ResourceResponse{ID: resourceID, ResourceIdentifier: "some-resource"}, nil
}

func (c *grantOneAPIClient) GetPermissionsByResource(_ context.Context, _ string, _ int64) ([]api.PermissionResponse, error) {
	return []api.PermissionResponse{{ID: 7, PermissionIdentifier: "read"}}, nil
}

func (c *grantOneAPIClient) GetUserPermissions(_ context.Context, _ string, userID int64) (*api.UserResponse, []api.PermissionResponse, error) {
	return &api.UserResponse{ID: userID}, c.current, nil
}

func (c *grantOneAPIClient) GetGroupPermissions(_ context.Context, _ string, groupID int64) (*api.GroupResponse, []api.PermissionResponse, error) {
	return &api.GroupResponse{ID: groupID}, c.current, nil
}

func (c *grantOneAPIClient) UpdateUserPermissions(_ context.Context, _ string, _ int64, request *api.UpdateUserPermissionsRequest) error {
	c.sentUser = request
	return nil
}

func (c *grantOneAPIClient) UpdateGroupPermissions(_ context.Context, _ string, _ int64, request *api.UpdateGroupPermissionsRequest) error {
	c.sentGroup = request
	return nil
}

// The rest of the ports grantOneAPIClient is passed to, which no test here reaches.

func (*grantOneAPIClient) GetAllGroups(context.Context, string) ([]api.GroupResponse, error) {
	panic("unexpected call to GetAllGroups")
}

func (*grantOneAPIClient) GetUsersByPermission(context.Context, string, int64, int, int) ([]api.UserResponse, int, error) {
	panic("unexpected call to GetUsersByPermission")
}

func (*grantOneAPIClient) SearchGroupsWithPermissionAnnotation(context.Context, string, int64, int, int) ([]api.GroupWithPermissionResponse, int, error) {
	panic("unexpected call to SearchGroupsWithPermissionAnnotation")
}

func (*grantOneAPIClient) SearchUsersWithPermissionAnnotation(context.Context, string, int64, string, int, int) ([]api.UserWithPermissionResponse, int, error) {
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
		build        func(httpHelper *render.Renderer, apiClient *grantOneAPIClient) http.HandlerFunc
		current      []api.PermissionResponse
		group        bool
		wantWanted   []int64
		wantExpected []int64
	}{
		{
			name:   "revoking from a user",
			target: "/admin/resources/2/users-with-permission/remove/5/7",
			build: func(h *render.Renderer, c *grantOneAPIClient) http.HandlerFunc {
				return HandleUsersWithPermissionRemovePermissionPost(h, c)
			},
			current:      []api.PermissionResponse{{ID: 3}, {ID: 7}},
			wantWanted:   []int64{3},
			wantExpected: []int64{3, 7},
		},
		{
			name:   "granting to a user with no grants",
			target: "/admin/resources/2/users-with-permission/add/5/7",
			build: func(h *render.Renderer, c *grantOneAPIClient) http.HandlerFunc {
				return HandleUsersWithPermissionAddPermissionPost(h, c)
			},
			current:      nil,
			wantWanted:   []int64{7},
			wantExpected: []int64{},
		},
		{
			name:   "revoking from a group",
			target: "/admin/resources/2/groups-with-permission/remove/5/7",
			build: func(h *render.Renderer, c *grantOneAPIClient) http.HandlerFunc {
				return HandleGroupsWithPermissionRemovePermissionPost(h, c)
			},
			current:      []api.PermissionResponse{{ID: 7}, {ID: 3}},
			group:        true,
			wantWanted:   []int64{3},
			wantExpected: []int64{7, 3},
		},
		{
			name:   "granting to a group with no grants",
			target: "/admin/resources/2/groups-with-permission/add/5/7",
			build: func(h *render.Renderer, c *grantOneAPIClient) http.HandlerFunc {
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
			apiClient := &grantOneAPIClient{current: tc.current}
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
				wanted, expected, sent = apiClient.sentGroup.PermissionIDs, apiClient.sentGroup.ExpectedPermissionIDs, apiClient.sentGroup
			} else {
				require.NotNil(t, apiClient.sentUser)
				wanted, expected, sent = apiClient.sentUser.PermissionIDs, apiClient.sentUser.ExpectedPermissionIDs, apiClient.sentUser
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
