package adminresourcehandlers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
)

// The users and the groups page of the authserver resource list the permissions the API returned,
// as returned. Both pages used to drop the userinfo permission from that list, and six more
// handlers beside them did the same before acting on it; nothing on the sign-in path read the row,
// and it is gone since #449, so the console has no permission to hide. A permission an
// administrator creates with that identifier is an ordinary one, and is listed first here because
// it is also the one each page selects when none is asked for.

// systemResourceApiClient is resourcePagingApiClient answering for the authserver resource.
type systemResourceApiClient struct {
	resourcePagingApiClient
}

func (c *systemResourceApiClient) GetResourceById(_ context.Context, accessToken string, resourceId int64) (*api.ResourceResponse, error) {
	return &api.ResourceResponse{Id: resourceId, ResourceIdentifier: builtin.AuthServerResourceIdentifier}, nil
}

// The rest of the ports systemResourceApiClient is passed to, which no test here reaches.

func (*systemResourceApiClient) GetGroupPermissions(context.Context, string, int64) (*api.GroupResponse, []api.PermissionResponse, error) {
	panic("unexpected call to GetGroupPermissions")
}

func (*systemResourceApiClient) GetUserPermissions(context.Context, string, int64) (*api.UserResponse, []api.PermissionResponse, error) {
	panic("unexpected call to GetUserPermissions")
}

func (*systemResourceApiClient) SearchUsersWithPermissionAnnotation(context.Context, string, int64, string, int, int) ([]api.UserWithPermissionResponse, int, error) {
	panic("unexpected call to SearchUsersWithPermissionAnnotation")
}

func (*systemResourceApiClient) UpdateGroupPermissions(context.Context, string, int64, *api.UpdateGroupPermissionsRequest) error {
	panic("unexpected call to UpdateGroupPermissions")
}

func (*systemResourceApiClient) UpdateUserPermissions(context.Context, string, int64, *api.UpdateUserPermissionsRequest) error {
	panic("unexpected call to UpdateUserPermissions")
}

func systemResourcePermissions() []api.PermissionResponse {
	system := api.ResourceResponse{Id: 7, ResourceIdentifier: builtin.AuthServerResourceIdentifier}
	return []api.PermissionResponse{
		{Id: 41, PermissionIdentifier: "userinfo", Resource: system},
		{Id: 42, PermissionIdentifier: builtin.ManagePermissionIdentifier, Resource: system},
	}
}

func TestHandleAdminResourceUsersWithPermissionGet_TheSystemResourceListsWhatTheApiReturned(t *testing.T) {
	apiClient := &systemResourceApiClient{resourcePagingApiClient{permissions: systemResourcePermissions()}}

	httpHelper := newHelper(t)
	bind := renderPermissionPage(t, HandleAdminResourceUsersWithPermissionGet(httpHelper, testStore(), apiClient), "users-with-permission", "", httpHelper)

	assert.Equal(t, systemResourcePermissions(), bind["permissions"])
	assert.Equal(t, int64(41), bind["selectedPermission"])
}

func TestHandleAdminResourceGroupsWithPermissionGet_TheSystemResourceListsWhatTheApiReturned(t *testing.T) {
	apiClient := &systemResourceApiClient{resourcePagingApiClient{permissions: systemResourcePermissions()}}

	httpHelper := newHelper(t)
	bind := renderPermissionPage(t, HandleAdminResourceGroupsWithPermissionGet(httpHelper, testStore(), apiClient), "groups-with-permission", "", httpHelper)

	assert.Equal(t, systemResourcePermissions(), bind["permissions"])
	assert.Equal(t, int64(41), bind["selectedPermission"])
}
