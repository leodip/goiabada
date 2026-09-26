package adminresourcehandlers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/leodip/goiabada/core/api"
	coreconstants "github.com/leodip/goiabada/core/constants"
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
	return &api.ResourceResponse{Id: resourceId, ResourceIdentifier: coreconstants.AuthServerResourceIdentifier}, nil
}

func systemResourcePermissions() []api.PermissionResponse {
	system := api.ResourceResponse{Id: 7, ResourceIdentifier: coreconstants.AuthServerResourceIdentifier}
	return []api.PermissionResponse{
		{Id: 41, PermissionIdentifier: "userinfo", Resource: system},
		{Id: 42, PermissionIdentifier: coreconstants.ManagePermissionIdentifier, Resource: system},
	}
}

func TestHandleAdminResourceUsersWithPermissionGet_TheSystemResourceListsWhatTheApiReturned(t *testing.T) {
	apiClient := &systemResourceApiClient{resourcePagingApiClient{permissions: systemResourcePermissions()}}

	httpHelper := newHelper(t)
	bind := render(t, HandleAdminResourceUsersWithPermissionGet(httpHelper, testStore(), apiClient), "users-with-permission", "", httpHelper)

	assert.Equal(t, systemResourcePermissions(), bind["permissions"])
	assert.Equal(t, int64(41), bind["selectedPermission"])
}

func TestHandleAdminResourceGroupsWithPermissionGet_TheSystemResourceListsWhatTheApiReturned(t *testing.T) {
	apiClient := &systemResourceApiClient{resourcePagingApiClient{permissions: systemResourcePermissions()}}

	httpHelper := newHelper(t)
	bind := render(t, HandleAdminResourceGroupsWithPermissionGet(httpHelper, testStore(), apiClient), "groups-with-permission", "", httpHelper)

	assert.Equal(t, systemResourcePermissions(), bind["permissions"])
	assert.Equal(t, int64(41), bind["selectedPermission"])
}
