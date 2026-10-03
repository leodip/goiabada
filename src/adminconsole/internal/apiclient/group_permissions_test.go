package apiclient

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Both halves are the wire response now, the group family's and the permission family's. Both are
// read here, so a change to either side that drops the other is caught.
func TestAuthServerClient_GetGroupPermissionsReturnsTheGroupBesideThePermissions(t *testing.T) {
	client, recorded := serves(t, `{"group":{`+groupBodyFields+`},"permissions":[{"id":9,`+
		`"permissionIdentifier":"read","description":"Read","resourceId":2,`+
		`"resource":{"id":2,"resourceIdentifier":"api","description":"The API"}}]}`)

	group, permissions, err := client.GetGroupPermissions(context.Background(), "an-access-token", 4)
	require.NoError(t, err)
	require.NotNil(t, group)

	gotPath, _ := recorded()
	assert.Equal(t, "/api/v1/admin/groups/4/permissions", gotPath)

	assert.Equal(t, int64(4), group.Id)
	assert.Equal(t, "admins", group.GroupIdentifier)

	require.Len(t, permissions, 1)
	assert.Equal(t, int64(9), permissions[0].Id)
	assert.Equal(t, "read", permissions[0].PermissionIdentifier)
	assert.Equal(t, "api", permissions[0].Resource.ResourceIdentifier)
}
