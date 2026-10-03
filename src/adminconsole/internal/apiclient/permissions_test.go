package apiclient

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// permissionBodyFields is one permission, carrying the resource it belongs to, which is
// resources_test.go's resourceBodyFields: the permission family decodes the resource family's
// shape in the nested position, so both read the same bytes (#350).
const permissionBodyFields = `"id":9,"permissionIdentifier":"read","description":"Read it",` +
	`"resourceId":2,"resource":{` + resourceBodyFields + `}`

// The permission methods all decode the same nested shape, and every one of them carried its own
// copy of the rebuild loop. The nested resource is what the loops truncated hardest: they copied
// three of its fields and dropped the flag, so a permission's resource arrived looking ordinary
// however the server had described it.
func TestAuthServerClient_GetPermissionsByResourceDecodesTheNestedResource(t *testing.T) {
	client, recorded := serves(t, `{"permissions":[{`+permissionBodyFields+`}]}`)

	permissions, err := client.GetPermissionsByResource(context.Background(), "an-access-token", 2)
	require.NoError(t, err)

	gotPath, _ := recorded()
	assert.Equal(t, "/api/v1/admin/resources/2/permissions", gotPath)

	require.Len(t, permissions, 1)
	assert.Equal(t, int64(9), permissions[0].Id)
	assert.Equal(t, "read", permissions[0].PermissionIdentifier)
	assert.Equal(t, "Read it", permissions[0].Description)
	assert.Equal(t, int64(2), permissions[0].ResourceId)
	assert.Equal(t, "api", permissions[0].Resource.ResourceIdentifier)
	assert.True(t, permissions[0].Resource.IsSystemLevelResource,
		"the flag survives the nested position too, which the rebuild loop could not carry at all")
}

func TestAuthServerClient_GetUserPermissionsReturnsTheUserBesideThePermissions(t *testing.T) {
	client, recorded := serves(t, `{"user":{"id":42,"username":"jdoe"},`+
		`"permissions":[{`+permissionBodyFields+`}]}`)

	user, permissions, err := client.GetUserPermissions(context.Background(), "an-access-token", 42)
	require.NoError(t, err)
	require.NotNil(t, user)

	gotPath, _ := recorded()
	assert.Equal(t, "/api/v1/admin/users/42/permissions", gotPath)

	assert.Equal(t, int64(42), user.Id)
	assert.Equal(t, "jdoe", user.Username)
	require.Len(t, permissions, 1)
	assert.Equal(t, "read", permissions[0].PermissionIdentifier)
}
