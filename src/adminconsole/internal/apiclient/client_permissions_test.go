package apiclient

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthServerClient_GetClientPermissionsReturnsTheClientBesideThePermissions(t *testing.T) {
	client, recorded := serves(t, `{"client":{"id":7,"clientIdentifier":"portal"},`+
		`"permissions":[{`+permissionBodyFields+`}]}`)

	clientResp, permissions, err := client.GetClientPermissions(context.Background(), "an-access-token", 7)
	require.NoError(t, err)
	require.NotNil(t, clientResp)

	gotPath, _ := recorded()
	assert.Equal(t, "/api/v1/admin/clients/7/permissions", gotPath)

	assert.Equal(t, int64(7), clientResp.Id)
	assert.Equal(t, "portal", clientResp.ClientIdentifier)
	require.Len(t, permissions, 1)
	assert.Equal(t, int64(9), permissions[0].Id)
}
