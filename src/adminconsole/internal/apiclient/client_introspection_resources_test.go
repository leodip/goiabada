package apiclient

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthServerClient_GetClientIntrospectionResourcesReturnsTheClientBesideItsResources(t *testing.T) {
	client, recorded := serves(t, `{"client":{"id":7,"clientIdentifier":"orders-backend","isPublic":false},`+
		`"resources":[{`+resourceBodyFields+`}]}`)

	clientResp, resources, err := client.GetClientIntrospectionResources(context.Background(), "an-access-token", 7)
	require.NoError(t, err)
	require.NotNil(t, clientResp)

	gotPath, gotAuthorization := recorded()
	assert.Equal(t, "/api/v1/admin/clients/7/introspection-resources", gotPath)
	assert.Equal(t, "Bearer an-access-token", gotAuthorization)

	assert.Equal(t, int64(7), clientResp.Id)
	assert.Equal(t, "orders-backend", clientResp.ClientIdentifier)
	require.Len(t, resources, 1)
	assert.Equal(t, int64(2), resources[0].Id)
	assert.Equal(t, "api", resources[0].ResourceIdentifier)
}
