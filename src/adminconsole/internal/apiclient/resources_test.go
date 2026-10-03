package apiclient

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The resource family's decode half, and with permissions_test.go, client_permissions_test.go and
// group_permissions_test.go the permission family's. Every method of both used to rebuild the
// response into a models.Permission or a models.Resource, field by field, and each rebuild was a
// list of the fields somebody remembered: a field added to the response and forgotten in the loop
// reached the handlers as its zero value with nothing going red. They hand the decoded response
// back now, so this is the seam where the console's view of a resource is pinned (#350).
//
// The bodies are the bytes the auth server writes, which apimapping's literal-JSON tables own on
// the other side of the wire. Written out here rather than shared with them, because a constant
// two modules edit together would let a shape change pass both.

// resourceBodyFields is one resource, lowerCamelCase, including the flag decision 10 put on the
// wire. The rebuild could not carry it at all: models.Resource has no such field, only a method.
const resourceBodyFields = `"id":2,"resourceIdentifier":"api","description":"The API",` +
	`"isSystemLevelResource":true`

func TestAuthServerClient_GetResourceByIdDecodesEveryFieldTheConsoleBinds(t *testing.T) {
	client, recorded := serves(t, `{"resource":{`+resourceBodyFields+`}}`)

	resource, err := client.GetResourceById(context.Background(), "an-access-token", 2)
	require.NoError(t, err)
	require.NotNil(t, resource)

	gotPath, gotAuthorization := recorded()
	assert.Equal(t, "/api/v1/admin/resources/2", gotPath)
	assert.Equal(t, "Bearer an-access-token", gotAuthorization)

	assert.Equal(t, int64(2), resource.Id)
	assert.Equal(t, "api", resource.ResourceIdentifier)
	assert.Equal(t, "The API", resource.Description)

	// Decision 10's console half. The five admin resource pages disable rename and delete on this
	// flag, and the API refuses both for the same reason; the flag reaching the console from the
	// server is what keeps the two from disagreeing. A console that recomputed the rule locally
	// would answer false for this identifier, because it is not the auth server's own.
	assert.True(t, resource.IsSystemLevelResource,
		"the system-level flag is the server's answer, not a rule the console reimplements")
}

func TestAuthServerClient_GetAllResourcesDecodesTheList(t *testing.T) {
	client, recorded := serves(t, `{"resources":[{`+resourceBodyFields+`},`+
		`{"id":3,"resourceIdentifier":"billing","description":"Billing","isSystemLevelResource":false}]}`)

	resources, err := client.GetAllResources(context.Background(), "an-access-token")
	require.NoError(t, err)

	gotPath, _ := recorded()
	assert.Equal(t, "/api/v1/admin/resources", gotPath)

	require.Len(t, resources, 2)
	assert.Equal(t, "api", resources[0].ResourceIdentifier)
	assert.True(t, resources[0].IsSystemLevelResource)
	assert.Equal(t, "billing", resources[1].ResourceIdentifier)
	assert.False(t, resources[1].IsSystemLevelResource,
		"a resource the server does not call system level must not be flagged as one")
}

func TestAuthServerClient_CreateResourceDecodesTheCreatedRow(t *testing.T) {
	client, recorded := servesStatus(t, http.StatusCreated, `{"resource":{`+resourceBodyFields+`}}`)

	resource, err := client.CreateResource(context.Background(), "an-access-token", nil)
	require.NoError(t, err)
	require.NotNil(t, resource)

	gotPath, _ := recorded()
	assert.Equal(t, "/api/v1/admin/resources", gotPath)
	assert.Equal(t, int64(2), resource.Id)
	assert.Equal(t, "api", resource.ResourceIdentifier)
}

func TestAuthServerClient_UpdateResourceDecodesTheUpdatedRow(t *testing.T) {
	client, recorded := serves(t, `{"resource":{`+resourceBodyFields+`}}`)

	resource, err := client.UpdateResource(context.Background(), "an-access-token", 2, nil)
	require.NoError(t, err)
	require.NotNil(t, resource)

	gotPath, _ := recorded()
	assert.Equal(t, "/api/v1/admin/resources/2", gotPath)
	assert.Equal(t, "The API", resource.Description)
}
