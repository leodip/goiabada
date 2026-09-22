package apiclient

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Seam 2 for the group attribute family (#350). The same reasoning as group_client_test.go: the
// rebuild into models.GroupAttribute is gone, so the decode is where a renamed tag now hides, and
// the bodies are literal JSON text for that reason.
//
// groupId is the field with the least visible failure: the edit handler refuses an attribute whose
// groupId does not match the group in the URL, so a decode that lost it turns every edit into a
// 404 rather than into a blank field.
const groupAttributeBodyFields = `
	"id": 7,
	"createdAt": "2026-01-02T03:04:05Z",
	"updatedAt": null,
	"key": "tier",
	"value": "gold",
	"includeInIdToken": true,
	"includeInAccessToken": false,
	"groupId": 4`

func TestAuthServerClient_GetGroupAttributesByGroupIdDecodesTheAttributeShape(t *testing.T) {
	client, recorded := serves(t, `{"attributes":[{`+groupAttributeBodyFields+`},`+
		`{"id":8,"key":"region","value":"br","groupId":4}]}`)

	attributes, err := client.GetGroupAttributesByGroupId(context.Background(), "an-access-token", 4)
	require.NoError(t, err)

	gotPath, gotAuthorization := recorded()
	assert.Equal(t, "/api/v1/admin/groups/4/attributes", gotPath)
	assert.Equal(t, "Bearer an-access-token", gotAuthorization)

	require.Len(t, attributes, 2)
	assert.Equal(t, int64(7), attributes[0].Id)
	assert.Equal(t, "tier", attributes[0].Key)
	assert.Equal(t, "gold", attributes[0].Value)
	assert.True(t, attributes[0].IncludeInIdToken)
	assert.False(t, attributes[0].IncludeInAccessToken)
	assert.Equal(t, int64(4), attributes[0].GroupId)

	require.NotNil(t, attributes[0].CreatedAt)
	assert.Equal(t, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), attributes[0].CreatedAt.UTC())
	assert.Nil(t, attributes[0].UpdatedAt, "a null timestamp must arrive as nil rather than as a zero time")

	assert.Equal(t, int64(8), attributes[1].Id)
	assert.Equal(t, "region", attributes[1].Key)
}

func TestAuthServerClient_GetGroupAttributeByIdDecodesTheSingleAttribute(t *testing.T) {
	client, recorded := serves(t, `{"attribute":{`+groupAttributeBodyFields+`}}`)

	attribute, err := client.GetGroupAttributeById(context.Background(), "an-access-token", 7)
	require.NoError(t, err)
	require.NotNil(t, attribute)

	gotPath, _ := recorded()
	assert.Equal(t, "/api/v1/admin/group-attributes/7", gotPath)

	assert.Equal(t, int64(7), attribute.Id)
	assert.Equal(t, "tier", attribute.Key)
	assert.Equal(t, "gold", attribute.Value)
	assert.Equal(t, int64(4), attribute.GroupId,
		"the edit page compares this against the group in the URL before it renders anything")
}

// Both writes answer the saved attribute, which the handlers discard today; the decode is still
// what a later caller would read, and a method that returned nil on a 200 would be found only then.
func TestAuthServerClient_CreateAndUpdateGroupAttributeReturnTheSavedAttribute(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		client, recorded := servesStatus(t, http.StatusCreated, `{"attribute":{`+groupAttributeBodyFields+`}}`)

		attribute, err := client.CreateGroupAttribute(context.Background(), "an-access-token", nil)
		require.NoError(t, err)
		require.NotNil(t, attribute)

		gotPath, _ := recorded()
		assert.Equal(t, "/api/v1/admin/group-attributes", gotPath)
		assert.Equal(t, int64(7), attribute.Id)
		assert.Equal(t, "tier", attribute.Key)
	})

	t.Run("update", func(t *testing.T) {
		client, recorded := serves(t, `{"attribute":{`+groupAttributeBodyFields+`}}`)

		attribute, err := client.UpdateGroupAttribute(context.Background(), "an-access-token", 7, nil)
		require.NoError(t, err)
		require.NotNil(t, attribute)

		gotPath, _ := recorded()
		assert.Equal(t, "/api/v1/admin/group-attributes/7", gotPath)
		assert.Equal(t, "gold", attribute.Value)
		assert.Equal(t, int64(4), attribute.GroupId)
	})
}
