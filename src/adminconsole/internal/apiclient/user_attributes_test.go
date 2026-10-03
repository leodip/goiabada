package apiclient

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A user attribute takes the same path and has the same exposure: four of its five fields are what
// the attributes page renders, and the fifth decides which token the value reaches.
func TestAuthServerClient_GetUserAttributesByUserIdDecodesTheAttributeShape(t *testing.T) {
	client, recorded := serves(t, `{"attributes":[{"id":7,"createdAt":"2026-01-02T03:04:05Z","updatedAt":null,`+
		`"key":"department","value":"engineering","includeInIdToken":true,"includeInAccessToken":false,"userId":42}]}`)

	attributes, err := client.GetUserAttributesByUserId(context.Background(), "an-access-token", 42)
	require.NoError(t, err)

	gotPath, _ := recorded()
	assert.Equal(t, "/api/v1/admin/users/42/attributes", gotPath)

	require.Len(t, attributes, 1)
	assert.Equal(t, int64(7), attributes[0].Id)
	assert.Equal(t, "department", attributes[0].Key)
	assert.Equal(t, "engineering", attributes[0].Value)
	assert.True(t, attributes[0].IncludeInIdToken)
	assert.False(t, attributes[0].IncludeInAccessToken)
	assert.Equal(t, int64(42), attributes[0].UserId)
	require.NotNil(t, attributes[0].CreatedAt)
	assert.Equal(t, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), attributes[0].CreatedAt.UTC())
}
