package apiclient

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Seam 2 for the group family (#350).
//
// The console used to decode api.GroupResponse and rebuild a models.Group from it, field by field,
// in six methods. It hands the decoded response to the handlers now, so the decode is the only
// place a renamed json tag is still invisible. The bodies below are therefore written as literal
// JSON text rather than marshalled from the struct they check: a body produced by the same tags it
// is meant to hold proves nothing.
//
// serves lives in user_client_test.go.
const groupBodyFields = `
	"id": 4,
	"createdAt": "2026-01-02T03:04:05Z",
	"updatedAt": null,
	"groupIdentifier": "admins",
	"description": "Administrators",
	"includeInIdToken": true,
	"includeInAccessToken": false,
	"memberCount": 17`

// The member count used to arrive as a second return value beside a models.Group that did not
// carry one. It is a field on the response now, filled by the same handler from the same query, so
// a method that answered the group but dropped the count would leave the delete confirmation
// offering to delete a group it says has no members.
func TestAuthServerClient_GetGroupByIdDecodesEveryFieldTheGroupPagesBind(t *testing.T) {
	client, recorded := serves(t, `{"group":{`+groupBodyFields+`}}`)

	group, err := client.GetGroupById(context.Background(), "an-access-token", 4)
	require.NoError(t, err)
	require.NotNil(t, group)

	gotPath, gotAuthorization := recorded()
	assert.Equal(t, "/api/v1/admin/groups/4", gotPath)
	assert.Equal(t, "Bearer an-access-token", gotAuthorization)

	assert.Equal(t, int64(4), group.Id)
	assert.Equal(t, "admins", group.GroupIdentifier)
	assert.Equal(t, "Administrators", group.Description)
	assert.True(t, group.IncludeInIdToken)
	assert.False(t, group.IncludeInAccessToken)
	assert.Equal(t, 17, group.MemberCount, "the member count is a field on the group, not a return beside it")

	require.NotNil(t, group.CreatedAt, "a present timestamp must arrive as a time, not as nil")
	assert.Equal(t, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), group.CreatedAt.UTC())
	assert.Nil(t, group.UpdatedAt, "a null timestamp must arrive as nil rather than as a zero time")
}

// The list behind /admin/groups, whose members column is per row: a decode that filled the count
// from the wrong row, or from nothing, is invisible in a one-row fixture.
func TestAuthServerClient_GetAllGroupsDecodesEachRowsMemberCount(t *testing.T) {
	client, recorded := serves(t, `{"groups":[{`+groupBodyFields+`},`+
		`{"id":5,"groupIdentifier":"site-viewers","description":"Viewers","memberCount":3}]}`)

	groups, err := client.GetAllGroups(context.Background(), "an-access-token")
	require.NoError(t, err)

	gotPath, _ := recorded()
	assert.Equal(t, "/api/v1/admin/groups", gotPath)

	require.Len(t, groups, 2)
	assert.Equal(t, "admins", groups[0].GroupIdentifier)
	assert.Equal(t, 17, groups[0].MemberCount)
	assert.Equal(t, int64(5), groups[1].Id)
	assert.Equal(t, "site-viewers", groups[1].GroupIdentifier)
	assert.Equal(t, "Viewers", groups[1].Description)
	assert.Equal(t, 3, groups[1].MemberCount)
}

// One body carries the user and the memberships, and both halves are bound: the user by the page's
// title, the groups by its list. UpdateUserGroups decodes the same shape from the PUT.
func TestAuthServerClient_GetUserGroupsReturnsTheUserAndTheMemberships(t *testing.T) {
	client, recorded := serves(t, `{"user":{"id":42,"email":"jane@example.com"},"groups":[{`+groupBodyFields+`}]}`)

	user, groups, err := client.GetUserGroups(context.Background(), "an-access-token", 42)
	require.NoError(t, err)

	gotPath, _ := recorded()
	assert.Equal(t, "/api/v1/admin/users/42/groups", gotPath)

	require.NotNil(t, user)
	assert.Equal(t, int64(42), user.Id)
	assert.Equal(t, "jane@example.com", user.Email)

	require.Len(t, groups, 1)
	assert.Equal(t, int64(4), groups[0].Id)
	assert.Equal(t, "admins", groups[0].GroupIdentifier)
}

func TestAuthServerClient_UpdateUserGroupsReturnsTheMembershipsItSaved(t *testing.T) {
	client, recorded := serves(t, `{"user":{"id":42,"email":"jane@example.com"},"groups":[{`+groupBodyFields+`}]}`)

	user, groups, err := client.UpdateUserGroups(context.Background(), "an-access-token", 42, nil)
	require.NoError(t, err)

	gotPath, _ := recorded()
	assert.Equal(t, "/api/v1/admin/users/42/groups", gotPath)

	require.NotNil(t, user)
	assert.Equal(t, int64(42), user.Id)
	require.Len(t, groups, 1)
	assert.Equal(t, "admins", groups[0].GroupIdentifier)
}

// CreateGroup and UpdateGroup both answer the saved group, and both feed a redirect rather than a
// page, so the id is the field that matters: a decode that lost it sends the administrator to
// /admin/groups/0/settings.
func TestAuthServerClient_CreateAndUpdateGroupReturnTheSavedGroup(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		client, recorded := servesStatus(t, http.StatusCreated, `{"group":{`+groupBodyFields+`}}`)

		group, err := client.CreateGroup(context.Background(), "an-access-token", nil)
		require.NoError(t, err)
		require.NotNil(t, group)

		gotPath, _ := recorded()
		assert.Equal(t, "/api/v1/admin/groups", gotPath)
		assert.Equal(t, int64(4), group.Id)
		assert.Equal(t, "admins", group.GroupIdentifier)
	})

	t.Run("update", func(t *testing.T) {
		client, recorded := serves(t, `{"group":{`+groupBodyFields+`}}`)

		group, err := client.UpdateGroup(context.Background(), "an-access-token", 4, nil)
		require.NoError(t, err)
		require.NotNil(t, group)

		gotPath, _ := recorded()
		assert.Equal(t, "/api/v1/admin/groups/4", gotPath)
		assert.Equal(t, int64(4), group.Id)
		assert.True(t, group.IncludeInIdToken)
		assert.False(t, group.IncludeInAccessToken)
	})
}

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
