package datatests

import (
	"context"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// deleteUserinfoPermission000050 is the version of the migration that deletes the authserver
// resource's userinfo permission and every grant of it (#449).
const deleteUserinfoPermission000050 = 50

// beforeDeleteUserinfoPermission000050 is the version below 000050 on the configured engine.
// SQLite carries no 000049, so it steps from 000048.
func beforeDeleteUserinfoPermission000050() int {
	if dbType() == "sqlite" {
		return 48
	}
	return 49
}

// userinfoDescription000050 is the description the seed gave the row until #449, which is what
// 000050's down restores it with.
const userinfoDescription000050 = "Access to the OpenID Connect user info endpoint"

// TestMigration000050_DeletesTheUserinfoPermissionAndItsGrants exercises the migration that removes
// the authserver resource's userinfo permission, against a REAL engine of the configured dialect.
// Nothing on the sign-in path read that row: /userinfo gates on the openid scope since #449, so a
// grant of it granted nothing, and the migration deletes the row with every user, group and client
// grant of it.
//
// The grants are deleted explicitly rather than left to the foreign keys' cascade, so the result
// does not depend on SQLite's foreign_keys pragma being on for the migration's connection; this
// test holds the three link tables to that on every engine.
//
// The properties, in order:
//
//  1. Up deletes the row and its three grants, and nothing else: a control permission on the
//     same resource, held by the same user, group and client, is untouched.
//  2. Down restores the row, with the seed's description, and none of its grants, which are
//     recorded nowhere else.
//  3. Up again deletes it again, which is what an operator who rolled back and retried does.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000050
func TestMigration000050_DeletesTheUserinfoPermissionAndItsGrants(t *testing.T) {
	h := newIsolatedDB(t)
	ctx := context.Background()
	before := beforeDeleteUserinfoPermission000050()

	require.NoErrorf(t, h.Migrator.Migrate(ctx, before), "migrate an empty database up to %d on %s", before, dbType())

	resource := &models.Resource{ResourceIdentifier: constants.AuthServerResourceIdentifier, Description: "Authorization server (system-level)"}
	require.NoError(t, h.DB.CreateResource(ctx, nil, resource))
	userinfo := &models.Permission{PermissionIdentifier: "userinfo", Description: userinfoDescription000050, ResourceId: resource.Id}
	require.NoError(t, h.DB.CreatePermission(ctx, nil, userinfo))
	control := &models.Permission{PermissionIdentifier: "mig50-control", Description: "Control", ResourceId: resource.Id}
	require.NoError(t, h.DB.CreatePermission(ctx, nil, control))

	user := &models.User{
		Enabled:      true,
		Subject:      "00000000-0000-0000-0000-000000050001",
		Username:     "mig50user",
		Email:        "mig50@example.com",
		PasswordHash: "not-a-real-hash",
	}
	require.NoError(t, h.DB.CreateUser(ctx, nil, user))
	group := &models.Group{GroupIdentifier: "mig50-group", Description: "Migration 000050 test group"}
	require.NoError(t, h.DB.CreateGroup(ctx, nil, group))
	client := &models.Client{ClientIdentifier: "mig50-client", Description: "Migration 000050 test client"}
	require.NoError(t, h.DB.CreateClient(ctx, nil, client))

	for _, permission := range []*models.Permission{userinfo, control} {
		require.NoError(t, h.DB.CreateUserPermission(ctx, nil, &models.UserPermission{UserId: user.Id, PermissionId: permission.Id}))
		require.NoError(t, h.DB.CreateGroupPermission(ctx, nil, &models.GroupPermission{GroupId: group.Id, PermissionId: permission.Id}))
		require.NoError(t, h.DB.CreateClientPermission(ctx, nil, &models.ClientPermission{ClientId: client.Id, PermissionId: permission.Id}))
	}

	// held reads the permission ids the user, the group and the client each hold.
	held := func() (userHolds, groupHolds, clientHolds []int64) {
		t.Helper()
		userPermissions, err := h.DB.GetUserPermissionsByUserId(ctx, nil, user.Id)
		require.NoError(t, err)
		for _, p := range userPermissions {
			userHolds = append(userHolds, p.PermissionId)
		}
		groupPermissions, err := h.DB.GetGroupPermissionsByGroupId(ctx, nil, group.Id)
		require.NoError(t, err)
		for _, p := range groupPermissions {
			groupHolds = append(groupHolds, p.PermissionId)
		}
		clientPermissions, err := h.DB.GetClientPermissionsByClientId(ctx, nil, client.Id)
		require.NoError(t, err)
		for _, p := range clientPermissions {
			clientHolds = append(clientHolds, p.PermissionId)
		}
		return userHolds, groupHolds, clientHolds
	}

	// identifiers reads the resource's permissions as identifier to description.
	identifiers := func() map[string]string {
		t.Helper()
		permissions, err := h.DB.GetPermissionsByResourceId(ctx, nil, resource.Id)
		require.NoError(t, err)
		out := map[string]string{}
		for _, p := range permissions {
			out[p.PermissionIdentifier] = p.Description
		}
		return out
	}

	userHolds, groupHolds, clientHolds := held()
	require.ElementsMatch(t, []int64{userinfo.Id, control.Id}, userHolds, "the fixture: the user holds both")
	require.ElementsMatch(t, []int64{userinfo.Id, control.Id}, groupHolds, "the fixture: the group holds both")
	require.ElementsMatch(t, []int64{userinfo.Id, control.Id}, clientHolds, "the fixture: the client holds both")

	require.NoErrorf(t, h.Migrator.Migrate(ctx, deleteUserinfoPermission000050), "apply 000050 on %s", dbType())

	// 1. The row and its three grants are gone; the control and its three are not.
	assert.Equalf(t, map[string]string{"mig50-control": "Control"}, identifiers(),
		"000050 must delete the userinfo permission and nothing else on the authserver resource on %s", dbType())
	userHolds, groupHolds, clientHolds = held()
	assert.Equalf(t, []int64{control.Id}, userHolds, "000050 must delete the user's userinfo grant, and only it, on %s", dbType())
	assert.Equalf(t, []int64{control.Id}, groupHolds, "000050 must delete the group's userinfo grant, and only it, on %s", dbType())
	assert.Equalf(t, []int64{control.Id}, clientHolds, "000050 must delete the client's userinfo grant, and only it, on %s", dbType())

	// 2. Down restores the row with the seed's description, and no grant of it.
	require.NoErrorf(t, h.Migrator.Migrate(ctx, before), "roll back 000050 on %s", dbType())
	assert.Equalf(t, map[string]string{"mig50-control": "Control", "userinfo": userinfoDescription000050}, identifiers(),
		"000050's down must restore the userinfo row on the authserver resource on %s", dbType())
	userHolds, groupHolds, clientHolds = held()
	assert.Equal(t, []int64{control.Id}, userHolds, "the down restores no grant: they are recorded nowhere else")
	assert.Equal(t, []int64{control.Id}, groupHolds, "the down restores no grant: they are recorded nowhere else")
	assert.Equal(t, []int64{control.Id}, clientHolds, "the down restores no grant: they are recorded nowhere else")

	// 3. And forward again.
	require.NoErrorf(t, h.Migrator.Migrate(ctx, deleteUserinfoPermission000050), "re-apply 000050 on %s", dbType())
	assert.Equalf(t, map[string]string{"mig50-control": "Control"}, identifiers(),
		"000050 must be re-appliable after a down/up round trip on %s", dbType())
}

// TestMigration000050_AnEmptyDatabase holds both directions to a database with no authserver
// resource, which is every fresh installation before the seed runs: up has nothing to delete and
// down has nowhere to insert the row, and neither may fail or invent one.
func TestMigration000050_AnEmptyDatabase(t *testing.T) {
	h := newIsolatedDB(t)
	ctx := context.Background()

	require.NoErrorf(t, h.Migrator.Migrate(ctx, deleteUserinfoPermission000050), "migrate an empty database through 000050 on %s", dbType())
	resource, err := h.DB.GetResourceByResourceIdentifier(ctx, nil, constants.AuthServerResourceIdentifier)
	require.NoError(t, err)
	require.Nil(t, resource, "the chain creates no authserver resource; the seed does")

	countPermissions := func() int {
		t.Helper()
		var n int
		require.NoError(t, h.SQL.QueryRow("SELECT COUNT(*) FROM permissions").Scan(&n))
		return n
	}
	atHead := countPermissions()

	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeDeleteUserinfoPermission000050()), "roll back 000050 on an empty database on %s", dbType())
	assert.Equalf(t, atHead, countPermissions(),
		"000050's down must insert nothing when there is no authserver resource to hold the row on %s", dbType())
}
