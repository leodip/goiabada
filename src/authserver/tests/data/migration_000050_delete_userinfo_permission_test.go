package datatests

import (
	"context"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// deleteUserinfoPermission000050 is the version of the migration that deletes the authserver
// resource's userinfo permission and every grant of it (#449).
const deleteUserinfoPermission000050 = 50

// beforeDeleteUserinfoPermission000050 is the version below 000050 on the configured engine.
// SQLite carries no 000049, so it steps from 000048.
func beforeDeleteUserinfoPermission000050() int {
	if dbType() == data.SQLite {
		return 48
	}
	return 49
}

// userinfoDescription000050 is the description the seed gave the row until #449, which is what
// 000050's down restores it with.
const userinfoDescription000050 = "Access to the OpenID Connect user info endpoint"

// userinfoFixture000050 is a database at the version below 000050 holding the authserver resource,
// its userinfo permission and a control permission beside it, each granted to one user, one group
// and one client.
type userinfoFixture000050 struct {
	h        *isolatedDB
	resource *record.Resource
	userinfo *record.Permission
	control  *record.Permission
	user     *record.User
	group    *record.Group
	client   *record.Client
}

// seedUserinfoFixture000050 migrates a fresh database to the version below 000050 and writes the
// fixture into it.
func seedUserinfoFixture000050(t *testing.T, h *isolatedDB) *userinfoFixture000050 {
	t.Helper()
	ctx := context.Background()
	before := beforeDeleteUserinfoPermission000050()

	require.NoErrorf(t, h.Migrator.Migrate(ctx, before), "migrate an empty database up to %d on %s", before, dbType())

	f := &userinfoFixture000050{h: h}
	f.resource = &record.Resource{ResourceIdentifier: builtin.AuthServerResourceIdentifier, Description: "Authorization server (system-level)"}
	require.NoError(t, h.DB.CreateResource(ctx, nil, f.resource))
	f.userinfo = &record.Permission{PermissionIdentifier: "userinfo", Description: userinfoDescription000050, ResourceId: f.resource.Id}
	require.NoError(t, h.DB.CreatePermission(ctx, nil, f.userinfo))
	f.control = &record.Permission{PermissionIdentifier: "mig50-control", Description: "Control", ResourceId: f.resource.Id}
	require.NoError(t, h.DB.CreatePermission(ctx, nil, f.control))

	f.user = &record.User{
		Enabled:      true,
		Subject:      "00000000-0000-0000-0000-000000050001",
		Username:     "mig50user",
		Email:        "mig50@example.com",
		PasswordHash: "not-a-real-hash",
	}
	require.NoError(t, h.DB.CreateUser(ctx, nil, f.user))
	f.group = &record.Group{GroupIdentifier: "mig50-group", Description: "Migration 000050 test group"}
	require.NoError(t, h.DB.CreateGroup(ctx, nil, f.group))
	f.client = &record.Client{ClientIdentifier: "mig50-client", Description: "Migration 000050 test client"}
	require.NoError(t, h.DB.CreateClient(ctx, nil, f.client))

	for _, permission := range []*record.Permission{f.userinfo, f.control} {
		require.NoError(t, h.DB.CreateUserPermission(ctx, nil, &record.UserPermission{UserId: f.user.Id, PermissionId: permission.Id}))
		require.NoError(t, h.DB.CreateGroupPermission(ctx, nil, &record.GroupPermission{GroupId: f.group.Id, PermissionId: permission.Id}))
		require.NoError(t, h.DB.CreateClientPermission(ctx, nil, &record.ClientPermission{ClientId: f.client.Id, PermissionId: permission.Id}))
	}

	userHolds, groupHolds, clientHolds := f.held(t)
	require.ElementsMatch(t, []int64{f.userinfo.Id, f.control.Id}, userHolds, "the fixture: the user holds both")
	require.ElementsMatch(t, []int64{f.userinfo.Id, f.control.Id}, groupHolds, "the fixture: the group holds both")
	require.ElementsMatch(t, []int64{f.userinfo.Id, f.control.Id}, clientHolds, "the fixture: the client holds both")
	return f
}

// held reads the permission ids the user, the group and the client each hold, straight from the
// three link tables: none of the reads joins permissions, so a grant left behind by a deleted
// permission is still returned.
func (f *userinfoFixture000050) held(t *testing.T) (userHolds, groupHolds, clientHolds []int64) {
	t.Helper()
	ctx := context.Background()
	userPermissions, err := f.h.DB.GetUserPermissionsByUserId(ctx, nil, f.user.Id)
	require.NoError(t, err)
	for _, p := range userPermissions {
		userHolds = append(userHolds, p.PermissionId)
	}
	groupPermissions, err := f.h.DB.GetGroupPermissionsByGroupId(ctx, nil, f.group.Id)
	require.NoError(t, err)
	for _, p := range groupPermissions {
		groupHolds = append(groupHolds, p.PermissionId)
	}
	clientPermissions, err := f.h.DB.GetClientPermissionsByClientId(ctx, nil, f.client.Id)
	require.NoError(t, err)
	for _, p := range clientPermissions {
		clientHolds = append(clientHolds, p.PermissionId)
	}
	return userHolds, groupHolds, clientHolds
}

// identifiers reads the resource's permissions as identifier to description.
func (f *userinfoFixture000050) identifiers(t *testing.T) map[string]string {
	t.Helper()
	permissions, err := f.h.DB.GetPermissionsByResourceId(context.Background(), nil, f.resource.Id)
	require.NoError(t, err)
	out := map[string]string{}
	for _, p := range permissions {
		out[p.PermissionIdentifier] = p.Description
	}
	return out
}

// TestMigration000050_DeletesTheUserinfoPermissionAndItsGrants exercises the migration that removes
// the authserver resource's userinfo permission, against a REAL engine of the configured dialect.
// Nothing on the sign-in path read that row: /userinfo gates on the openid scope since #449, so a
// grant of it granted nothing, and the migration deletes the row with every user, group and client
// grant of it.
//
// Foreign keys are enforced here on every engine, so the link tables' ON DELETE CASCADE would take
// a grant with its permission even if the migration's own DELETE of it were missing. What holds
// those deletes is TestMigration000050_SQLiteWithForeignKeysOff.
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
	f := seedUserinfoFixture000050(t, h)

	require.NoErrorf(t, h.Migrator.Migrate(ctx, deleteUserinfoPermission000050), "apply 000050 on %s", dbType())

	// 1. The row and its three grants are gone; the control and its three are not.
	assert.Equalf(t, map[string]string{"mig50-control": "Control"}, f.identifiers(t),
		"000050 must delete the userinfo permission and nothing else on the authserver resource on %s", dbType())
	userHolds, groupHolds, clientHolds := f.held(t)
	assert.Equalf(t, []int64{f.control.Id}, userHolds, "000050 must delete the user's userinfo grant, and only it, on %s", dbType())
	assert.Equalf(t, []int64{f.control.Id}, groupHolds, "000050 must delete the group's userinfo grant, and only it, on %s", dbType())
	assert.Equalf(t, []int64{f.control.Id}, clientHolds, "000050 must delete the client's userinfo grant, and only it, on %s", dbType())

	// 2. Down restores the row with the seed's description, and no grant of it.
	require.NoErrorf(t, h.Migrator.Migrate(ctx, before), "roll back 000050 on %s", dbType())
	assert.Equalf(t, map[string]string{"mig50-control": "Control", "userinfo": userinfoDescription000050}, f.identifiers(t),
		"000050's down must restore the userinfo row on the authserver resource on %s", dbType())
	userHolds, groupHolds, clientHolds = f.held(t)
	assert.Equal(t, []int64{f.control.Id}, userHolds, "the down restores no grant: they are recorded nowhere else")
	assert.Equal(t, []int64{f.control.Id}, groupHolds, "the down restores no grant: they are recorded nowhere else")
	assert.Equal(t, []int64{f.control.Id}, clientHolds, "the down restores no grant: they are recorded nowhere else")

	// 3. And forward again.
	require.NoErrorf(t, h.Migrator.Migrate(ctx, deleteUserinfoPermission000050), "re-apply 000050 on %s", dbType())
	assert.Equalf(t, map[string]string{"mig50-control": "Control"}, f.identifiers(t),
		"000050 must be re-appliable after a down/up round trip on %s", dbType())
}

// TestMigration000050_SQLiteWithForeignKeysOff holds the migration's own grant deletes, which the
// case above cannot see. SQLite enforces a foreign key, and so runs its ON DELETE CASCADE, only on a
// connection that has run PRAGMA foreign_keys = ON. sqlitedb.New runs it on the one connection
// it keeps open, but a connection opened any other way starts with foreign keys off, and then
// deleting the permission leaves every grant of it behind, pointing at a row that no longer exists.
// 000050 deletes the grants itself so its result does not depend on which connection runs it
// (#449). Here the pragma is turned off on the migration's connection before 000050 runs, so each
// grant is gone afterwards only if its own DELETE removed it.
//
// The other three engines enforce the cascade on every connection the runner opens, so there the
// explicit deletes cannot be told apart from it and this case is SQLite's alone.
//
// Run via: ./run-tests.sh --type data --db sqlite --run TestMigration000050
func TestMigration000050_SQLiteWithForeignKeysOff(t *testing.T) {
	if dbType() != data.SQLite {
		t.Skipf("SQLite only: %s enforces the link tables' cascade on every connection", dbType())
	}
	h := newIsolatedDB(t)
	ctx := context.Background()
	f := seedUserinfoFixture000050(t, h)

	// foreignKeys reads the pragma on the pool's one connection, which sqlitedb.New caps the
	// pool at and keeps open, so it is the connection the migrator runs the file on.
	foreignKeys := func() int {
		t.Helper()
		var on int
		require.NoError(t, h.SQL.QueryRowContext(ctx, "PRAGMA foreign_keys;").Scan(&on))
		return on
	}
	_, err := h.SQL.ExecContext(ctx, "PRAGMA foreign_keys = OFF;")
	require.NoError(t, err)
	require.Equal(t, 0, foreignKeys(), "the fixture: foreign keys are off on the migration's connection")

	require.NoError(t, h.Migrator.Migrate(ctx, deleteUserinfoPermission000050), "apply 000050 with foreign keys off")
	require.Equal(t, 0, foreignKeys(), "000050 ran on a connection with foreign keys off, or this case proves nothing")

	assert.Equal(t, map[string]string{"mig50-control": "Control"}, f.identifiers(t),
		"000050 must delete the userinfo permission and nothing else on the authserver resource")
	userHolds, groupHolds, clientHolds := f.held(t)
	assert.Equal(t, []int64{f.control.Id}, userHolds, "000050 must delete the user's userinfo grant itself, with no cascade to do it")
	assert.Equal(t, []int64{f.control.Id}, groupHolds, "000050 must delete the group's userinfo grant itself, with no cascade to do it")
	assert.Equal(t, []int64{f.control.Id}, clientHolds, "000050 must delete the client's userinfo grant itself, with no cascade to do it")

	// And no row anywhere is left pointing at a parent that is gone.
	rows, err := h.SQL.QueryContext(ctx, "PRAGMA foreign_key_check;")
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	var orphans []string
	for rows.Next() {
		var table, parent string
		var rowid, fkid any
		require.NoError(t, rows.Scan(&table, &rowid, &parent, &fkid))
		orphans = append(orphans, table+" -> "+parent)
	}
	require.NoError(t, rows.Err())
	assert.Empty(t, orphans, "000050 must leave no row referencing a deleted permission")
}

// TestMigration000050_AnEmptyDatabase holds both directions to a database with no authserver
// resource, which is every fresh installation before the seed runs: up has nothing to delete and
// down has nowhere to insert the row, and neither may fail or invent one.
func TestMigration000050_AnEmptyDatabase(t *testing.T) {
	h := newIsolatedDB(t)
	ctx := context.Background()

	require.NoErrorf(t, h.Migrator.Migrate(ctx, deleteUserinfoPermission000050), "migrate an empty database through 000050 on %s", dbType())
	resource, err := h.DB.GetResourceByResourceIdentifier(ctx, nil, builtin.AuthServerResourceIdentifier)
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
