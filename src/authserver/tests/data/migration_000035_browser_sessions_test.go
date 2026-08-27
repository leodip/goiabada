package datatests

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Seam 3 of #266: migration 000035, against an ISOLATED database of the configured
// dialect (see migration_testdb_helper.go).
//
// The migration does five things and each is asserted below: it creates
// browser_sessions with its unique lookup index and its expiry index, it adds the
// browser-sessions permission on the authserver resource, it grants that permission to
// admin-console-client, it strips every OTHER grant that client holds, and it turns
// client_credentials_enabled on for that client. The strip has a test of its own further
// down, because the fixture it needs is an installation this one does not describe.
//
// newIsolatedDB runs migrations and NOTHING else, so at 000034 the resources and clients
// tables are empty and every guarded `INSERT ... SELECT ... FROM resources WHERE
// resource_identifier = 'authserver'` would match no row and insert nothing. Both arms
// below therefore build their own fixture at 000034 first, in the shape a real
// installation carries. Without it the permission assertions would be reading an empty
// table and passing for the wrong reason.
//
// The idempotence arm is a SECOND isolated database whose 000034 fixture already carries
// the permission and the grant, as an installation seeded by a newer binary does, with
// 000035 applied once over it. Neither way of running the up twice would prove anything:
// Migrator.Migrate(35) a second time is ErrNoChange and executes no statement, and
// replaying the up file by hand dies at CREATE TABLE browser_sessions before it ever
// reaches the guard.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000035_BrowserSessions
func TestMigration000035_BrowserSessions(t *testing.T) {
	h := newIsolatedDB(t)

	require.NoError(t, h.Migrator.Migrate(34), "migrate to 000034")

	assert.False(t, tableExists000035(t, h, "browser_sessions"),
		"browser_sessions must not exist at 000034, so what is found afterwards is what 000035 added")

	seedInstallation000035(t, h)

	require.NoError(t, h.Migrator.Migrate(35), "apply 000035")
	assertAfter000035(t, h, "after apply")

	// Down, then up again. SQL Server's constraints bite in both directions, and this is
	// the arm 000031's entry records catching them.
	require.NoError(t, h.Migrator.Migrate(34), "roll back 000035")

	assert.False(t, tableExists000035(t, h, "browser_sessions"),
		"the down migration must drop browser_sessions")
	assert.Equal(t, 0, countBrowserSessionsPermission000035(t, h),
		"the down migration must delete the permission")
	assert.Equal(t, 0, countBrowserSessionsGrant000035(t, h),
		"the down migration must delete the grant")
	assert.False(t, clientCredentialsEnabled000035(t, h),
		"the down migration must put client_credentials_enabled back")

	require.NoError(t, h.Migrator.Migrate(35), "apply 000035 again")
	assertAfter000035(t, h, "after down then up")
}

// TestMigration000035_GuardedInsertsAreIdempotent applies 000035 over a 000034 fixture
// that ALREADY carries the permission and the grant. Nothing may be duplicated: the
// permissions table has a unique index on (permission_identifier, resource_id) that would
// turn a second insert into a migration failure at startup, and clients_permissions has
// none, so a second grant would land silently and be listed twice in the admin console
// for as long as anyone left it there.
func TestMigration000035_GuardedInsertsAreIdempotent(t *testing.T) {
	h := newIsolatedDB(t)

	require.NoError(t, h.Migrator.Migrate(34), "migrate to 000034")
	resourceId, clientId := seedInstallation000035(t, h)

	// The end state 000035 produces, already present before it runs.
	permissionId := seedBrowserSessionsPermission000035(t, h, resourceId)
	seedBrowserSessionsGrant000035(t, h, clientId, permissionId)

	require.Equal(t, 1, countBrowserSessionsPermission000035(t, h), "fixture: one permission")
	require.Equal(t, 1, countBrowserSessionsGrant000035(t, h), "fixture: one grant")

	require.NoError(t, h.Migrator.Migrate(35), "apply 000035 over a fixture that already has both rows")

	assert.Equal(t, 1, countBrowserSessionsPermission000035(t, h),
		"the guarded permission insert must add nothing when the permission is already there")
	assert.Equal(t, 1, countBrowserSessionsGrant000035(t, h),
		"the guarded grant insert must add nothing when the grant is already there")
	assert.True(t, tableExists000035(t, h, "browser_sessions"),
		"the rest of the migration still runs")
	assert.True(t, clientCredentialsEnabled000035(t, h),
		"the UPDATE is naturally idempotent and must still have run")
}

// TestMigration000035_StripsWiderGrantsFromTheAdminConsoleClient covers decision 21,
// answered "B" on #267.
//
// The migration turns client_credentials_enabled back on for admin-console-client. On a
// fresh install the seeder gives that client the browser-sessions permission and nothing
// else, so the grant is as narrow as decision 16 says. On an UPGRADE it need not be: an
// administrator can enable client credentials on the built-in client through the admin
// console, grant it the authserver resource's manage permission, and switch client
// credentials off again, all through supported UI journeys, and the grant survives. Left
// alone, this migration would make it usable again, silently, because a
// client_credentials token requested without a scope carries every permission its client
// holds.
//
// The fixture below is exactly that installation. Two properties are asserted beyond the
// obvious one, and each is a way the DELETE could be written wrong while still passing
// the first: the manage PERMISSION must survive, because deleting it would strip it from
// every user and group that holds it, and another client's grant of the same permission
// must survive, because the statement is keyed on this one client.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000035_StripsWiderGrantsFromTheAdminConsoleClient
func TestMigration000035_StripsWiderGrantsFromTheAdminConsoleClient(t *testing.T) {
	h := newIsolatedDB(t)

	require.NoError(t, h.Migrator.Migrate(34), "migrate to 000034")
	resourceId, clientId := seedInstallation000035(t, h)

	managePermissionId := seedPermission000035(t, h, resourceId, "manage",
		"Manage the authorization server")
	seedBrowserSessionsGrant000035(t, h, clientId, managePermissionId)

	otherClientId := seedClient000035(t, h, "some-other-client")
	seedBrowserSessionsGrant000035(t, h, otherClientId, managePermissionId)

	require.Equal(t, 1, countGrantsForClient000035(t, h, "admin-console-client"),
		"fixture: the admin console client starts holding the wide grant and nothing else")
	require.Equal(t, 1, countGrantOfPermission000035(t, h, "some-other-client", "manage"),
		"fixture: another client holds the same permission")

	require.NoError(t, h.Migrator.Migrate(35), "apply 000035")

	assert.Equal(t, 0, countGrantOfPermission000035(t, h, "admin-console-client", "manage"),
		"the upgrade must remove the wide grant, or it becomes usable the moment the migration "+
			"turns client credentials back on")
	assert.Equal(t, 1, countBrowserSessionsGrant000035(t, h),
		"the grant this same migration creates must survive its own strip")
	assert.Equal(t, 1, countGrantsForClient000035(t, h, "admin-console-client"),
		"browser-sessions is the only permission the admin console client is left holding")

	assert.Equal(t, 1, countPermission000035(t, h, "manage"),
		"only the GRANT is removed: deleting the permission itself would strip it from every "+
			"user and group holding it")
	assert.Equal(t, 1, countGrantOfPermission000035(t, h, "some-other-client", "manage"),
		"the strip is keyed on the admin console client, so no other client's grants move")

	assert.True(t, clientCredentialsEnabled000035(t, h),
		"the rest of the migration still runs")
}

// TestMigration000035_StripsBrowserSessionsGrantsFromEveryOtherPrincipal covers decision
// 22, answered "B" on #267.
//
// The permission INSERT is guarded with NOT EXISTS so that re-running the migration adds
// nothing, which is what the idempotence arm above pins. The other consequence of that
// guard is the subject of this test: on an installation where an administrator had already
// added a permission named exactly 'browser-sessions' to the built-in authserver resource,
// the migration ADOPTS theirs rather than creating one, and from this release that
// permission also authorizes the new session endpoint, because RequireBearerTokenScope
// admits any token whose scope carries authserver:browser-sessions and checks nothing
// about who presents it. Whatever the administrator meant by the name is silently widened.
//
// The fixture is reachable through supported journeys, which is why it is worth a test:
// HandleAPIResourcePermissionsPut refuses only to delete or rename a BUILT-IN permission
// and its create arm has no resource check at all, so a permission of any name can be
// added to the authserver resource. A user or group grant is not a lesser case than a
// client one either, because the authorize endpoint filters a requested scope against what
// the principal holds, so such a grant reaches an ordinary access token.
//
// Three properties are asserted beyond the obvious one, and each is a way the statements
// could be written wrong while still passing the first. The permission ROW must survive,
// because the endpoint this whole migration exists for is authorized by it. The admin
// console client's own grant must survive, because it is the one legitimate holder and
// this same file creates it. And each principal's grant of a DIFFERENT permission must
// survive, because the statements are keyed on this permission alone.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000035_StripsBrowserSessionsGrantsFromEveryOtherPrincipal
func TestMigration000035_StripsBrowserSessionsGrantsFromEveryOtherPrincipal(t *testing.T) {
	h := newIsolatedDB(t)

	require.NoError(t, h.Migrator.Migrate(34), "migrate to 000034")
	resourceId, _ := seedInstallation000035(t, h)

	// The administrator's own permission of that name, made before this release existed.
	// The guarded INSERT adopts it rather than creating a second one.
	browserSessionsId := seedBrowserSessionsPermission000035(t, h, resourceId)

	// A second permission on the same resource that nothing in the migration names, held by
	// the same three principals. Nothing may touch it.
	manageId := seedPermission000035(t, h, resourceId, "manage", "Manage the authorization server")

	otherClientId := seedClient000035(t, h, "some-other-client")
	seedBrowserSessionsGrant000035(t, h, otherClientId, browserSessionsId)
	seedBrowserSessionsGrant000035(t, h, otherClientId, manageId)

	userId := seedUser000035(t, h, "mig35-holder")
	seedUserGrant000035(t, h, userId, browserSessionsId)
	seedUserGrant000035(t, h, userId, manageId)

	groupId := seedGroup000035(t, h, "mig35-holders")
	seedGroupGrant000035(t, h, groupId, browserSessionsId)
	seedGroupGrant000035(t, h, groupId, manageId)

	require.Equal(t, 1, countGrantOfPermission000035(t, h, "some-other-client", "browser-sessions"),
		"fixture: another client holds the administrator's browser-sessions permission")
	require.Equal(t, 1, countUserGrant000035(t, h, "browser-sessions"),
		"fixture: a user holds it")
	require.Equal(t, 1, countGroupGrant000035(t, h, "browser-sessions"),
		"fixture: a group holds it")

	require.NoError(t, h.Migrator.Migrate(35), "apply 000035")

	assert.Equal(t, 0, countGrantOfPermission000035(t, h, "some-other-client", "browser-sessions"),
		"another client's grant must go: the endpoint admits whoever carries the scope, so leaving "+
			"it hands that client the ability to create admin console session rows at will")
	assert.Equal(t, 0, countUserGrant000035(t, h, "browser-sessions"),
		"a user's grant must go: the authorize endpoint filters a requested scope against what the "+
			"user holds, so it reaches an ordinary access token")
	assert.Equal(t, 0, countGroupGrant000035(t, h, "browser-sessions"),
		"a group's grant must go, for the same reason a user's does")

	assert.Equal(t, 1, countBrowserSessionsPermission000035(t, h),
		"the permission ROW is adopted, not duplicated and not deleted: the endpoint this migration "+
			"exists for is authorized by it")
	assert.Equal(t, 1, countBrowserSessionsGrant000035(t, h),
		"the admin console client is the one legitimate holder, and its grant is created by this "+
			"same file, so the strip must not take it")
	assert.Equal(t, 1, countGrantsForClient000035(t, h, "admin-console-client"),
		"and browser-sessions is still the only permission it holds")

	assert.Equal(t, 1, countGrantOfPermission000035(t, h, "some-other-client", "manage"),
		"the statements are keyed on browser-sessions alone, so a client's other grants do not move")
	assert.Equal(t, 1, countUserGrant000035(t, h, "manage"),
		"nor do a user's")
	assert.Equal(t, 1, countGroupGrant000035(t, h, "manage"),
		"nor a group's")

	assert.True(t, clientCredentialsEnabled000035(t, h),
		"the rest of the migration still runs")
}

// assertAfter000035 is everything 000035 is responsible for, asserted in one place so the
// apply arm and the down-then-up arm cannot drift apart.
func assertAfter000035(t *testing.T, h *isolatedDB, when string) {
	t.Helper()

	require.True(t, tableExists000035(t, h, "browser_sessions"), "%s: browser_sessions must exist", when)

	lookup := describeIndex(t, h, "browser_sessions", "idx_browser_sessions_owner_hash")
	assert.True(t, lookup.Exists, "%s: the lookup index must exist", when)
	assert.True(t, lookup.Unique, "%s: the lookup index must be UNIQUE, or one owner could hold "+
		"two rows for one identifier", when)
	assert.Equal(t, []string{"owner", "session_id_hash"}, lookup.Columns,
		"%s: the lookup index is on (owner, session_id_hash), in that order", when)

	expiry := describeIndex(t, h, "browser_sessions", "idx_browser_sessions_expires_at")
	assert.True(t, expiry.Exists, "%s: the reaper's index must exist", when)
	assert.False(t, expiry.Unique, "%s: many sessions share an expiry, so this index cannot be unique", when)
	assert.Equal(t, []string{"expires_at"}, expiry.Columns, "%s: the reaper deletes on expires_at alone", when)

	assert.Equal(t, 1, countBrowserSessionsPermission000035(t, h),
		"%s: exactly one browser-sessions permission on the authserver resource", when)
	assert.Equal(t, 1, countBrowserSessionsGrant000035(t, h),
		"%s: admin-console-client must carry the grant exactly once", when)
	assert.Equal(t, 1, countGrantsForClient000035(t, h, "admin-console-client"),
		"%s: browser-sessions is the ONLY permission the admin console client is left holding, "+
			"which is decision 21's answer to what an upgrade does with a wider one", when)
	assert.True(t, clientCredentialsEnabled000035(t, h),
		"%s: admin-console-client obtains its bearer token through client_credentials", when)
}

// seedInstallation000035 builds the 000034 fixture the guarded inserts need to match:
// an authserver resource and an admin-console-client with client_credentials_enabled off,
// which is what every installation predating this migration carries.
func seedInstallation000035(t *testing.T, h *isolatedDB) (resourceId, clientId int64) {
	t.Helper()

	_, err := h.SQL.Exec(fmt.Sprintf(
		`INSERT INTO resources (resource_identifier, description) VALUES ('authserver', '%s')`,
		"Authorization server (system-level)"))
	require.NoError(t, err, "seed the authserver resource")
	require.NoError(t, h.SQL.QueryRow(
		`SELECT id FROM resources WHERE resource_identifier = 'authserver'`).Scan(&resourceId),
		"read back the seeded resource id")

	clientId = seedClient000035(t, h, "admin-console-client")

	require.False(t, clientCredentialsEnabled000035(t, h),
		"the fixture must start with client_credentials_enabled off, or the migration's UPDATE "+
			"would be asserted against a value it did not set")

	return resourceId, clientId
}

// seedClient000035 inserts a client with client_credentials_enabled off. Every NOT NULL
// column without a default is named, so the insert does not depend on per-engine defaults
// agreeing.
func seedClient000035(t *testing.T, h *isolatedDB, identifier string) int64 {
	t.Helper()

	falseLit, trueLit := boolLiterals000031()

	_, err := h.SQL.Exec(fmt.Sprintf(`INSERT INTO clients
		(client_identifier, enabled, consent_required, is_public, authorization_code_enabled,
		 client_credentials_enabled, token_expiration_in_seconds,
		 refresh_token_offline_idle_timeout_in_seconds, refresh_token_offline_max_lifetime_in_seconds,
		 include_open_id_connect_claims_in_access_token, default_acr_level)
		VALUES ('%s', %s, %s, %s, %s, %s, 300, 2592000, 5184000,
		        'default', 'urn:goiabada:level2_optional')`,
		identifier, trueLit, falseLit, falseLit, trueLit, falseLit))
	require.NoErrorf(t, err, "seed the %s client", identifier)

	var id int64
	require.NoError(t, h.SQL.QueryRow(fmt.Sprintf(
		`SELECT id FROM clients WHERE client_identifier = '%s'`, identifier)).Scan(&id),
		"read back the seeded client id")
	return id
}

func seedBrowserSessionsPermission000035(t *testing.T, h *isolatedDB, resourceId int64) int64 {
	t.Helper()
	return seedPermission000035(t, h, resourceId, "browser-sessions",
		"Read and write admin console browser sessions")
}

func seedPermission000035(t *testing.T, h *isolatedDB, resourceId int64, identifier, description string) int64 {
	t.Helper()
	_, err := h.SQL.Exec(fmt.Sprintf(
		`INSERT INTO permissions (permission_identifier, description, resource_id)
		 VALUES ('%s', '%s', %d)`, identifier, description, resourceId))
	require.NoErrorf(t, err, "seed the %s permission", identifier)

	var id int64
	require.NoError(t, h.SQL.QueryRow(fmt.Sprintf(
		`SELECT id FROM permissions WHERE permission_identifier = '%s' AND resource_id = %d`,
		identifier, resourceId)).Scan(&id), "read back the seeded permission id")
	return id
}

func seedBrowserSessionsGrant000035(t *testing.T, h *isolatedDB, clientId, permissionId int64) {
	t.Helper()
	_, err := h.SQL.Exec(fmt.Sprintf(
		`INSERT INTO clients_permissions (client_id, permission_id) VALUES (%d, %d)`,
		clientId, permissionId))
	require.NoError(t, err, "seed the client permission grant")
}

func countBrowserSessionsPermission000035(t *testing.T, h *isolatedDB) int {
	t.Helper()
	var n int
	require.NoError(t, h.SQL.QueryRow(
		`SELECT COUNT(*) FROM permissions p
		 JOIN resources r ON r.id = p.resource_id
		 WHERE p.permission_identifier = 'browser-sessions' AND r.resource_identifier = 'authserver'`).Scan(&n),
		"count the browser-sessions permission")
	return n
}

func countBrowserSessionsGrant000035(t *testing.T, h *isolatedDB) int {
	t.Helper()
	var n int
	require.NoError(t, h.SQL.QueryRow(
		`SELECT COUNT(*) FROM clients_permissions cp
		 JOIN clients c ON c.id = cp.client_id
		 JOIN permissions p ON p.id = cp.permission_id
		 JOIN resources r ON r.id = p.resource_id
		 WHERE c.client_identifier = 'admin-console-client'
		   AND p.permission_identifier = 'browser-sessions'
		   AND r.resource_identifier = 'authserver'`).Scan(&n),
		"count the admin console client's browser-sessions grant")
	return n
}

// countGrantsForClient000035 counts every permission a client holds, whatever it is. The
// migration's strip is the only thing that makes this number smaller, so an assertion on
// the browser-sessions grant alone would pass with the strip deleted.
func countGrantsForClient000035(t *testing.T, h *isolatedDB, clientIdentifier string) int {
	t.Helper()
	var n int
	require.NoError(t, h.SQL.QueryRow(fmt.Sprintf(
		`SELECT COUNT(*) FROM clients_permissions cp
		 JOIN clients c ON c.id = cp.client_id
		 WHERE c.client_identifier = '%s'`, clientIdentifier)).Scan(&n),
		"count every grant the client holds")
	return n
}

func countGrantOfPermission000035(t *testing.T, h *isolatedDB, clientIdentifier, permissionIdentifier string) int {
	t.Helper()
	var n int
	require.NoError(t, h.SQL.QueryRow(fmt.Sprintf(
		`SELECT COUNT(*) FROM clients_permissions cp
		 JOIN clients c ON c.id = cp.client_id
		 JOIN permissions p ON p.id = cp.permission_id
		 WHERE c.client_identifier = '%s' AND p.permission_identifier = '%s'`,
		clientIdentifier, permissionIdentifier)).Scan(&n),
		"count one client's grant of one permission")
	return n
}

func countPermission000035(t *testing.T, h *isolatedDB, permissionIdentifier string) int {
	t.Helper()
	var n int
	require.NoError(t, h.SQL.QueryRow(fmt.Sprintf(
		`SELECT COUNT(*) FROM permissions WHERE permission_identifier = '%s'`,
		permissionIdentifier)).Scan(&n), "count the permission rows themselves")
	return n
}

// clientCredentialsEnabled000035 normalises the flag to a bool in SQL rather than in Go:
// the column is `numeric` on SQLite, tinyint(1) on MySQL, a genuine boolean on PostgreSQL
// and BIT on SQL Server, which is four different Go scan targets for one question.
func clientCredentialsEnabled000035(t *testing.T, h *isolatedDB) bool {
	t.Helper()
	var flag string
	require.NoError(t, h.SQL.QueryRow(
		`SELECT CASE WHEN client_credentials_enabled = `+enabledLiteral000035()+` THEN '1' ELSE '0' END
		 FROM clients WHERE client_identifier = 'admin-console-client'`).Scan(&flag),
		"read client_credentials_enabled")
	return flag == "1"
}

func enabledLiteral000035() string {
	if dbType() == "postgres" {
		return "true"
	}
	return "1"
}

// tableExists000035 answers from the engine's catalog rather than by trying a query and
// reading the error, so a permission fault or a typo cannot look like an absent table.
func tableExists000035(t *testing.T, h *isolatedDB, table string) bool {
	t.Helper()

	var q string
	switch dbType() {
	case "mysql":
		q = fmt.Sprintf(`SELECT COUNT(*) FROM information_schema.tables
			WHERE table_schema = DATABASE() AND table_name = '%s'`, table)
	case "postgres":
		q = fmt.Sprintf(`SELECT COUNT(*) FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = '%s'`, table)
	case "mssql":
		q = fmt.Sprintf(`SELECT COUNT(*) FROM sys.tables WHERE name = '%s'`, table)
	default: // sqlite
		q = fmt.Sprintf(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = '%s'`, table)
	}

	var n int
	require.NoErrorf(t, h.SQL.QueryRow(q).Scan(&n), "table catalog lookup: %s", table)
	return n > 0
}

// seedUser000035 inserts one user. Every NOT NULL column without a default is named, so
// the insert does not depend on per-engine defaults agreeing. Only one user is seeded, so
// a NULL email would be safe even on SQL Server, where a unique index treats two NULLs as
// equal; it is set anyway so the row does not depend on that staying true.
func seedUser000035(t *testing.T, h *isolatedDB, name string) int64 {
	t.Helper()

	falseLit, trueLit := boolLiterals000031()
	subject := "00000000-0000-4000-8000-000000000035"

	_, err := h.SQL.Exec(fmt.Sprintf(`INSERT INTO users
		(enabled, subject, username, email, email_verified, phone_number_verified,
		 password_hash, otp_enabled)
		VALUES (%s, '%s', '%s', '%s@test.local', %s, %s, 'x', %s)`,
		trueLit, subject, name, name, falseLit, falseLit, falseLit))
	require.NoError(t, err, "seed a user")

	var id int64
	require.NoError(t, h.SQL.QueryRow(fmt.Sprintf(
		"SELECT id FROM users WHERE subject = '%s'", subject)).Scan(&id),
		"read back the seeded user id")
	return id
}

// seedGroup000035 inserts one group. The table name is quoted per engine because MySQL
// 8.0.2 made GROUPS a reserved word, so the bare name parses on three engines and fails on
// the fourth.
func seedGroup000035(t *testing.T, h *isolatedDB, identifier string) int64 {
	t.Helper()

	falseLit, _ := boolLiterals000031()

	_, err := h.SQL.Exec(fmt.Sprintf(
		`INSERT INTO %s (group_identifier, include_in_id_token, include_in_access_token)
		 VALUES ('%s', %s, %s)`, groupsTable000035(), identifier, falseLit, falseLit))
	require.NoError(t, err, "seed a group")

	var id int64
	require.NoError(t, h.SQL.QueryRow(fmt.Sprintf(
		"SELECT id FROM %s WHERE group_identifier = '%s'", groupsTable000035(), identifier)).Scan(&id),
		"read back the seeded group id")
	return id
}

func groupsTable000035() string {
	switch dbType() {
	case "mysql":
		return "`groups`"
	case "mssql":
		return "[groups]"
	default: // sqlite, postgres
		return `"groups"`
	}
}

func seedUserGrant000035(t *testing.T, h *isolatedDB, userId, permissionId int64) {
	t.Helper()
	_, err := h.SQL.Exec(fmt.Sprintf(
		`INSERT INTO users_permissions (user_id, permission_id) VALUES (%d, %d)`,
		userId, permissionId))
	require.NoError(t, err, "seed the user permission grant")
}

func seedGroupGrant000035(t *testing.T, h *isolatedDB, groupId, permissionId int64) {
	t.Helper()
	_, err := h.SQL.Exec(fmt.Sprintf(
		`INSERT INTO groups_permissions (group_id, permission_id) VALUES (%d, %d)`,
		groupId, permissionId))
	require.NoError(t, err, "seed the group permission grant")
}

// countUserGrant000035 and countGroupGrant000035 count grants of one permission on the
// authserver resource across every principal of that kind, not per principal: the
// migration's statements exclude nobody there, so the number a correct migration leaves is
// zero whoever held it.
func countUserGrant000035(t *testing.T, h *isolatedDB, permissionIdentifier string) int {
	t.Helper()
	var n int
	require.NoError(t, h.SQL.QueryRow(fmt.Sprintf(
		`SELECT COUNT(*) FROM users_permissions up
		 JOIN permissions p ON p.id = up.permission_id
		 JOIN resources r ON r.id = p.resource_id
		 WHERE p.permission_identifier = '%s' AND r.resource_identifier = 'authserver'`,
		permissionIdentifier)).Scan(&n), "count the user grants of one permission")
	return n
}

func countGroupGrant000035(t *testing.T, h *isolatedDB, permissionIdentifier string) int {
	t.Helper()
	var n int
	require.NoError(t, h.SQL.QueryRow(fmt.Sprintf(
		`SELECT COUNT(*) FROM groups_permissions gp
		 JOIN permissions p ON p.id = gp.permission_id
		 JOIN resources r ON r.id = p.resource_id
		 WHERE p.permission_identifier = '%s' AND r.resource_identifier = 'authserver'`,
		permissionIdentifier)).Scan(&n), "count the group grants of one permission")
	return n
}
