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
// The migration does four things and each is asserted below: it creates
// browser_sessions with its unique lookup index and its expiry index, it adds the
// browser-sessions permission on the authserver resource, it grants that permission to
// admin-console-client, and it turns client_credentials_enabled on for that client.
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
	assert.True(t, clientCredentialsEnabled000035(t, h),
		"%s: admin-console-client obtains its bearer token through client_credentials", when)
}

// seedInstallation000035 builds the 000034 fixture the guarded inserts need to match:
// an authserver resource and an admin-console-client with client_credentials_enabled off,
// which is what every installation predating this migration carries.
func seedInstallation000035(t *testing.T, h *isolatedDB) (resourceId, clientId int64) {
	t.Helper()

	falseLit, trueLit := boolLiterals000031()

	_, err := h.SQL.Exec(fmt.Sprintf(
		`INSERT INTO resources (resource_identifier, description) VALUES ('authserver', '%s')`,
		"Authorization server (system-level)"))
	require.NoError(t, err, "seed the authserver resource")
	require.NoError(t, h.SQL.QueryRow(
		`SELECT id FROM resources WHERE resource_identifier = 'authserver'`).Scan(&resourceId),
		"read back the seeded resource id")

	// Every NOT NULL column without a default is named, so this insert does not depend on
	// per-engine defaults agreeing.
	_, err = h.SQL.Exec(fmt.Sprintf(`INSERT INTO clients
		(client_identifier, enabled, consent_required, is_public, authorization_code_enabled,
		 client_credentials_enabled, token_expiration_in_seconds,
		 refresh_token_offline_idle_timeout_in_seconds, refresh_token_offline_max_lifetime_in_seconds,
		 include_open_id_connect_claims_in_access_token, default_acr_level)
		VALUES ('admin-console-client', %s, %s, %s, %s, %s, 300, 2592000, 5184000,
		        'default', 'urn:goiabada:level2_optional')`,
		trueLit, falseLit, falseLit, trueLit, falseLit))
	require.NoError(t, err, "seed the admin console client")
	require.NoError(t, h.SQL.QueryRow(
		`SELECT id FROM clients WHERE client_identifier = 'admin-console-client'`).Scan(&clientId),
		"read back the seeded client id")

	require.False(t, clientCredentialsEnabled000035(t, h),
		"the fixture must start with client_credentials_enabled off, or the migration's UPDATE "+
			"would be asserted against a value it did not set")

	return resourceId, clientId
}

func seedBrowserSessionsPermission000035(t *testing.T, h *isolatedDB, resourceId int64) int64 {
	t.Helper()
	_, err := h.SQL.Exec(fmt.Sprintf(
		`INSERT INTO permissions (permission_identifier, description, resource_id)
		 VALUES ('browser-sessions', 'Read and write admin console browser sessions', %d)`, resourceId))
	require.NoError(t, err, "seed the browser-sessions permission")

	var id int64
	require.NoError(t, h.SQL.QueryRow(fmt.Sprintf(
		`SELECT id FROM permissions WHERE permission_identifier = 'browser-sessions' AND resource_id = %d`,
		resourceId)).Scan(&id), "read back the seeded permission id")
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
