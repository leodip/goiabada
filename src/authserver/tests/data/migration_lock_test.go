package datatests

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/data/migrator"
	"github.com/leodip/goiabada/core/data/mssqldb"
	"github.com/leodip/goiabada/core/data/mysqldb"
	"github.com/leodip/goiabada/core/data/postgresdb"
	"github.com/stretchr/testify/require"
)

// migrationLockHoldBudget is how long a migration is required to stay blocked while another
// session holds the migration lock. It has to sit well under MySQL's GET_LOCK timeout of ten
// seconds, which is the one lock of the three that gives up rather than waiting, or the test
// would be asserting a blocked operation against an operation that had already failed.
const migrationLockHoldBudget = 2 * time.Second

// migrationLockFinishBudget is how long the same migration is then allowed to take once the
// lock comes back. Generous: the whole chain runs inside it, and on SQL Server that is the
// slowest thing this package does.
const migrationLockFinishBudget = 3 * time.Minute

// TestMigrationLock_ARunnerWaitsForTheResourceAndGivesItBack is the only thing in this change
// that can tell a runner which TAKES the cross-process migration lock from one that never
// reaches for it (#268 decision 4, goal 2).
//
// Nothing else can. The lock resource names are pinned as strings by a unit test, which is a
// claim about a formula and not about a statement ever being issued; every chain, catalog and
// per-migration test in this package runs serially against its own isolated database, so all of
// them pass unchanged against an adapter with acquisition deleted. What would be lost is the one
// window the lock exists for: two Goiabada processes of different releases migrating one
// database during an upgrade, where the loser has to wait rather than apply the same files a
// second time over the winner's work.
//
// Modelled on database_create_test.go's holdCreationLock, which does this for #293's creation
// lock. The identity comes from the production symbol, migrator.MySQL / Postgres / SQLServer,
// rather than from a resource name restated here: a test holding the WRONG resource passes
// whatever the runner does.
//
// The holder is a second *sql.Conn out of the isolated database's own pool, which is a distinct
// SESSION on all three engines, and a session is all these locks are scoped to. Two processes
// are not needed, and could not be observed from inside one test anyway.
//
// SQLite is skipped: it has no session-scoped lock statement to contend on, and the runner
// excludes itself there with a process-wide mutex instead.
//
// Run via: ./run-tests.sh --type data --db <mysql|postgres|mssql> --run TestMigrationLock
func TestMigrationLock_ARunnerWaitsForTheResourceAndGivesItBack(t *testing.T) {
	if !hasSessionMigrationLock() {
		t.Skipf("%s has no session-scoped migration lock: its exclusion is a process-wide mutex", dbType())
	}

	h := newIsolatedDB(t)
	eng := migrationLockEngine(t, h.Name)

	release := holdMigrationLock(t, h, eng)
	done := runInBackground(func() error { return h.Migrator.Up() })

	select {
	case err := <-done:
		t.Fatalf("Up() completed in under %s while another session held the migration lock (it answered %v). "+
			"The runner is not taking the lock, so two binaries of different releases would migrate one database at once (#268 decision 4)",
			migrationLockHoldBudget, err)
	case <-time.After(migrationLockHoldBudget):
	}

	release()
	select {
	case err := <-done:
		require.NoErrorf(t, err, "the chain must run once the lock is released on %s", dbType())
	case <-time.After(migrationLockFinishBudget):
		t.Fatalf("Up() did not finish within %s after the migration lock was released on %s",
			migrationLockFinishBudget, dbType())
	}

	// And the runner gave the resource back. This is the half acquisition alone does not buy: a
	// runner that locked and never unlocked would pass everything above and then block every
	// later migrator on this database, on two of the three engines for ever.
	requireMigrationLockIsFree(t, h, eng, "after a successful migration")
}

// TestMigrationLock_AFailedMigrationStillGivesTheResourceBack is the error path of the same
// property, and it needs a database of its own: the failure it forces leaves migration 000001
// half applied, which nothing afterwards could migrate either way.
//
// The failure is a `clients` table pre-created by hand. Migration 000001 creates that table on
// all three engines, so the very first up file dies for a reason no renumbering can move, and
// the chain never gets far enough to depend on any down file. That matters here: the downs below
// 000024 have never been executed and two of them are recorded as broken on SQL Server, which is
// a later stage's problem and must not be this test's.
//
// Run via: ./run-tests.sh --type data --db <mysql|postgres|mssql> --run TestMigrationLock
func TestMigrationLock_AFailedMigrationStillGivesTheResourceBack(t *testing.T) {
	if !hasSessionMigrationLock() {
		t.Skipf("%s has no session-scoped migration lock: its exclusion is a process-wide mutex", dbType())
	}

	h := newIsolatedDB(t)
	eng := migrationLockEngine(t, h.Name)

	_, err := h.SQL.Exec("CREATE TABLE clients (id BIGINT NOT NULL)")
	require.NoErrorf(t, err, "seed the collision migration 000001 will hit on %s", dbType())

	require.Errorf(t, h.Migrator.Up(),
		"000001 must fail against a clients table that already exists on %s", dbType())

	// The dirty marker is the evidence the failure was the migration's and not the fixture's:
	// the runner writes it before the file runs and clears it after, so a run that never
	// reached the file would have left the table empty.
	version, dirty, err := h.Migrator.Version()
	require.NoErrorf(t, err, "read the version the failed migration recorded on %s", dbType())
	require.Truef(t, dirty, "the failed migration must leave the database dirty on %s", dbType())
	require.Equalf(t, 1, version, "and dirty at the version whose file failed on %s", dbType())

	requireMigrationLockIsFree(t, h, eng, "after a migration whose file failed")
}

// TestMigrationLock_ThePreCreateGivesTheResourceBack covers the one place outside the runner
// that takes the migration lock: SQL Server's schema_migrations pre-create, which is a catalog
// check followed by a CREATE and is safe only while the lock is held (#293).
//
// It holds the same resource on the same instance, so it owes the same two things Migrator.run
// owes and for the same reasons: the lock has to come back, and a session that failed to give it
// back must not return to the pool. NewMigrator is where that happens, and newIsolatedDB already
// called it, so this asks a SECOND construction against the same database and then takes the
// resource from a pool of its own.
//
// SQL Server only. It is the only engine whose pre-create reaches for the lock at all: the other
// three create the table with a plain IF NOT EXISTS, which their engines make atomic.
//
// Run via: ./run-tests.sh --type data --db mssql --run TestMigrationLock
func TestMigrationLock_ThePreCreateGivesTheResourceBack(t *testing.T) {
	if dbType() != "mssql" {
		t.Skipf("%s pre-creates schema_migrations without a lock: only SQL Server has no atomic form of that check-then-create", dbType())
	}

	h := newIsolatedDB(t)
	eng := migrationLockEngine(t, h.Name)

	// The pre-create runs inside NewMigrator, so this is what puts the lock ceremony under test
	// rather than the runner's own.
	source, ok := h.DB.(migratable)
	require.Truef(t, ok, "the %s database must expose NewMigrator", dbType())
	_, err := source.NewMigrator()
	require.NoErrorf(t, err, "construct a second migrator, which pre-creates schema_migrations again on %s", dbType())

	requireMigrationLockIsFree(t, h, eng, "after the schema_migrations pre-create")
}

// hasSessionMigrationLock is the three engines whose migration lock is a statement rather than a
// process-wide mutex.
func hasSessionMigrationLock() bool {
	switch dbType() {
	case "mysql", "postgres", "mssql":
		return true
	default:
		return false
	}
}

// migrationLockEngine is the engine value the runner itself builds for this dialect and this
// database, which is where the lock's resource name comes from.
func migrationLockEngine(t *testing.T, name string) migrator.Engine {
	t.Helper()
	require.NotEmptyf(t, name, "the isolated database on %s must carry its server-side name, which the lock resource is computed over", dbType())

	switch dbType() {
	case "mysql":
		return migrator.MySQL(name)
	case "postgres":
		return migrator.Postgres(name)
	case "mssql":
		return migrator.SQLServer(name)
	default:
		t.Fatalf("%s has no session-scoped migration lock", dbType())
		return migrator.Engine{}
	}
}

// holdMigrationLock takes the migration lock on a session of its own and returns the function
// that gives it back. The release is also registered on t, so a failing assertion never leaves
// the resource held for whatever runs next; calling it twice is harmless.
func holdMigrationLock(t *testing.T, h *isolatedDB, eng migrator.Engine) func() {
	t.Helper()
	ctx := context.Background()

	// The isolated database's own pool is enough HERE, unlike requireMigrationLockIsFree
	// below: this connection is pinned before the runner asks for one and stays pinned while
	// it works, so database/sql cannot hand the same session to both.
	conn, err := h.SQL.Conn(ctx)
	require.NoErrorf(t, err, "pin a second session to hold the migration lock on %s", dbType())
	require.NoErrorf(t, eng.Lock(ctx, conn), "take the migration lock the runner serialises on, on %s", dbType())

	released := false
	release := func() {
		if released {
			return
		}
		released = true
		// The unlock error is asserted rather than discarded: an unlock that did not happen
		// leaves the operation under test blocked, and the failure would otherwise surface as a
		// timeout naming the runner instead of this fixture.
		require.NoErrorf(t, eng.Unlock(ctx, conn), "release the migration lock on %s", dbType())
		require.NoErrorf(t, conn.Close(), "give the holding session back on %s", dbType())
	}
	t.Cleanup(release)
	return release
}

// requireMigrationLockIsFree takes the resource from a session that is definitely not the
// runner's, under a bounded context, which is what says the runner released it. Bounded because
// two of the three locks wait indefinitely: without a deadline a runner that leaked the lock
// would hang the tier rather than fail this test.
//
// FROM A POOL OF ITS OWN, and that is the whole correctness of this check rather than a
// stylistic choice. All three locks are re-entrant within one session, and the runner gives its
// connection back to the pool when it is done. Asking that same pool for a connection here
// hands back the very session the runner used, which re-takes its own lock and succeeds whether
// the release happened or not. Measured: with the runner's unlock deleted, this passed on
// PostgreSQL until the pool was separated (#268).
func requireMigrationLockIsFree(t *testing.T, h *isolatedDB, eng migrator.Engine, when string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), migrationLockHoldBudget)
	defer cancel()

	pool := freshPoolTo(t, h.Name)
	conn, err := pool.Conn(ctx)
	require.NoErrorf(t, err, "pin a session of its own to re-take the migration lock %s on %s", when, dbType())
	defer func() { _ = conn.Close() }()

	require.NoErrorf(t, eng.Lock(ctx, conn),
		"the migration lock must be free %s on %s: the runner takes it for one operation and gives it back (#268 decision 8)",
		when, dbType())
	require.NoErrorf(t, eng.Unlock(ctx, conn), "release the migration lock again %s on %s", when, dbType())
}

// freshPoolTo opens a second connection pool to an existing database through the engine's own
// production constructor, with Create false so it touches nothing, and registers its close on t.
// Every connection it makes is a session no other pool in this test can be holding.
func freshPoolTo(t *testing.T, name string) *sql.DB {
	t.Helper()
	cfg := config.GetDatabase()

	switch dbType() {
	case "mysql":
		db, err := mysqldb.NewMySQLDatabase(&mysqldb.DatabaseConfig{
			Type: "mysql", Username: cfg.Username, Password: cfg.Password,
			Host: cfg.Host, Port: cfg.Port, Name: name, Create: false,
		}, false)
		require.NoErrorf(t, err, "open a second pool to %s", name)
		t.Cleanup(func() { _ = db.DB.Close() })
		return db.DB

	case "postgres":
		db, err := postgresdb.NewPostgresDatabase(&postgresdb.DatabaseConfig{
			Type: "postgres", Username: cfg.Username, Password: cfg.Password,
			Host: cfg.Host, Port: cfg.Port, Name: name, Create: false,
		}, false)
		require.NoErrorf(t, err, "open a second pool to %s", name)
		t.Cleanup(func() { _ = db.DB.Close() })
		return db.DB

	case "mssql":
		db, err := mssqldb.NewMsSQLDatabase(&mssqldb.DatabaseConfig{
			Type: "mssql", Username: cfg.Username, Password: cfg.Password,
			Host: cfg.Host, Port: cfg.Port, Name: name, Create: false,
		}, false)
		require.NoErrorf(t, err, "open a second pool to %s", name)
		t.Cleanup(func() { _ = db.DB.Close() })
		return db.DB

	default:
		t.Fatalf("freshPoolTo has no constructor for %s", dbType())
		return nil
	}
}

// runInBackground starts fn and answers on a buffered channel, so the goroutine finishes even
// when the test has already given up waiting for it.
func runInBackground(fn func() error) <-chan error {
	done := make(chan error, 1)
	go func() { done <- fn() }()
	return done
}
