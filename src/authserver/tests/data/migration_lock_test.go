package datatests

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/data/migrator"
	"github.com/leodip/goiabada/core/data/mssqldb"
	"github.com/leodip/goiabada/core/data/mysqldb"
	"github.com/leodip/goiabada/core/data/postgresdb"
	mssql "github.com/microsoft/go-mssqldb"
	"github.com/stretchr/testify/assert"
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

// releaseApplockStatement is the fragment identifying the one statement the fault below refuses.
// It is matched rather than restated in full because the engine builds it with its own
// placeholder; matching the procedure name is enough to pick it out of everything else the
// pre-create issues, and too little to pick out anything it should not.
const releaseApplockStatement = "sp_releaseapplock"

// errPrecreateUnlockFault is the failure injected into that statement. A sentinel, so the
// assertion is identity rather than a string match on whatever the driver would have said.
var errPrecreateUnlockFault = errors.New("injected sp_releaseapplock failure")

// TestMigrationLock_ThePreCreateGivesTheResourceBackWhenTheReleaseFails is the failure half of the
// test above, and the only thing that can tell the pre-create's cleanup from its absence.
//
// The test above exercises a release that works, which is every run against a healthy database, so
// it stays green with the cleanup deleted: on that path the code being protected never executes.
// What the cleanup exists for is the other path. When sp_releaseapplock fails, the session still
// holds an exclusive session-scoped lock that later migrators wait on indefinitely, and returning
// it to the pool hands that lock to the next borrower for the life of the process. So the failure
// has to be reported rather than swallowed, and the connection destroyed rather than pooled.
//
// The fault goes into the real go-mssqldb driver rather than a fake one, and into exactly one
// statement. Acquisition, the catalog check, the CREATE and the release are all issued against the
// real SQL Server; only the release's answer is replaced. A scripted driver would prove the code
// calls something, and nothing about whether a real exclusive lock came back, which is the only
// question here. NewMigrator is called unchanged: no production seam, hook or build tag stands
// behind this, which is what makes it a test of the shipped path.
//
// Both DDL outcomes run, because they leave the function through different returns. A successful
// CREATE reaches the end and the deferred unlock supplies the error; a failing CREATE is already
// returning one, and the unlock's has to join it rather than replace it.
//
// SQL Server only, for the same reason as the test above: it is the one engine whose pre-create
// takes a lock at all.
//
// Run via: ./run-tests.sh --type data --db mssql --run TestMigrationLock
func TestMigrationLock_ThePreCreateGivesTheResourceBackWhenTheReleaseFails(t *testing.T) {
	if dbType() != "mssql" {
		t.Skipf("%s pre-creates schema_migrations without a lock: only SQL Server has no atomic form of that check-then-create", dbType())
	}

	for _, failDDL := range []bool{false, true} {
		name := "the create succeeds"
		if failDDL {
			name = "the create fails too"
		}
		t.Run(name, func(t *testing.T) {
			h := newIsolatedDB(t)
			db, ok := h.DB.(*mssqldb.MsSQLDatabase)
			require.True(t, ok, "the mssql database must be the concrete type whose pool this swaps")

			// newIsolatedDB already pre-created the table, so without this the CREATE would be a
			// no-op and the succeeding-DDL case would never reach it.
			_, err := h.SQL.Exec("DROP TABLE schema_migrations")
			require.NoError(t, err, "clear the table the fixture's own construction created")
			if failDDL {
				// A VIEW is not an object of type U, so the pre-create's IF OBJECT_ID guard sees
				// nothing and issues the CREATE, which SQL Server then refuses for the name.
				_, err = h.SQL.Exec("CREATE VIEW schema_migrations AS SELECT CAST(0 AS BIGINT) AS version, CAST(0 AS BIT) AS dirty")
				require.NoError(t, err, "seed the collision the CREATE will hit")
			}

			faultPool := precreateFaultPool(t, h.Name)
			original := db.DB
			db.DB = faultPool
			t.Cleanup(func() { db.DB = original })

			_, err = db.NewMigrator()
			require.ErrorIs(t, err, errPrecreateUnlockFault,
				"a release that failed must reach the caller: it is the only notice that this database now carries a lock held against every later migrator")
			if failDDL {
				assert.Contains(t, err.Error(), "unable to create the schema_migrations table",
					"and it must join the CREATE's failure rather than replacing it")
			}

			// The session that failed to release must not go back to the pool. Both counters,
			// because InUse alone is zero for a connection sitting idle in the pool still holding
			// the lock, which is the exact state being ruled out.
			stats := faultPool.Stats()
			assert.Equal(t, 0, stats.InUse, "the connection must not still be checked out")
			assert.Equal(t, 0, stats.OpenConnections,
				"the session that failed to release the lock must be destroyed, not pooled for the next borrower")

			// And the resource is actually free, observed from a session that is definitely not
			// that one. This is the assertion the counters cannot make: a pool's connection count
			// says nothing about what the server still holds.
			requireMigrationLockIsFree(t, h, migrationLockEngine(t, h.Name), "after a pre-create whose release failed")
		})
	}
}

// precreateFaultPool opens a pool to an existing database through the real SQL Server driver, with
// every statement but sp_releaseapplock going to the server untouched.
//
// One connection, so the assertions about open connections describe the one session that took the
// lock rather than a pool that happened to have others.
func precreateFaultPool(t *testing.T, name string) *sql.DB {
	t.Helper()
	cfg := config.GetDatabase()

	dsn := url.URL{
		Scheme:   "sqlserver",
		User:     url.UserPassword(cfg.Username, cfg.Password),
		Host:     fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		RawQuery: url.Values{"database": {name}, "encrypt": {"disable"}}.Encode(),
	}
	connector, err := mssql.NewConnector(dsn.String())
	require.NoErrorf(t, err, "build a real SQL Server connector to %s", name)

	pool := sql.OpenDB(precreateFaultConnector{Connector: connector})
	pool.SetMaxOpenConns(1)
	pool.SetMaxIdleConns(1)
	t.Cleanup(func() { _ = pool.Close() })
	return pool
}

// precreateFaultConnector hands out real connections wrapped so one statement can fail.
type precreateFaultConnector struct{ *mssql.Connector }

func (c precreateFaultConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	// The concrete type, not the driver.Conn interface, and deliberately: database/sql picks its
	// path by testing the connection for optional interfaces (ConnBeginTx, NamedValueChecker,
	// QueryerContext and the rest), and a wrapper embedding the interface would hide every one of
	// them. The parameterised lock statements need them, so such a fixture would change the very
	// behaviour it is here to observe.
	native, ok := conn.(*mssql.Conn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("unexpected SQL Server connection type %T", conn)
	}
	return &precreateFaultConn{Conn: native}, nil
}

// precreateFaultConn refuses the release statement and passes everything else through.
//
// The fault sits on the prepared statement rather than on an ExecContext override because
// go-mssqldb's Conn implements no driver.ExecerContext, so database/sql prepares every statement
// it issues and that is the only path the release can take. Adding an override would introduce a
// path the driver does not have. Should a later version of the driver add one, this stops
// intercepting and the assertions below fail rather than quietly passing, which is the direction
// a fixture like this has to fail in.
type precreateFaultConn struct{ *mssql.Conn }

func (c *precreateFaultConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	stmt, err := c.Conn.PrepareContext(ctx, query)
	if err != nil || !strings.Contains(query, releaseApplockStatement) {
		return stmt, err
	}
	return precreateFaultStmt{Stmt: stmt}, nil
}

func (c *precreateFaultConn) Prepare(query string) (driver.Stmt, error) {
	return c.PrepareContext(context.Background(), query)
}

// precreateFaultStmt is the prepared form of the same refusal.
type precreateFaultStmt struct{ driver.Stmt }

func (s precreateFaultStmt) Exec([]driver.Value) (driver.Result, error) {
	return nil, errPrecreateUnlockFault
}

func (s precreateFaultStmt) ExecContext(context.Context, []driver.NamedValue) (driver.Result, error) {
	return nil, errPrecreateUnlockFault
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
