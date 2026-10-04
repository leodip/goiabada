package datatests

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/datafactory"
	"github.com/leodip/goiabada/authserver/internal/data/migrator"
	"github.com/leodip/goiabada/authserver/internal/data/mssqldb"
	"github.com/leodip/goiabada/authserver/internal/data/mysqldb"
	"github.com/leodip/goiabada/authserver/internal/data/postgresdb"
	"github.com/leodip/goiabada/core/logging/logtest"
	mssql "github.com/microsoft/go-mssqldb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// migrationLockHoldBudget is how long a migration is required to stay blocked while another
// session holds the migration lock, in the tests asking only whether the runner takes it at all.
// How long the runner then goes on waiting is TestMigrationLock_AStartQueuedBehindTheLock's
// question, held past migrationLockPastTheOldGiveUp.
const migrationLockHoldBudget = 2 * time.Second

// migrationLockPastTheOldGiveUp is how long a start queued behind the migration lock is held
// there by TestMigrationLock_AStartQueuedBehindTheLockWaitsPastTenSecondsAndSaysSo. MySQL's
// GET_LOCK used to wait ten seconds and then give up, so the queued process wrote an Error
// record, exited 1 and crash-looped; it waits indefinitely now, as PostgreSQL's and SQL Server's
// locks always did (#390 decision 6). Two seconds past the old limit, so a runner that still gave
// up would have done so with time to spare for the assertion to see it.
const migrationLockPastTheOldGiveUp = 12 * time.Second

// migrationLockRecordBudget is how long a start is allowed to take to reach the migration lock
// and say it is waiting: the open, the connection and, on SQL Server, the schema_migrations
// pre-create all come first.
const migrationLockRecordBudget = time.Minute

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
	done := runInBackground(func() error { return h.Migrator.Up(context.Background()) })

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

	require.Errorf(t, h.Migrator.Up(context.Background()),
		"000001 must fail against a clients table that already exists on %s", dbType())

	// The dirty marker is the evidence the failure was the migration's and not the fixture's:
	// the runner writes it before the file runs and clears it after, so a run that never
	// reached the file would have left the table empty.
	version, dirty, err := h.Migrator.Version(context.Background())
	require.NoErrorf(t, err, "read the version the failed migration recorded on %s", dbType())
	require.Truef(t, dirty, "the failed migration must leave the database dirty on %s", dbType())
	require.Equalf(t, 1, version, "and dirty at the version whose file failed on %s", dbType())

	requireMigrationLockIsFree(t, h, eng, "after a migration whose file failed")
}

// TestMigrationLock_AStartQueuedBehindTheLockWaitsPastTenSecondsAndSaysSo is #390 decisions 6
// and 7 on the real engines, through the start itself: datafactory.NewDatabase, the call the
// auth server's main makes, against a database whose migration lock another session holds.
//
// Two things a pod queued behind another pod's migration used to get wrong. On MySQL it gave up
// after ten seconds and crash-looped, the one engine-specific route into CrashLoopBackOff; on
// every engine it wrote nothing while it waited, so it could not be told from a hung one. So the
// start must say it is waiting, once, before it waits; still be waiting well past the old ten
// seconds; and then migrate, saying so, once the lock comes back.
//
// The hold is a second session out of the isolated database's own pool, as in the tests above,
// on the resource the production engine names. Holding the wrong resource would let a start that
// never reached for the lock pass the wait half, and fail only the record half, for the wrong
// reason.
//
// Run via: ./run-tests.sh --type data --db <mysql|postgres|mssql> --run TestMigrationLock
func TestMigrationLock_AStartQueuedBehindTheLockWaitsPastTenSecondsAndSaysSo(t *testing.T) {
	if !hasSessionMigrationLock() {
		t.Skipf("%s has no session-scoped migration lock: its exclusion is a process-wide mutex", dbType())
	}

	h := newIsolatedDB(t)
	eng := migrationLockEngine(t, h.Name)

	release := holdMigrationLock(t, h, eng)
	capture := logtest.CaptureSlog(t)
	done := startInBackground(t, h.Name)

	awaitRecord(t, capture, done, "waiting for the migration lock")
	select {
	case res := <-done:
		t.Fatalf("the start ended within %s of saying it was waiting, while the migration lock was still held (it answered %v). "+
			"A queued start must wait for the lock rather than give up and be restarted (#390 decision 6)",
			migrationLockPastTheOldGiveUp, res.err)
	case <-time.After(migrationLockPastTheOldGiveUp):
	}
	assert.Empty(t, recordsNamed(capture, "migrating the database"),
		"nothing may migrate while another session holds the lock")

	release()
	select {
	case res := <-done:
		require.NoErrorf(t, res.err, "the start must migrate once the lock is released on %s", dbType())
	case <-time.After(migrationLockFinishBudget):
		t.Fatalf("the start did not finish within %s after the migration lock was released on %s",
			migrationLockFinishBudget, dbType())
	}

	waits := recordsNamed(capture, "waiting for the migration lock")
	require.Len(t, waits, 1, "the wait is said once, however long it lasts")
	assert.Equal(t, slog.LevelInfo, waits[0].Level, "waiting is lifecycle, which is Info")
	assert.Empty(t, waits[0].Attrs, "the record names no resource: an operator has nothing to do with it")

	assert.Equal(t,
		[]string{"opening the database", "waiting for the migration lock", "migrating the database", "database migrated"},
		messageOrder(capture, "opening the database", "waiting for the migration lock", "migrating the database",
			"database migrated", "no need to migrate the database"),
		"the start waited, then migrated the never-migrated database, and said each in that order")
	migrating := recordsNamed(capture, "migrating the database")
	require.Len(t, migrating, 1)
	assert.Equal(t, int64(0), migrating[0].Attrs["from_version"], "the isolated database was never migrated")

	requireMigrationLockIsFree(t, h, eng, "after a start that waited for it")
}

// TestMigrationLock_AStartQueuedBehindAnotherPodsMigrationSaysSoTwice is decision 7's own example:
// the queued start waits, and when the lock comes back the other process has already migrated, so
// it writes the wait record and then "no need to migrate the database".
//
// Run via: ./run-tests.sh --type data --db <mysql|postgres|mssql> --run TestMigrationLock
func TestMigrationLock_AStartQueuedBehindAnotherPodsMigrationSaysSoTwice(t *testing.T) {
	if !hasSessionMigrationLock() {
		t.Skipf("%s has no session-scoped migration lock: its exclusion is a process-wide mutex", dbType())
	}

	h := newIsolatedDB(t)
	eng := migrationLockEngine(t, h.Name)
	require.NoErrorf(t, h.Migrator.Up(context.Background()), "the other pod's migration, already done, on %s", dbType())

	release := holdMigrationLock(t, h, eng)
	capture := logtest.CaptureSlog(t)
	done := startInBackground(t, h.Name)

	awaitRecord(t, capture, done, "waiting for the migration lock")
	release()
	select {
	case res := <-done:
		require.NoErrorf(t, res.err, "the start must carry on once the lock is released on %s", dbType())
	case <-time.After(migrationLockFinishBudget):
		t.Fatalf("the start did not finish within %s after the migration lock was released on %s",
			migrationLockFinishBudget, dbType())
	}

	assert.Equal(t,
		[]string{"waiting for the migration lock", "no need to migrate the database"},
		messageOrder(capture, "waiting for the migration lock", "migrating the database",
			"database migrated", "no need to migrate the database"))
}

// TestMigrationLock_AStartWithTheLockFreeSaysNothingAboutWaiting is the other half of the wait
// record: the start tries the lock without waiting first, and only a held lock is a wait to
// report. A start that wrote it every time would tell an operator nothing.
//
// Run via: ./run-tests.sh --type data --db <mysql|postgres|mssql> --run TestMigrationLock
func TestMigrationLock_AStartWithTheLockFreeSaysNothingAboutWaiting(t *testing.T) {
	if !hasSessionMigrationLock() {
		t.Skipf("%s has no session-scoped migration lock: its exclusion is a process-wide mutex", dbType())
	}

	h := newIsolatedDB(t)
	eng := migrationLockEngine(t, h.Name)

	capture := logtest.CaptureSlog(t)
	res := <-startInBackground(t, h.Name)
	require.NoErrorf(t, res.err, "the start must migrate a database nobody else is migrating on %s", dbType())

	assert.Equal(t,
		[]string{"migrating the database", "database migrated"},
		messageOrder(capture, "waiting for the migration lock", "migrating the database",
			"database migrated", "no need to migrate the database"),
		"a free lock is taken at once, so there was no wait to say")

	requireMigrationLockIsFree(t, h, eng, "after a start that took it at once")
}

// startResult is what a start in the background answered.
type startResult struct{ err error }

// startInBackground runs datafactory.NewDatabase against the isolated database named, in a
// goroutine, as the auth server's main would, with Create off since the database exists. The
// opened pool is closed on t before the isolated database's own drop runs, which needs no session
// left on it.
func startInBackground(t *testing.T, name string) <-chan startResult {
	t.Helper()
	cfg := appConfig.Database
	cfg.Name = name
	cfg.Create = false

	opened := make(chan data.Database, 1)
	t.Cleanup(func() {
		select {
		case db := <-opened:
			closeStarted(db)
		default:
		}
	})

	done := make(chan startResult, 1)
	go func() {
		db, err := datafactory.NewDatabase(context.Background(), &cfg, dataKey, nil, false)
		if db != nil {
			opened <- db
		}
		done <- startResult{err: err}
	}()
	return done
}

// closeStarted closes the pool a start opened.
func closeStarted(db data.Database) {
	switch concrete := db.(type) {
	case *mysqldb.Database:
		_ = concrete.DB.Close()
	case *postgresdb.Database:
		_ = concrete.DB.Close()
	case *mssqldb.Database:
		_ = concrete.DB.Close()
	}
}

// awaitRecord waits until the start writes message, failing if the start ends first or does not
// get there within migrationLockRecordBudget.
func awaitRecord(t *testing.T, capture *logtest.SlogCapture, done <-chan startResult, message string) {
	t.Helper()
	deadline := time.After(migrationLockRecordBudget)
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		if len(recordsNamed(capture, message)) > 0 {
			return
		}
		select {
		case res := <-done:
			t.Fatalf("the start ended (answering %v) without writing %q while another session held the migration lock on %s",
				res.err, message, dbType())
		case <-deadline:
			t.Fatalf("the start did not write %q within %s while another session held the migration lock on %s",
				message, migrationLockRecordBudget, dbType())
		case <-tick.C:
		}
	}
}

func recordsNamed(capture *logtest.SlogCapture, message string) []logtest.CapturedRecord {
	var found []logtest.CapturedRecord
	for _, r := range capture.Records() {
		if r.Message == message {
			found = append(found, r)
		}
	}
	return found
}

// messageOrder is the captured messages among wanted, in the order they were written.
func messageOrder(capture *logtest.SlogCapture, wanted ...string) []string {
	keep := map[string]bool{}
	for _, w := range wanted {
		keep[w] = true
	}
	var order []string
	for _, r := range capture.Records() {
		if keep[r.Message] {
			order = append(order, r.Message)
		}
	}
	return order
}

// TestMigrationLock_ThePreCreateGivesTheResourceBack covers the one place outside the runner
// that takes the migration lock: SQL Server's schema_migrations pre-create, which is a catalog
// check followed by a CREATE and is safe only while the lock is held (#293).
//
// It holds the same resource on the same instance, so it owes the same two things Migrator.run
// owes and for the same reasons: the lock has to come back, and a session that failed to give it
// back must not return to the pool. NewMigrator is where that happens, and newIsolatedDB already
// called it, so this drops the table that construction created, asks a SECOND construction
// against the same database and then takes the resource from a pool of its own. The drop is what
// puts the lock under test: a pre-create finding the table already there takes no lock at all,
// since there is nothing to create and the lock may be held by another process's migration, which
// the start then waits for in the runner, where it says so (#390 decision 7).
//
// SQL Server only. It is the only engine whose pre-create reaches for the lock at all: the other
// three create the table with a plain IF NOT EXISTS, which their engines make atomic.
//
// Run via: ./run-tests.sh --type data --db mssql --run TestMigrationLock
func TestMigrationLock_ThePreCreateGivesTheResourceBack(t *testing.T) {
	if dbType() != data.MSSQL {
		t.Skipf("%s pre-creates schema_migrations without a lock: only SQL Server has no atomic form of that check-then-create", dbType())
	}

	h := newIsolatedDB(t)
	eng := migrationLockEngine(t, h.Name)

	_, err := h.SQL.Exec("DROP TABLE schema_migrations")
	require.NoError(t, err, "clear the table the fixture's own construction created")

	// The pre-create runs inside NewMigrator, so this is what puts the lock ceremony under test
	// rather than the runner's own.
	_, err = h.DB.NewMigrator(context.Background())
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
	if dbType() != data.MSSQL {
		t.Skipf("%s pre-creates schema_migrations without a lock: only SQL Server has no atomic form of that check-then-create", dbType())
	}

	for _, failDDL := range []bool{false, true} {
		name := "the create succeeds"
		if failDDL {
			name = "the create fails too"
		}
		t.Run(name, func(t *testing.T) {
			h := newIsolatedDB(t)
			db, ok := h.DB.(*mssqldb.Database)
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

			_, err = db.NewMigrator(context.Background())
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
	cfg := &appConfig.Database

	connector, err := mssql.NewConnector(msSQLDatabaseDSN(cfg.Username, cfg.Password, name, cfg))
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
	case data.MySQL, data.Postgres, data.MSSQL:
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
	case data.MySQL:
		return migrator.MySQL(name)
	case data.Postgres:
		return migrator.Postgres(name)
	case data.MSSQL:
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
	cfg := &appConfig.Database

	switch dbType() {
	case data.MySQL:
		db, err := mysqldb.New(context.Background(), &mysqldb.DatabaseConfig{
			Username: cfg.Username, Password: cfg.Password,
			Host: cfg.Host, Port: cfg.Port, Name: name, Create: false,
		}, false)
		require.NoErrorf(t, err, "open a second pool to %s", name)
		t.Cleanup(func() { _ = db.DB.Close() })
		return db.DB

	case data.Postgres:
		db, err := postgresdb.New(context.Background(), &postgresdb.DatabaseConfig{
			Username: cfg.Username, Password: cfg.Password,
			Host: cfg.Host, Port: cfg.Port, Name: name, Create: false,
		}, false)
		require.NoErrorf(t, err, "open a second pool to %s", name)
		t.Cleanup(func() { _ = db.DB.Close() })
		return db.DB

	case data.MSSQL:
		db, err := mssqldb.New(context.Background(), &mssqldb.DatabaseConfig{
			Username: cfg.Username, Password: cfg.Password,
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
