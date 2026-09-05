package datatests

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/data/mssqldb"
	"github.com/stretchr/testify/require"
)

// #139 STAGE 8: THE ORDERING MEASURED WITH READ_COMMITTED_SNAPSHOT ON.
//
// Every ordering measurement on this branch was taken on SQL Server as the dev container creates
// it, which means READ_COMMITTED_SNAPSHOT OFF. That is the default for a database made by CREATE
// DATABASE and it is not what every deployment runs: RCSI is a common operational choice, and it
// changes SQL Server's READ COMMITTED from taking shared read locks to serving row versions. The
// complaint is an untested configuration rather than a known defect.
//
// WHY THE ORDERING IS EXPECTED TO SURVIVE. The guarantee rests on both parties issuing a WRITE
// against the same user_sessions row before touching anything else. RCSI changes readers, not
// writers: two writes to one row still queue behind each other, and a writer released from that
// queue re-reads the current committed row rather than its snapshot. AcquireUserSessionRow is an
// UPDATE and the termination's DELETE is a write, so the mechanism is untouched. Two further
// reason for the same expectation: PostgreSQL's READ COMMITTED is already the snapshot-reads
// configuration, with no shared read locks at all, and this branch is green there.
//
// WHAT DOES NOT FOLLOW, and is why the client-deletion gates run here as well rather than only
// the issuance pair. It is tempting to argue that RCSI can only remove lock conflicts, never add
// one, so a cycle that does not form with it off cannot appear with it on. Removing a conflict
// changes which interleavings are REACHABLE: a transaction that no longer stops at a read goes on
// to ask for locks it never previously reached, and a cycle can close there. DeleteClient holds
// that shape, a plain association read between its exclusive client acquisition and the session
// rows it takes next.
//
// None of the above is a measurement, which is why this file exists.
//
// WHAT THE FOLLOW-UP DRAFT ALSO RAISED, AND WHY IT IS NOT REACHABLE. SNAPSHOT isolation reports a
// write-write conflict as error 3960, an abort rather than a wait, and nothing in the repository
// handles 3960. It cannot arrive: commondb.BeginTransaction calls d.DB.Begin(), which is BeginTx
// with sql.LevelDefault, and no code anywhere sets a transaction isolation level. A transaction
// runs under SNAPSHOT only if the client asks for it, so ALLOW_SNAPSHOT_ISOLATION ON alone changes
// nothing for Goiabada whatever an operator sets it to. RCSI is different, and is the whole of the
// real exposure, because it changes what READ COMMITTED means without the application asking for
// anything.
//
// THE STOPPING RULE. If a measurement here contradicts the expectation above, the answer is not a
// fix invented on the spot: either the ordering needs a primitive that does not depend on
// lock-based READ COMMITTED, or the documentation has to say RCSI is unsupported, and both are
// design decisions rather than repairs.

const (
	// rcsiStatementTimeout bounds the ALTER DATABASE. SQL Server will not change
	// READ_COMMITTED_SNAPSHOT while another connection is open on the database, and
	// ALTER DATABASE ... COLLATE has already been seen to block for that family of reason on the
	// shared fixture. A fixture that cannot get exclusive access must FAIL rather than hang the
	// tier.
	rcsiStatementTimeout = 30 * time.Second

	// rcsiConnectTimeout bounds the master connection and the read-back.
	rcsiConnectTimeout = 15 * time.Second
)

type rcsiFixture struct {
	// primary and secondary are two data.Database handles over the SAME database, because the
	// interleavings need two connections and secondDatabase points at the shared one.
	primary   data.Database
	secondary data.Database
	name      string
}

var (
	rcsiOnce     sync.Once
	rcsiBuilt    *rcsiFixture
	rcsiBuildErr error
)

// rcsiDatabase returns the package's RCSI fixture, building it on first use and skipping the
// calling test on every engine that has no such setting.
//
// BUILT ONCE FOR THE PACKAGE rather than per test, deliberately. Looping isolated-database
// fixtures has exhausted this container's SQL Server memory pool before, and it presents as a hang
// on an unrelated test rather than as anything that names the cause. Its database is dropped from
// TestMain, because a fixture that outlives every individual test cannot register teardown on a T.
func rcsiDatabase(t *testing.T) *rcsiFixture {
	t.Helper()

	if dbType() != "mssql" {
		t.Skip("READ_COMMITTED_SNAPSHOT is a SQL Server setting: PostgreSQL and MySQL are MVCC already, and SQLite has one writer")
	}

	rcsiOnce.Do(func() { rcsiBuilt, rcsiBuildErr = buildRCSIFixture() })

	require.NoError(t, rcsiBuildErr, "building the RCSI fixture")
	require.NotNil(t, rcsiBuilt)
	return rcsiBuilt
}

// buildRCSIFixture creates a database, turns RCSI on, CONFIRMS it is on, and only then opens the
// handles that migrate it. The order is the whole of this function and none of it is inherited
// from newIsolatedDB, which cannot be reused unchanged: that helper calls NewMigrator, whose
// sqlserver.WithInstance reserves a connection for the life of the migrator and releases it only
// at cleanup, so an ALTER DATABASE afterwards would be a second connection waiting on the
// fixture's own reserved one.
func buildRCSIFixture() (*rcsiFixture, error) {
	cfg := config.GetDatabase()
	name := isolatedDBName()

	// 1. Create the database through the constructor the migration fixtures use, so it lands at
	//    the collation #283 pins, and then let go of it completely.
	//
	//    NOT data.NewDatabase, and the difference is not cosmetic. That entry point runs the
	//    migration chain and the startup data tasks, neither of which this step wants, and it
	//    returns the data.Database interface, which declares no Close: the pool it opened would
	//    stay open for the life of the process and step 2 would be an ALTER DATABASE evicting
	//    this function's own connections. The concrete constructor creates the database and
	//    nothing else, and it exposes the *sql.DB, so "let go of it completely" is a statement
	//    that actually runs and is checked.
	created, err := mssqldb.NewMsSQLDatabase(&mssqldb.DatabaseConfig{
		Type:     "mssql",
		Username: cfg.Username,
		Password: cfg.Password,
		Host:     cfg.Host,
		Port:     cfg.Port,
		Name:     name,
		Create:   true,
	}, false)
	if err != nil {
		return nil, fmt.Errorf("creating the RCSI database %s: %w", name, err)
	}

	deferPackageTeardown(func() { dropRCSIDatabase(cfg, name) })

	if err := created.DB.Close(); err != nil {
		return nil, fmt.Errorf("releasing the pool that created %s: %w", name, err)
	}

	// 2. Turn RCSI on from master, with a deadline, so a fixture that cannot get exclusive access
	//    fails instead of hanging. WITH ROLLBACK IMMEDIATE stays even though step 1 now closes
	//    its pool: Close returns once the driver has begun tearing the connections down, and a
	//    stray session from a previous run of this fixture would otherwise make the ALTER wait.
	master, err := sql.Open("sqlserver", msSQLMasterDSN(cfg))
	if err != nil {
		return nil, fmt.Errorf("connecting to master: %w", err)
	}
	defer func() { _ = master.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), rcsiStatementTimeout)
	defer cancel()
	alter := fmt.Sprintf("ALTER DATABASE [%s] SET READ_COMMITTED_SNAPSHOT ON WITH ROLLBACK IMMEDIATE", name)
	if _, err := master.ExecContext(ctx, alter); err != nil {
		return nil, fmt.Errorf("turning READ_COMMITTED_SNAPSHOT on for %s: %w", name, err)
	}

	// 3. READ IT BACK, and this step is not ceremony. A fixture that quietly failed to apply the
	//    setting would make this whole file a second run of the tests we already have, reported as
	//    new evidence, which is worse than not running it at all.
	on, err := readRCSIFlag(master, name)
	if err != nil {
		return nil, err
	}
	if !on {
		return nil, fmt.Errorf("sys.databases reports READ_COMMITTED_SNAPSHOT still off for %s after the ALTER succeeded", name)
	}

	// 4. Only now the two handles, each of which migrates the chain and runs the startup tasks.
	//    Both are closed from the package teardown, registered AFTER the drop so it runs last:
	//    a DROP DATABASE behind two live pools would have to evict them, and this way there is
	//    nothing left to evict.
	primary, err := data.NewDatabase(rcsiConfig(cfg, name), false)
	if err != nil {
		return nil, fmt.Errorf("opening the RCSI fixture's first handle: %w", err)
	}
	deferPackageTeardown(func() { closeRCSIHandle(primary) })

	secondary, err := data.NewDatabase(rcsiConfig(cfg, name), false)
	if err != nil {
		return nil, fmt.Errorf("opening the RCSI fixture's second handle: %w", err)
	}
	deferPackageTeardown(func() { closeRCSIHandle(secondary) })

	return &rcsiFixture{primary: primary, secondary: secondary, name: name}, nil
}

// rcsiConfig is the fixture's database, never created by the handle that opens it: creation is
// step 1's job and has to be finished, and read back, before anything migrates it.
func rcsiConfig(cfg *config.DatabaseConfig, name string) *config.DatabaseConfig {
	return &config.DatabaseConfig{
		Type:     "mssql",
		Username: cfg.Username,
		Password: cfg.Password,
		Host:     cfg.Host,
		Port:     cfg.Port,
		Name:     name,
		Create:   false,
	}
}

// closeRCSIHandle releases one fixture pool. data.Database declares no Close, so the pool is
// reached through the concrete type, which is known here: this fixture is SQL Server only.
func closeRCSIHandle(db data.Database) {
	if concrete, ok := db.(*mssqldb.MsSQLDatabase); ok {
		_ = concrete.DB.Close()
	}
}

func readRCSIFlag(master *sql.DB, name string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rcsiConnectTimeout)
	defer cancel()

	var on bool
	err := master.QueryRowContext(ctx,
		"SELECT is_read_committed_snapshot_on FROM sys.databases WHERE name = @p1", name).Scan(&on)
	if err != nil {
		return false, fmt.Errorf("reading is_read_committed_snapshot_on for %s: %w", name, err)
	}
	return on, nil
}

func dropRCSIDatabase(cfg *config.DatabaseConfig, name string) {
	master, err := sql.Open("sqlserver", msSQLMasterDSN(cfg))
	if err != nil {
		return
	}
	defer func() { _ = master.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), rcsiStatementTimeout)
	defer cancel()
	_, _ = master.ExecContext(ctx, fmt.Sprintf(
		"IF DB_ID(N'%s') IS NOT NULL BEGIN ALTER DATABASE [%s] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [%s]; END",
		name, name, name))
}

// TestRCSI_TheFixtureIsTheDatabaseUnderTest is the check that catches the mistake the handle
// threading can silently make.
//
// Every seeder and assertion this file's tests use now has an ...On(db, ...) form, with the
// original name delegating to it with the package handle. A helper left on the package handle
// while the rest of a test runs against this fixture is not a compile error and not obviously a
// failure either: identity columns on two SQL Server databases hand out the same numeric ids, so
// a reload of "id 7" finds a different row of the same shape and the assertion passes for the
// wrong reason.
//
// So the fixture states its own identity: rows created here are visible on this handle and absent
// from the package handle, and the RCSI flag really is on.
func TestRCSI_TheFixtureIsTheDatabaseUnderTest(t *testing.T) {
	f := rcsiDatabase(t)

	user := createTestUserOn(t, f.primary)

	mine, err := f.primary.GetUserById(nil, user.Id)
	require.NoError(t, err, "reloading the seeded user on the fixture's own handle")
	require.NotNil(t, mine, "a row seeded on the fixture must be visible there")
	require.Equal(t, user.Subject, mine.Subject)

	// The same id on the shared database is either absent or a different user. Both are correct
	// answers; what would be wrong is finding THIS user, which is what a seeder left on the
	// package handle would produce.
	theirs, err := database.GetUserById(nil, user.Id)
	require.NoError(t, err, "reloading the same id on the package handle")
	if theirs != nil {
		require.NotEqual(t, user.Subject, theirs.Subject,
			"a row seeded on the RCSI fixture must not be found on the package's shared database: "+
				"a helper still pointing at the global would make every assertion in this file read the wrong database")
	}

	// And the configuration under test is actually in force.
	master, err := sql.Open("sqlserver", msSQLMasterDSN(config.GetDatabase()))
	require.NoError(t, err)
	defer func() { _ = master.Close() }()
	on, err := readRCSIFlag(master, f.name)
	require.NoError(t, err)
	require.True(t, on, "the fixture's whole purpose is that READ_COMMITTED_SNAPSHOT is on")
}
