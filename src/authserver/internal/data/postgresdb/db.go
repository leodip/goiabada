// Package postgresdb is the PostgreSQL adapter: the constructor that opens, and when asked
// creates, the application database, the migration chain PostgreSQL runs, and the handful of
// Database methods whose SQL differs from commondb's. Everything else is promoted from the
// embedded common implementation.
package postgresdb

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"strings"

	"github.com/huandu/go-sqlbuilder"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/commondb"
	"github.com/leodip/goiabada/authserver/internal/data/migrator"
	"github.com/leodip/goiabada/core/errs"
)

//go:embed migrations/*.sql
var postgresMigrationsFs embed.FS

// Database declares only the methods PostgreSQL needs its own SQL for; the rest are promoted
// from the embedded common implementation. See commondb.Database for what embedding does
// and does not buy (#416).
type Database struct {
	*commondb.Database
	dbConfig *DatabaseConfig
}

// The compiler holds the adapter to the whole interface here, in its own package, so an engine
// missing a method fails where the method is missing rather than only where datafactory hands
// the adapter out (#438).
var _ data.Database = (*Database)(nil)

// DatabaseConfig is what PostgreSQL reads to connect: the credentials, the address, the database
// name, and whether it may create that database (#438 decision 3).
type DatabaseConfig struct {
	Username string
	Password string
	Host     string
	Port     int
	Name     string
	// Create decides whether the constructor may create the database when it is absent. It is
	// positive-sense, so the zero value does not create: every literal has to set it (#293).
	Create bool
	// Pool is the application database's connection pool; the maintenance connection a creating
	// start opens is not under it. nil leaves database/sql's own pool, unlimited, which only the
	// tools and the data tier's fixtures that call this constructor directly open with: the
	// server's comes through datafactory, which always passes one (#394).
	Pool *data.PoolConfig
}

// New opens the PostgreSQL database dbConfig names, creating it first when dbConfig.Create says
// so. Every statement it issues runs under ctx, the caller's, the creation lock's wait included,
// so a start held behind that lock ends when the caller stops waiting (#438 decision 3).
func New(ctx context.Context, dbConfig *DatabaseConfig, logSQL bool) (*Database, error) {

	// One record where five used to be, and no password: the URL is assembled below from the
	// same four values, so a startup problem is read off this line rather than off four
	// consecutive ones that a collector had no way to join (#320 decision 6).
	slog.InfoContext(ctx, "using database", "type", "postgres", "username", dbConfig.Username,
		"host", dbConfig.Host, "port", dbConfig.Port, "name", dbConfig.Name)

	if dbConfig.Create {
		// Create database if not exists.
		//
		// Serialized, because PostgreSQL's CREATE DATABASE does NOT tolerate being raced. With
		// the database absent, 7 of 8 concurrent creators fail with `duplicate key value
		// violates unique constraint "pg_database_datname_index"` (SQLSTATE 23505), which is not
		// the 42P04 isDuplicateDatabase tolerates below: the loser returns
		// "unable to create database" and the process exits. Two replicas starting together
		// against a fresh server is an ordinary topology, not a hypothetical one (#293).
		defaultDB, err := sql.Open("pgx", MaintenanceDSN(dbConfig))
		if err != nil {
			return nil, errs.Wrap(err, "unable to connect to default database")
		}
		defer func() { _ = defaultDB.Close() }()

		if err := createDatabaseUnderAdvisoryLock(ctx, defaultDB, dbConfig.Name); err != nil {
			return nil, err
		}
	} else {
		// The operator says the database is already there, so nothing is created and no
		// connection is opened to the postgres maintenance database: a role owning the
		// application database and holding no CREATEDB is enough to start, which is what the
		// production checklist's "don't use root/admin accounts" asks for and what this
		// engine refused to allow before (#293).
		slog.InfoContext(ctx, "database creation is disabled, so the database must already exist", "setting", "GOIABADA_DB_CREATE")
	}

	// Opened after the creating arm, as MySQL and SQL Server open theirs, so a creation that
	// fails or gives up at the caller's deadline returns before there is a pool to leave open:
	// opened first, each of those two returns abandoned it, a goroutine and a handle nobody
	// could close (#438).
	db, err := sql.Open("pgx", DSN(dbConfig))
	if err != nil {
		return nil, errs.Wrap(err, "unable to open database")
	}
	if dbConfig.Pool != nil {
		dbConfig.Pool.ApplyTo(db)
	}

	if !dbConfig.Create {
		// sql.Open only parses the URL, so without this an absent database would come back as
		// a usable handle and a nil error, and the failure would surface inside the migrator
		// as somebody else's problem. Ping forces first use here, so the caller gets
		// PostgreSQL's own `database "x" does not exist (SQLSTATE 3D000)` from the
		// constructor. Not on the creating arm, where the CREATE DATABASE above already forces
		// the question.
		if err := db.PingContext(ctx); err != nil {
			_ = db.Close()
			return nil, errs.Wrap(err, "unable to connect to database")
		}
	}

	commonDb := commondb.New(db, sqlbuilder.PostgreSQL, logSQL)
	commonDb.IsDeadlock = isDeadlock
	commonDb.IsUniqueViolation = isUniqueViolation
	commonDb.InsertReturningIdSQL = insertReturningIdSQL
	commonDb.ExplicitIdInsertSQL = explicitIdInsertSQL

	postgresDb := Database{
		Database: commonDb,
		dbConfig: dbConfig,
	}
	return &postgresDb, nil
}

// advisoryLockNamespace keeps this lock's keys away from any other advisory lock a session on
// the maintenance database might take. Advisory locks share one 64-bit key space per database.
const advisoryLockNamespace = "goiabada:create-database:"

// AdvisoryLockKey derives the key createDatabaseUnderAdvisoryLock serializes on, from the name
// of the database being created.
//
// FNV-1a computed in Go rather than through the server's own hashtextextended, so it needs no
// minimum server version and is stable by construction: every Goiabada process racing for one
// database name arrives at the same key without asking the server anything. The key is an opaque
// identity, so the uint64 to int64 wrap that pg_advisory_lock's bigint argument forces is
// deliberate and costs nothing.
//
// Keyed by NAME, unlike the SQL Server lock one file over, which is keyed by a constant. That
// asymmetry is intentional and is not a thing to tidy: pg_database.datname is compared
// byte-exact, so this key is exactly as precise as the catalog check it guards. SQL Server
// compares sys.databases.name under master's collation, which folds case and more, and no
// Go-side key can be made to agree with that (#293).
//
// Exported because the key is an inter-process contract rather than an implementation detail:
// anything that has to interoperate with a starting Goiabada, a test holding the lock from
// outside included, needs the identity itself and cannot re-derive it without becoming a second
// definition that is free to drift.
func AdvisoryLockKey(name string) int64 {
	h := fnv.New64a()
	// hash.Hash documents that Write never returns an error.
	_, _ = h.Write([]byte(advisoryLockNamespace + name))
	//nolint:gosec // G115: the sum is reinterpreted as a lock key on purpose; any bit pattern is a valid key
	return int64(h.Sum64())
}

// rowQuerier is the one method databaseExists needs, so that the same predicate can be asked of
// the maintenance pool and of the single connection the lock is held on.
type rowQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// databaseExists asks pg_database whether name is there.
//
// datname is compared byte-exact, which is what lets AdvisoryLockKey be derived from the name:
// the key is exactly as precise as this check. Called twice per creating start, once outside
// the lock to decide whether the lock is needed at all and once inside it to decide whether to
// create. One function, so the two can never disagree (#293).
func databaseExists(ctx context.Context, q rowQuerier, name string) (bool, error) {
	var found int
	if err := q.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM pg_database WHERE datname = $1", name).Scan(&found); err != nil {
		return false, errs.Wrap(err, "unable to check whether the database exists")
	}
	return found > 0, nil
}

// createDatabaseUnderAdvisoryLock creates the application database when it is not there, holding
// an exclusive advisory lock across the check and the create so that at most one process ever
// issues CREATE DATABASE.
//
// The lock, the check and the create all run on ONE connection pinned out of the maintenance
// pool. A session-level advisory lock belongs to the session that took it, so a lock taken
// through the pooled *sql.DB could be released on a different connection and stay held for the
// life of the process, blocking every later start. Same hazard, same remedy, as the
// sp_getapplock the SQL Server driver takes around its own version table (#284).
//
// Advisory locks live in a key space scoped to the database the session is connected to, and
// every racer here is connected to `postgres`. That shared space is the whole reason this works.
//
// The lock has no timeout of its own, so a stuck holder blocks startup rather than failing it.
// Accepted in #293 decision 5, the same trade the migration lock one layer down already makes:
// what it spans is one catalog read and one CREATE DATABASE. The wait is the caller's, though: it
// runs under ctx, and pgx abandons it when ctx ends, leaving the pool usable (#438 decision 3).
// The release below runs under the same ctx and may then fail, which leaves nothing held: the
// lock belongs to a session of the maintenance pool, and New closes that pool on its way out.
//
// That trade is only affordable because the lock is reached ONLY when the database is absent.
// An advisory lock taken in the `postgres` maintenance database shares one key space with every
// session on the server, so ANY role that can connect there can hold this key indefinitely,
// including a role with no rights whatsoever inside Goiabada's own database. Taking it
// unconditionally would put that stranger on the path of every ordinary restart for the life of
// the deployment, which is not the cost decision 5 weighed. The unlocked pre-check below keeps
// the exposure inside the window where the database really is absent, which is the one start
// that has to create it (#293).
//
// The pre-check cannot let a second creator through. It only returns early when the database is
// already there, and what decides whether CREATE DATABASE runs is still the check taken under
// the lock. Both ask pg_database the same question through databaseExists, deliberately: two
// spellings of the same predicate could drift apart, and the outer one is only sound while it
// is no weaker than the inner one.
func createDatabaseUnderAdvisoryLock(ctx context.Context, maintenanceDB *sql.DB, name string) error {
	exists, err := databaseExists(ctx, maintenanceDB, name)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	conn, err := maintenanceDB.Conn(ctx)
	if err != nil {
		return errs.Wrap(err, "unable to pin a connection for the database creation lock")
	}
	defer func() { _ = conn.Close() }()

	key := AdvisoryLockKey(name)
	if _, execErr := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", key); execErr != nil {
		return errs.Wrap(execErr, "unable to take the database creation lock")
	}
	defer func() {
		_, _ = conn.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", key)
	}()

	exists, err = databaseExists(ctx, conn, name)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	// The "already exists" tolerance stays. Under the lock it no longer covers another Goiabada
	// process, which cannot be in here at the same time, but it still covers an operator running
	// createdb by hand inside the window, and it costs one condition.
	if _, err := conn.ExecContext(ctx, fmt.Sprintf("CREATE DATABASE %s;", quoteIdentifier(name))); err != nil &&
		!isDuplicateDatabase(err) {
		return errs.Wrap(err, "unable to create database")
	}
	return nil
}

// quoteIdentifier wraps name in the double quotes PostgreSQL spells an identifier with, doubling
// any double quote inside it.
//
// It is here because the name is used two ways that have to agree, and unquoted they do not.
// PostgreSQL down-cases an unquoted identifier, so CREATE DATABASE Goiabada creates `goiabada`,
// while the same string sits in the connection URL's path as a literal connection parameter and
// is not folded. GOIABADA_DB_NAME=Goiabada therefore used to create one database and then
// connect to another, failing with `database "Goiabada" does not exist (SQLSTATE 3D000)` on
// every start, for the life of the deployment, with the database it did create sitting next to
// the one it asked for. Quoting makes both halves spell the same thing, and settles the
// neighbouring case of a name that needs quotes for some other reason, a hyphen or a space,
// which was a syntax error.
//
// Nothing here changes for a lower-case name, which is what every existing deployment has: a
// name PostgreSQL would not have folded quotes to itself.
//
// pg_database.datname is compared byte-exact, so databaseExists and AdvisoryLockKey stay as they
// are and stay exactly as precise as this statement. That is the asymmetry with SQL Server, one
// file over, where the catalog folds and the lock resource has to be wider than the name.
//
// The doubling is the injection answer too. GOIABADA_DB_NAME is operator-supplied configuration
// rather than user input, so this is hardening and not a live hole, but an identifier cannot be
// passed as a bind parameter and this is the only thing that can be done about it.
func quoteIdentifier(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

// isDeadlock is PostgreSQL's half of RunInTransaction's classifier: SQLSTATE 40P01,
// deadlock_detected, which the server raises on the transaction it chose as the victim after
// rolling it back. 55P03, lock_not_available, is a lock wait that ran out and is deliberately
// not here: the row is still held, so rerunning would only wait again (#301).
func isDeadlock(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "40P01"
}

// PostgreSQL reports both of the conditions this file classifies as a SQLSTATE, and both were
// observed rather than remembered.
//
// pgUniqueViolation, 23505, is what a write colliding with a unique index returns: the probe
// recorded `*pgconn.PgError "duplicate key value violates unique constraint" (SQLSTATE 23505)`.
// pgDuplicateDatabase, 42P04, is what CREATE DATABASE returns when the name is taken (#279).
//
// The two are not interchangeable, and the comment in createDatabaseUnderAdvisoryLock says why:
// racing CREATE DATABASE statements do NOT lose with 42P04, they lose with 23505 on
// pg_database_datname_index. That is the reason the create is serialised by an advisory lock, and
// it is the reason isDuplicateDatabase accepts only 42P04 (#293).
const (
	pgUniqueViolation   = "23505"
	pgDuplicateDatabase = "42P04"
)

// isUniqueViolation is PostgreSQL's row of the unique-key classifier table commondb's wrapSQLError consults.
//
// pgconn.PgError has pointer receivers, so the pointer is the only form that is an error and the
// only form the driver returns; there is no value form to check.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation
}

// isDuplicateDatabase reports whether err is PostgreSQL refusing a CREATE DATABASE because that
// name already exists.
//
// It replaces a strings.Contains for "already exists" on the driver's English sentence. The text
// was never the engine's contract: it is localised by lc_messages, so an operator running a server
// with a non-English locale got a create failure the code did not recognise, and the process
// exited on a database that was already there. The SQLSTATE is the same five characters in every
// locale (#279).
func isDuplicateDatabase(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == pgDuplicateDatabase
}

// schemaMigrationsTableDDL pins the shape of the version table the runner keeps, which
// Goiabada creates before anything migrates rather than leaving to whatever applies the files
// (#284 decision 7). It is the statement golang-migrate v4.19.1's PostgreSQL driver would
// have itself, verbatim, and the driver reaches it behind an information_schema count.
//
// Issuing it first makes the driver's own statement a no-op and the shape Goiabada's, so
// this table has one shape on all four engines and a dependency bump that changed the
// driver's DDL cannot silently change what Goiabada builds. SQLite is the engine where this
// actually differs today; here it pins what is already true.
//
// Unqualified, so it lands in the connection's current schema, which is the same one the
// migration lock's resource name is computed over.
const schemaMigrationsTableDDL = "CREATE TABLE IF NOT EXISTS schema_migrations " +
	"(version bigint not null primary key, dirty boolean not null)"

// ensureSchemaMigrationsTable creates the version table at Goiabada's shape when it is not
// there yet.
func (d *Database) ensureSchemaMigrationsTable(ctx context.Context) error {
	if _, err := d.DB.ExecContext(ctx, schemaMigrationsTableDDL); err != nil {
		return errs.Wrap(err, "unable to create the schema_migrations table")
	}
	return nil
}

// NewMigrator builds a runner bound to this database and the embedded migration files.
// Startup brings it to head through UpToHead; tests use it to step to a specific version (e.g.
// seed at 000020, then apply 000021 in isolation).
//
// There is nothing to close. The runner takes a connection out of the pool for the duration
// of one operation and gives it back before returning (#268 decision 8).
//
// The Progress SQL Server's pre-create reports a lock wait to goes unused: the version table here is
// created by one idempotent statement, which waits for no migration lock.
func (d *Database) NewMigrator(ctx context.Context, _ migrator.Progress) (*migrator.Migrator, error) {
	if err := d.ensureSchemaMigrationsTable(ctx); err != nil {
		return nil, err
	}

	m, err := migrator.New(d.DB, postgresMigrationsFs, "migrations", migrator.Postgres(d.dbConfig.Name))
	if err != nil {
		return nil, errs.Wrap(err, "unable to create migration instance")
	}
	return m, nil
}
