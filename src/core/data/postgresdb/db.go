package postgresdb

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"hash/fnv"
	"log/slog"
	"strings"

	gomigrate "github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/huandu/go-sqlbuilder"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/leodip/goiabada/core/data/commondb"
	"github.com/pkg/errors"
)

//go:embed migrations/*.sql
var postgresMigrationsFs embed.FS

type PostgresDatabase struct {
	DB       *sql.DB
	CommonDB *commondb.CommonDatabase
	dbConfig *DatabaseConfig
}

type DatabaseConfig struct {
	Type     string
	Username string
	Password string
	Host     string
	Port     int
	Name     string
	DSN      string
	// Create decides whether the constructor may create the database when it is absent. It is
	// positive-sense, so the zero value does not create: every literal has to set it (#293).
	Create bool
}

func NewPostgresDatabase(dbConfig *DatabaseConfig, logSQL bool) (*PostgresDatabase, error) {

	slog.Info("using database postgres")
	slog.Info(fmt.Sprintf("db username: %v", dbConfig.Username))
	slog.Info(fmt.Sprintf("db host: %v", dbConfig.Host))
	slog.Info(fmt.Sprintf("db port: %v", dbConfig.Port))
	slog.Info(fmt.Sprintf("db name: %v", dbConfig.Name))

	dbURL := fmt.Sprintf("postgres://%v:%v@%v:%v/%v",
		dbConfig.Username,
		dbConfig.Password,
		dbConfig.Host,
		dbConfig.Port,
		dbConfig.Name)

	// Open with database/sql for commondb compatibility
	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		return nil, errors.Wrap(err, "unable to open database")
	}

	if dbConfig.Create {
		// Create database if not exists.
		//
		// Serialized, because PostgreSQL's CREATE DATABASE does NOT tolerate being raced. With
		// the database absent, 7 of 8 concurrent creators fail with `duplicate key value
		// violates unique constraint "pg_database_datname_index"` (SQLSTATE 23505), whose text
		// does not contain "already exists" and so is not tolerated below: the loser returns
		// "unable to create database" and the process exits. Two replicas starting together
		// against a fresh server is an ordinary topology, not a hypothetical one (#293).
		defaultDB, err := sql.Open("pgx", fmt.Sprintf("postgres://%v:%v@%v:%v/postgres",
			dbConfig.Username,
			dbConfig.Password,
			dbConfig.Host,
			dbConfig.Port))
		if err != nil {
			return nil, errors.Wrap(err, "unable to connect to default database")
		}
		defer func() { _ = defaultDB.Close() }()

		if err := createDatabaseUnderAdvisoryLock(defaultDB, dbConfig.Name); err != nil {
			return nil, err
		}
	} else {
		// The operator says the database is already there, so nothing is created and no
		// connection is opened to the postgres maintenance database: a role owning the
		// application database and holding no CREATEDB is enough to start, which is what the
		// production checklist's "don't use root/admin accounts" asks for and what this
		// engine refused to allow before (#293).
		slog.Info("db create: disabled, the database must already exist (GOIABADA_DB_CREATE=false)")

		// sql.Open only parses the URL, so without this an absent database would come back as
		// a usable handle and a nil error, and the failure would surface inside the migrator
		// as somebody else's problem. Ping forces first use here, so the caller gets
		// PostgreSQL's own `database "x" does not exist (SQLSTATE 3D000)` from the
		// constructor. Not on the creating arm, where the CREATE DATABASE above already forces
		// the question.
		if err := db.Ping(); err != nil {
			_ = db.Close()
			return nil, errors.Wrap(err, "unable to connect to database")
		}
	}

	commonDb := commondb.NewCommonDatabase(db, sqlbuilder.PostgreSQL, logSQL)

	postgresDb := PostgresDatabase{
		DB:       db,
		CommonDB: commonDb,
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
		return false, errors.Wrap(err, "unable to check whether the database exists")
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
// The lock is untimed, so a stuck holder blocks startup rather than failing it. Accepted in #293
// decision 5, the same trade the migration lock one layer down already makes: what it spans is
// one catalog read and one CREATE DATABASE.
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
func createDatabaseUnderAdvisoryLock(maintenanceDB *sql.DB, name string) error {
	ctx := context.Background()

	exists, err := databaseExists(ctx, maintenanceDB, name)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	conn, err := maintenanceDB.Conn(ctx)
	if err != nil {
		return errors.Wrap(err, "unable to pin a connection for the database creation lock")
	}
	defer func() { _ = conn.Close() }()

	key := AdvisoryLockKey(name)
	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", key); err != nil {
		return errors.Wrap(err, "unable to take the database creation lock")
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
	if _, err := conn.ExecContext(ctx, fmt.Sprintf("CREATE DATABASE %v;", name)); err != nil &&
		!strings.Contains(err.Error(), "already exists") {
		return errors.Wrap(err, "unable to create database")
	}
	return nil
}

func (d *PostgresDatabase) BeginTransaction() (*sql.Tx, error) {
	return d.CommonDB.BeginTransaction()
}

func (d *PostgresDatabase) CommitTransaction(tx *sql.Tx) error {
	return d.CommonDB.CommitTransaction(tx)
}

func (d *PostgresDatabase) RollbackTransaction(tx *sql.Tx) error {
	return d.CommonDB.RollbackTransaction(tx)
}

// NewMigrator builds a golang-migrate instance bound to this database and the
// embedded migration files. Migrate delegates to it; tests use it to step to a
// specific version (e.g. seed at 000020, then apply 000021 in isolation).
// schemaMigrationsTableDDL pins the shape of golang-migrate's own version table, which
// Goiabada creates before handing the database over rather than leaving to the driver
// (#284 decision 7). It is the statement golang-migrate v4.19.1's PostgreSQL driver would
// issue itself, verbatim, and the driver reaches it behind an information_schema count.
//
// Issuing it first makes the driver's own statement a no-op and the shape Goiabada's, so
// this table has one shape on all four engines and a dependency bump that changed the
// driver's DDL cannot silently change what Goiabada builds. SQLite is the engine where this
// actually differs today; here it pins what is already true.
//
// Unqualified, so it lands in the connection's current schema, which is the same one
// postgres.WithInstance resolves through CURRENT_SCHEMA().
const schemaMigrationsTableDDL = "CREATE TABLE IF NOT EXISTS schema_migrations " +
	"(version bigint not null primary key, dirty boolean not null)"

// ensureSchemaMigrationsTable creates the version table at Goiabada's shape when it is not
// there yet.
func (d *PostgresDatabase) ensureSchemaMigrationsTable() error {
	if _, err := d.DB.Exec(schemaMigrationsTableDDL); err != nil {
		return errors.Wrap(err, "unable to create the schema_migrations table")
	}
	return nil
}

func (d *PostgresDatabase) NewMigrator() (*gomigrate.Migrate, error) {
	if err := d.ensureSchemaMigrationsTable(); err != nil {
		return nil, err
	}

	driver, err := postgres.WithInstance(d.DB, &postgres.Config{
		DatabaseName: d.dbConfig.Name,
	})
	if err != nil {
		return nil, errors.Wrap(err, "unable to create migration driver")
	}

	iofs, err := iofs.New(postgresMigrationsFs, "migrations")
	if err != nil {
		return nil, errors.Wrap(err, "unable to create migration filesystem")
	}

	migrator, err := gomigrate.NewWithInstance("iofs", iofs, "postgres", driver)
	if err != nil {
		return nil, errors.Wrap(err, "unable to create migration instance")
	}
	return migrator, nil
}

func (d *PostgresDatabase) Migrate() error {
	migrator, err := d.NewMigrator()
	if err != nil {
		return err
	}

	err = migrator.Up()
	if err != nil && err != gomigrate.ErrNoChange {
		return errors.Wrap(err, "unable to migrate the database")
	} else if err != nil && err == gomigrate.ErrNoChange {
		slog.Info("no need to migrate the database")
	}

	return nil
}

func (d *PostgresDatabase) IsEmpty() (bool, error) {
	return d.CommonDB.IsEmpty()
}
