package datafactory

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/migrator"
	"github.com/leodip/goiabada/authserver/internal/data/sqlitedb"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sourceConfig is one loaded GOIABADA_DB_* configuration in which no two values are equal.
//
// The distinctness is what makes the mapper tables below load-bearing. Six fields copied by
// hand is six chances to write one into another's place, and neither the engine's error nor
// the dispatch record can see the difference: a swapped Host and Name still answers `dial tcp`,
// and Password appears in no engine's error at all. With two fields sharing a value, a mapper
// writing one into the other's slot would still match.
func sourceConfig() *config.DatabaseConfig {
	return &config.DatabaseConfig{
		Type:     "source-type",
		Username: "source-username",
		Password: "source-password",
		Host:     "source-host",
		Port:     15432,
		Name:     "source-name",
		DSN:      "source-dsn",
		Create:   true,

		MaxOpenConns:    41,
		MaxIdleConns:    intPtr(17),
		ConnMaxLifetime: 43 * time.Minute,
		ConnMaxIdleTime: 7 * time.Minute,
	}
}

// sourcePool is the pool sourceConfig describes, written out rather than read off it, so a mapper
// that read the wrong field cannot agree with the expectation by construction.
var sourcePool = data.PoolConfig{
	MaxOpenConns:    41,
	MaxIdleConns:    17,
	ConnMaxLifetime: 43 * time.Minute,
	ConnMaxIdleTime: 7 * time.Minute,
}

func intPtr(n int) *int { return &n }

// poolOf is what a mapper put in an engine's Pool, nil included, so a mapper that left it out
// fails its row rather than panicking the table.
func poolOf(p *data.PoolConfig) any {
	if p == nil {
		return nil
	}
	return *p
}

// fieldCase is one field of one engine's configuration: where the mapper put it, and where the
// loaded configuration said it belongs.
type fieldCase struct {
	field string
	got   any
	want  any
}

// assertMapping runs one mapper's table and then pins how many fields the engine's own struct
// declares against how many the table checked.
//
// The count is not bookkeeping: a field added to an engine's DatabaseConfig and left out of the
// mapper is a setting an operator sets and the driver never receives, which produces no error
// anywhere. Here it is a failing test naming the engine.
func assertMapping(t *testing.T, engine string, mapped any, cases []fieldCase) {
	t.Helper()

	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			assert.Equalf(t, tc.want, tc.got,
				"%s's %s carries another field's value, which no engine error would reveal", engine, tc.field)
		})
	}

	declared := reflect.TypeOf(mapped).Elem().NumField()
	assert.Equalf(t, len(cases), declared,
		"%s.DatabaseConfig declares %d fields and this table checks %d: a field the mapper does not copy is a setting the operator sets and the driver never sees",
		engine, declared, len(cases))
}

// TestMysqlConfig_CopiesEveryField is seam 2 for MySQL: all seven fields, Create and the pool
// included. The loaded Type and DSN are not among them, because the engine reads neither, and the
// field count assertMapping pins is what says they stay out (#438 decision 3). SQLite has no
// mapper: its constructor takes the DSN alone, and its pool is its own (#394).
func TestMysqlConfig_CopiesEveryField(t *testing.T) {
	c := sourceConfig()
	got := mysqlConfig(c)

	assertMapping(t, "mysqldb", got, []fieldCase{
		{"Username", got.Username, c.Username},
		{"Password", got.Password, c.Password},
		{"Host", got.Host, c.Host},
		{"Port", got.Port, c.Port},
		{"Name", got.Name, c.Name},
		{"Create", got.Create, c.Create},
		{"Pool", poolOf(got.Pool), sourcePool},
	})
}

// TestPostgresConfig_CopiesEveryField is seam 2 for PostgreSQL.
func TestPostgresConfig_CopiesEveryField(t *testing.T) {
	c := sourceConfig()
	got := postgresConfig(c)

	assertMapping(t, "postgresdb", got, []fieldCase{
		{"Username", got.Username, c.Username},
		{"Password", got.Password, c.Password},
		{"Host", got.Host, c.Host},
		{"Port", got.Port, c.Port},
		{"Name", got.Name, c.Name},
		{"Create", got.Create, c.Create},
		{"Pool", poolOf(got.Pool), sourcePool},
	})
}

// TestMssqlConfig_CopiesEveryField is seam 2 for SQL Server.
func TestMssqlConfig_CopiesEveryField(t *testing.T) {
	c := sourceConfig()
	got := mssqlConfig(c)

	assertMapping(t, "mssqldb", got, []fieldCase{
		{"Username", got.Username, c.Username},
		{"Password", got.Password, c.Password},
		{"Host", got.Host, c.Host},
		{"Port", got.Port, c.Port},
		{"Name", got.Name, c.Name},
		{"Create", got.Create, c.Create},
		{"Pool", poolOf(got.Pool), sourcePool},
	})
}

// TestEngineConfigs_AnUnsetIdleCapFollowsTheOpenCap: with no idle cap configured, each server
// engine is given the open cap as its idle cap, so a busy pod keeps the connections it opened
// rather than closing and reopening them above a smaller idle cap (#394 decision 6).
func TestEngineConfigs_AnUnsetIdleCapFollowsTheOpenCap(t *testing.T) {
	c := sourceConfig()
	c.MaxIdleConns = nil
	want := data.PoolConfig{MaxOpenConns: 41, MaxIdleConns: 41, ConnMaxLifetime: 43 * time.Minute, ConnMaxIdleTime: 7 * time.Minute}

	assert.Equal(t, want, poolOf(mysqlConfig(c).Pool), "mysqldb")
	assert.Equal(t, want, poolOf(postgresConfig(c).Pool), "postgresdb")
	assert.Equal(t, want, poolOf(mssqlConfig(c).Pool), "mssqldb")
}

// TestOpenDatabase_SQLiteKeepsItsOneConnectionWhateverIsConfigured pins SQLite's pool, which the
// pool settings never reach: one open connection, one idle, no lifetime and no idle time, whatever
// the four settings say. The single connection is what the comments in issuance, refresh-token
// rotation and commondb reason from. The handle's own statistics show the open cap that took, and
// the start's pool record, the one place all four values are visible, says the same (#394).
func TestOpenDatabase_SQLiteKeepsItsOneConnectionWhateverIsConfigured(t *testing.T) {
	capture := logtest.CaptureSlog(t)
	cfg := &config.DatabaseConfig{
		Type:            "sqlite",
		DSN:             filepath.Join(t.TempDir(), "pool.db"),
		MaxOpenConns:    9,
		MaxIdleConns:    intPtr(8),
		ConnMaxLifetime: time.Hour,
		ConnMaxIdleTime: 2 * time.Hour,
	}

	database, err := OpenDatabase(context.Background(), cfg, false)
	require.NoError(t, err)
	concrete, ok := database.(*sqlitedb.Database)
	require.True(t, ok, "a sqlite type opens the sqlite engine")
	t.Cleanup(func() { _ = concrete.DB.Close() })

	assert.Equal(t, 1, concrete.DB.Stats().MaxOpenConnections, "SQLite runs on one connection whatever is configured")

	records := recordsNamed(capture, "database connection pool")
	require.Len(t, records, 1, "a start says once what pool it opened: %s", capture.Text())
	assert.Equal(t, slog.LevelInfo, records[0].Level, "the pool a start opened is configuration, which is Info")
	assert.Equal(t, map[string]any{
		"max_open_conns":     int64(1),
		"max_idle_conns":     int64(1),
		"conn_max_lifetime":  time.Duration(0),
		"conn_max_idle_time": time.Duration(0),
	}, records[0].Attrs, "the record shows SQLite's fixed values, not the configured ones")
	assert.Equal(t, []string{"opening the database", "database connection pool"},
		messageOrder(capture, "opening the database", "database connection pool"),
		"the pool is said once the engine has opened it")
}

// unreachable is a configuration pointed at a port nothing listens on, which is how every server
// engine below is made to fail in its own words without a live server. The probe behind decision 4
// measured the worst of these at 7ms.
func unreachable(dbType string, create bool) *config.DatabaseConfig {
	return &config.DatabaseConfig{
		Type:     dbType,
		Username: "u",
		Password: "p",
		Host:     "127.0.0.1",
		Port:     1,
		Name:     "x",
		Create:   create,
	}
}

// dispatchRecord returns the one "opening the database" record, failing the test when the switch
// wrote none or more than one. Every other record captured belongs to the engine that was
// reached, which is the thing under test and not something this helper should hide.
func dispatchRecord(t *testing.T, capture *logtest.SlogCapture) logtest.CapturedRecord {
	t.Helper()

	var found []logtest.CapturedRecord
	for _, record := range capture.Records() {
		if record.Message == "opening the database" {
			found = append(found, record)
		}
	}
	require.Lenf(t, found, 1, "want exactly one dispatch record, got %d: %v", len(found), capture.Text())
	return found[0]
}

// TestOpenDatabase_Dispatch is seam 1: which engine each configured name reaches, what Create
// does to the connection ordering inside that engine, and that the configured type reaches
// data.ParseDialect: one quoted row accepted, one refusal. Every other input to the parse is
// data.ParseDialect's own table (#438 decision 6).
//
// Every engine is observed through Goiabada's own errs.Wrap prefix and never through driver text.
// pgx leaking `user=u database=x` and go-sql-driver leaking `dial tcp 127.0.0.1:1` would be
// end-to-end evidence that the fields reach the driver, but they are third-party strings that
// churn on a dependency bump; decision 4 rejected resting on them.
//
// Three of the six server prefixes are unique to their engine and are what name the engine
// reached: "unable to create database" is MySQL's alone here, "unable to check whether the
// database exists" PostgreSQL's, "unable to connect to master database" SQL Server's. Each
// engine's pair of prefixes is what shows Create changing which connection is opened first,
// which an operator sees as a different error for the same server being down.
func TestOpenDatabase_Dispatch(t *testing.T) {
	tests := []struct {
		name string
		cfg  func(t *testing.T) *config.DatabaseConfig
		// wantType is the value of the dispatch record's type attribute, which is the parsed
		// dialect and never the engine reached. Empty for the refusal, which writes no record.
		wantType data.Dialect
		// wantErr is the whole error for the refusal and the errs.Wrap prefix for a failed open;
		// empty means the open must succeed.
		wantErr string
		exact   bool
		why     string
	}{
		{
			name:     "mysql opens the configured database when Create is off",
			cfg:      func(t *testing.T) *config.DatabaseConfig { return unreachable("mysql", false) },
			wantType: data.MySQL,
			wantErr:  "unable to connect to database",
			why:      "the only connection attempted is the configured one",
		},
		{
			name:     "mysql creates before connecting when Create is on",
			cfg:      func(t *testing.T) *config.DatabaseConfig { return unreachable("mysql", true) },
			wantType: data.MySQL,
			wantErr:  "unable to create database",
			why:      "Create reached mysqldb, which issues its CREATE DATABASE before opening the configured one",
		},
		{
			name:     "postgres opens the configured database when Create is off",
			cfg:      func(t *testing.T) *config.DatabaseConfig { return unreachable("postgres", false) },
			wantType: data.Postgres,
			wantErr:  "unable to connect to database",
			why:      "no maintenance connection is opened, so the configured database is the only one attempted",
		},
		{
			name:     "postgres asks the maintenance database first when Create is on",
			cfg:      func(t *testing.T) *config.DatabaseConfig { return unreachable("postgres", true) },
			wantType: data.Postgres,
			wantErr:  "unable to check whether the database exists",
			why:      "Create reached postgresdb, which connects to the postgres database to ask before it creates anything",
		},
		{
			name:     "mssql opens the configured database when Create is off",
			cfg:      func(t *testing.T) *config.DatabaseConfig { return unreachable("mssql", false) },
			wantType: data.MSSQL,
			wantErr:  "unable to connect to database",
			why:      "master is left alone, so the configured database is the only one attempted",
		},
		{
			name:     "mssql connects to master first when Create is on",
			cfg:      func(t *testing.T) *config.DatabaseConfig { return unreachable("mssql", true) },
			wantType: data.MSSQL,
			wantErr:  "unable to connect to master database",
			why:      "Create reached mssqldb, which takes master before it creates anything",
		},
		{
			name: "sqlite opens a file with Create off",
			cfg: func(t *testing.T) *config.DatabaseConfig {
				return &config.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "off.db")}
			},
			wantType: data.SQLite,
			why:      "sqlite is reached and opens for real, which is the arm no unreachable host can observe",
		},
		{
			name: "sqlite opens the same way with Create on",
			cfg: func(t *testing.T) *config.DatabaseConfig {
				return &config.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "on.db"), Create: true}
			},
			wantType: data.SQLite,
			why:      "GOIABADA_DB_CREATE changes nothing on SQLite because sqlitedb.New takes the DSN alone and has nowhere to receive it; what decides whether an absent file is created is mode=rw in the operator's own DSN (#293, #438 decision 4)",
		},
		{
			name:     "a double-quoted type dispatches to its engine",
			cfg:      func(t *testing.T) *config.DatabaseConfig { return unreachable("\"mysql\"", true) },
			wantType: data.MySQL,
			wantErr:  "unable to create database",
			why:      "an operator whose env file quotes the value reaches MySQL rather than the refusal, and the engine-unique prefix is what says so",
		},
		{
			name:    "an unknown type is refused, and the message names it with its length",
			cfg:     func(t *testing.T) *config.DatabaseConfig { return unreachable("wat", false) },
			wantErr: "unsupported database type: wat (string length 3). supported types are: mysql, sqlite, postgres, mssql",
			exact:   true,
			why:     "this string is the whole of what an operator gets for a mistyped GOIABADA_DB_TYPE, so it is pinned byte for byte; a refused type writes only its refusal, never an opening record naming an engine nothing opened. data.ParseDialect's own table owns every other refused input",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			capture := logtest.CaptureSlog(t)

			cfg := tc.cfg(t)
			database, err := OpenDatabase(context.Background(), cfg, false)

			if tc.wantErr == "" {
				require.NoErrorf(t, err, "the open must succeed: %s", tc.why)
				assert.IsTypef(t, &sqlitedb.Database{}, database,
					"the returned handle names the engine reached: %s", tc.why)
				// The file the DSN names is there afterwards, which is what says the DSN, and
				// nothing else, reached sqlitedb.New: dropped on the way, it would open the
				// in-memory default and write no file at all (#438 decision 4).
				_, statErr := os.Stat(cfg.DSN)
				require.NoErrorf(t, statErr, "SQLite opened the file its DSN names: %s", tc.why)
			} else {
				require.Errorf(t, err, "the open must fail: %s", tc.why)
				// Compared against a nil interface rather than through assert.Nil, which reports
				// a typed nil pointer as nil: all four constructors answer one beside their
				// error, so an arm returning the call directly would put a non-nil data.Database
				// over it and this is the one assertion that can tell the difference (#353).
				var noDatabase Migratable
				assert.Equalf(t, noDatabase, database,
					"a failed open returns no database at all, not a typed nil behind a non-nil interface: %s", tc.why)
				assert.Emptyf(t, recordsNamed(capture, "database connection pool"),
					"a failed open opened no pool, so it says nothing about one: %s", tc.why)

				if tc.exact {
					assert.Equalf(t, tc.wantErr, err.Error(),
						"the refusal is pinned byte for byte: %s", tc.why)
				} else {
					assert.Truef(t, strings.HasPrefix(err.Error(), tc.wantErr+":"),
						"want the error wrapped by %q, got %q: %s", tc.wantErr, err.Error(), tc.why)
				}
			}

			if tc.wantType == "" {
				for _, record := range capture.Records() {
					assert.NotEqualf(t, "opening the database", record.Message,
						"a refused type writes no opening record: %s", tc.why)
				}
				return
			}

			// The record is pinned here as a rider on cases already written, and is never the
			// dispatch assertion: it carries the dialect that was parsed, so a test resting on it
			// would pass with every arm wired to the same constructor.
			record := dispatchRecord(t, capture)
			assert.Equal(t, slog.LevelInfo, record.Level,
				"opening the database is lifecycle, which is Info: an operator reads it to know which engine a process chose")
			assert.Equalf(t, string(tc.wantType), record.Attrs["type"],
				"the record carries the dialect it dispatched on")
		})
	}
}

// TestNewDatabase_WritesTheNoMigrationRecordOnlyWhenNothingRan is the startup record's two rows.
// The four engines each wrote "no need to migrate the database" until #438 moved the step to head
// into the migrator's UpToHead and the record here, beside the caller that knows a process is
// starting. A first start migrates and writes nothing of the kind; a restart on the same file
// finds the schema at head and says so once, at Info, which is lifecycle.
//
// A real SQLite file rather than a double: the migrator is a concrete type, and the file is the
// one thing that can be at head on the second open and not on the first.
func TestNewDatabase_WritesTheNoMigrationRecordOnlyWhenNothingRan(t *testing.T) {
	const record = "no need to migrate the database"
	cfg := &config.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "startup.db")}
	aesKey := []byte("0123456789abcdef0123456789abcdef")

	start := func(t *testing.T) []logtest.CapturedRecord {
		t.Helper()
		capture := logtest.CaptureSlog(t)
		database, err := NewDatabase(context.Background(), cfg, aesKey, nil, false)
		require.NoError(t, err)
		concrete, ok := database.(*sqlitedb.Database)
		require.True(t, ok, "a sqlite type opens the sqlite engine")
		require.NoError(t, concrete.DB.Close(), "released so the next start is a fresh open")

		var found []logtest.CapturedRecord
		for _, r := range capture.Records() {
			if r.Message == record {
				found = append(found, r)
			}
		}
		return found
	}

	assert.Empty(t, start(t), "the first start ran the whole chain, so nothing was left unmigrated to report")

	second := start(t)
	require.Len(t, second, 1, "a restart at head says so exactly once")
	assert.Equal(t, slog.LevelInfo, second[0].Level, "a start finding nothing to migrate is lifecycle, which is Info")
}

// TestNewDatabase_SaysWhenItMigratesAndWhenItHasMigrated is #390 decision 7's two records around
// the migrations: a start that runs files says so before the first, with where the schema goes
// from and to and how many files that is, and again after the last, with how many ran and how
// long they took. A restart at head writes neither. Without them a start running a long
// migration writes nothing between opening the database and listening, and cannot be told from
// a hung one.
//
// The expected numbers come from the SQLite migration directory, read here by filename rather
// than through the runner, so a runner that miscounted its own chain would not agree with itself
// by construction. A never-migrated database reads from_version 0: no Goiabada migration is
// numbered 0, and the runner's own marker for it is an implementation detail no record carries.
func TestNewDatabase_SaysWhenItMigratesAndWhenItHasMigrated(t *testing.T) {
	head, carried := sqliteMigrationSet(t)
	cfg := &config.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "records.db")}
	aesKey := []byte("0123456789abcdef0123456789abcdef")

	start := func(t *testing.T) *logtest.SlogCapture {
		t.Helper()
		capture := logtest.CaptureSlog(t)
		database, err := NewDatabase(context.Background(), cfg, aesKey, nil, false)
		require.NoError(t, err)
		concrete, ok := database.(*sqlitedb.Database)
		require.True(t, ok, "a sqlite type opens the sqlite engine")
		require.NoError(t, concrete.DB.Close(), "released so the next start is a fresh open")
		return capture
	}

	first := start(t)
	migrating := recordsNamed(first, "migrating the database")
	require.Len(t, migrating, 1, "a first start says once that it is migrating")
	assert.Equal(t, slog.LevelInfo, migrating[0].Level, "migrating is lifecycle, which is Info")
	assert.Equal(t, map[string]any{
		"from_version": int64(0),
		"to_version":   int64(head),
		"pending":      int64(carried),
	}, migrating[0].Attrs)

	migrated := recordsNamed(first, "database migrated")
	require.Len(t, migrated, 1, "and once that it has migrated")
	assert.Equal(t, slog.LevelInfo, migrated[0].Level, "migrated is lifecycle, which is Info")
	assert.Equal(t, int64(0), migrated[0].Attrs["from_version"])
	assert.Equal(t, int64(head), migrated[0].Attrs["to_version"])
	assert.Equal(t, int64(carried), migrated[0].Attrs["applied"])
	took, ok := migrated[0].Attrs["duration"].(time.Duration)
	require.Truef(t, ok, "duration is a time.Duration, as the request logger's is: got %T", migrated[0].Attrs["duration"])
	assert.Positive(t, took, "a chain of %d files took some time", carried)
	assert.Len(t, migrated[0].Attrs, 4, "and nothing else")

	order := messageOrder(first, "opening the database", "migrating the database", "database migrated")
	assert.Equal(t, []string{"opening the database", "migrating the database", "database migrated"}, order,
		"the records read in the order the start does the work")
	assert.Empty(t, recordsNamed(first, "no need to migrate the database"), "a start that migrated did need to")
	assert.Empty(t, recordsNamed(first, "waiting for the migration lock"),
		"SQLite's lock is a mutex in this process, which another process can never hold")

	second := start(t)
	assert.Empty(t, recordsNamed(second, "migrating the database"), "a restart at head runs nothing")
	assert.Empty(t, recordsNamed(second, "database migrated"), "so it has migrated nothing")
	assert.Len(t, recordsNamed(second, "no need to migrate the database"), 1, "and says that instead")
}

// TestStartupProgress_SaysTheWaitOncePerStart: a start can queue for the migration lock twice,
// on SQL Server, whose schema_migrations pre-create takes it before the runner does, and it says it
// is waiting once, before the first wait. The records are the operator's, and a second one would
// read as a second process queued (#390 decision 7). The real engine's cases are the data tier's
// TestMigrationLock tests; this is the record's half.
func TestStartupProgress_SaysTheWaitOncePerStart(t *testing.T) {
	capture := logtest.CaptureSlog(t)
	progress := &startupProgress{ctx: context.Background()}

	progress.WaitingForLock()
	progress.WaitingForLock()

	waits := recordsNamed(capture, "waiting for the migration lock")
	require.Len(t, waits, 1, "two waits in one start are said once")
	assert.Equal(t, slog.LevelInfo, waits[0].Level)
}

// TestNewDatabase_AStopDuringTheMigrationsSaysWhereItLeftTheSchema is #390 decision 9's record: a
// start stopped while it migrates says where the schema stopped, from where, and how many files
// ran and remained, so an operator reading the last start knows the next one carries on from
// there. The stop arrives as the start says it is migrating, which is after the lock and before
// the first file, so it lands between files whatever the machine's speed; the runner's own tests
// hold a stop landing inside a file.
func TestNewDatabase_AStopDuringTheMigrationsSaysWhereItLeftTheSchema(t *testing.T) {
	_, carried := sqliteMigrationSet(t)
	dsn := filepath.Join(t.TempDir(), "stopped.db")
	cfg := &config.DatabaseConfig{Type: "sqlite", DSN: dsn}
	aesKey := []byte("0123456789abcdef0123456789abcdef")

	capture := logtest.CaptureSlog(t)
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	stopOnRecord(t, "migrating the database", stop)

	database, err := NewDatabase(ctx, cfg, aesKey, nil, false)

	require.ErrorIs(t, err, context.Canceled, "the start was asked to stop, and answers in a way main can match")
	assert.Nil(t, database)
	stopped := recordsNamed(capture, "database migration stopped")
	require.Len(t, stopped, 1, "a stop during the migrations says so once")
	assert.Equal(t, slog.LevelInfo, stopped[0].Level, "a stop the platform asked for is lifecycle, which is Info")
	assert.Equal(t, map[string]any{
		"from_version":    int64(0),
		"reached_version": int64(0),
		"applied":         int64(0),
		"remaining":       int64(carried),
	}, stopped[0].Attrs)
	assert.Equal(t, []string{"migrating the database", "database migration stopped"},
		messageOrder(capture, "migrating the database", "database migrated", "database migration stopped"),
		"the schema did not reach head, so nothing may say it was migrated")

	_, dirty, versionErr := sqliteMigrator(t, dsn).Version(context.Background())
	assert.Truef(t, migrator.IsNilVersion(versionErr), "the stop came before the first file, so nothing is recorded: %v", versionErr)
	assert.False(t, dirty)
}

// TestNewDatabase_AStopAfterTheMigrationsStartsNoFurtherStep: the migrations are done and the
// stop is answered before the next step, so the start ends there, with nothing to say about a
// migration that finished.
func TestNewDatabase_AStopAfterTheMigrationsStartsNoFurtherStep(t *testing.T) {
	head, _ := sqliteMigrationSet(t)
	dsn := filepath.Join(t.TempDir(), "migrated.db")
	cfg := &config.DatabaseConfig{Type: "sqlite", DSN: dsn}
	aesKey := []byte("0123456789abcdef0123456789abcdef")

	capture := logtest.CaptureSlog(t)
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	stopOnRecord(t, "database migrated", stop)

	database, err := NewDatabase(ctx, cfg, aesKey, nil, false)

	require.ErrorIs(t, err, context.Canceled, "a start asked to stop goes no further than the step it was in")
	assert.Nil(t, database)
	assert.Empty(t, recordsNamed(capture, "database migration stopped"), "the migrations were not under way")

	version, dirty, versionErr := sqliteMigrator(t, dsn).Version(context.Background())
	require.NoError(t, versionErr)
	assert.Equal(t, head, version)
	assert.False(t, dirty)
}

// stopOnRecord calls stop as soon as a record carrying message is written, over whatever handler
// is installed, which is the capture.
func stopOnRecord(t *testing.T, message string, stop func()) {
	t.Helper()
	previous := slog.Default()
	slog.SetDefault(slog.New(stoppingHandler{Handler: previous.Handler(), message: message, stop: stop}))
	t.Cleanup(func() { slog.SetDefault(previous) })
}

type stoppingHandler struct {
	slog.Handler
	message string
	stop    func()
}

func (h stoppingHandler) Handle(ctx context.Context, r slog.Record) error {
	err := h.Handler.Handle(ctx, r)
	if r.Message == h.message {
		h.stop()
	}
	return err
}

// sqliteMigrator opens the SQLite file at dsn for a look at its schema version, closing it on t.
func sqliteMigrator(t *testing.T, dsn string) *migrator.Migrator {
	t.Helper()
	db, err := sqlitedb.New(context.Background(), dsn, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.DB.Close() })
	m, err := db.NewMigrator(context.Background(), nil)
	require.NoError(t, err)
	return m
}

// sqliteMigrationSet reads the SQLite migration directory by filename: the highest version, and
// how many versions it carries, which is how many steps a never-migrated database takes to head.
func sqliteMigrationSet(t *testing.T) (head, carried int) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join("..", "sqlitedb", "migrations"))
	require.NoError(t, err)
	versions := map[int]bool{}
	for _, e := range entries {
		digits, _, found := strings.Cut(e.Name(), "_")
		require.Truef(t, found, "a migration file is named <version>_<name>: %s", e.Name())
		v, err := strconv.Atoi(digits)
		require.NoErrorf(t, err, "a migration file starts with its version: %s", e.Name())
		versions[v] = true
		head = max(head, v)
	}
	require.NotEmpty(t, versions, "the directory carries migrations")
	return head, len(versions)
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

// TestOpenDatabase_PassesLogSQLToTheEngine covers the factory's other parameter, which every
// caller in the tree passes false for and which nothing else observes.
//
// commondb.Database gates every SQL record on the flag, so a transaction opened on the returned
// handle writes "beginning transaction" when the flag arrived and nothing when it did not. The
// capture is installed after the open, so what is read is the flag's effect rather than the
// engine's own startup records.
func TestOpenDatabase_PassesLogSQLToTheEngine(t *testing.T) {
	tests := []struct {
		name   string
		logSQL bool
		want   bool
		why    string
	}{
		{
			name:   "logSQL on reaches the engine",
			logSQL: true,
			want:   true,
			why:    "an operator who turns SQL logging on gets the records the setting promises",
		},
		{
			name:   "logSQL off reaches the engine",
			logSQL: false,
			want:   false,
			why:    "the default writes no SQL records, which is what keeps statements out of a production log",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			database, err := OpenDatabase(context.Background(),
				&config.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "logsql.db")}, tc.logSQL)
			require.NoError(t, err)

			capture := logtest.CaptureSlog(t)

			tx, err := database.BeginTransaction(context.Background())
			require.NoError(t, err)
			require.NoError(t, database.RollbackTransaction(context.Background(), tx))

			text := capture.Text()
			assert.Equalf(t, tc.want, strings.Contains(text, "beginning transaction"),
				"want the begin record present=%v, got %q: %s", tc.want, text, tc.why)
			assert.Equalf(t, tc.want, strings.Contains(text, "rolling back transaction"),
				"want the rollback record present=%v, got %q: %s", tc.want, text, tc.why)
		})
	}
}
