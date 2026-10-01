package datafactory

import (
	"context"
	"log/slog"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/sqlitedb"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sourceConfig is one loaded GOIABADA_DB_* configuration in which no two values are equal.
//
// The distinctness is what makes the mapper tables below load-bearing. Eight fields copied by
// hand is eight chances to write one into another's place, and neither the engine's error nor
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
	}
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

// TestMysqlConfig_CopiesEveryField is seam 2 for MySQL: all eight fields, Create included.
func TestMysqlConfig_CopiesEveryField(t *testing.T) {
	c := sourceConfig()
	got := mysqlConfig(c)

	assertMapping(t, "mysqldb", got, []fieldCase{
		{"Type", got.Type, c.Type},
		{"Username", got.Username, c.Username},
		{"Password", got.Password, c.Password},
		{"Host", got.Host, c.Host},
		{"Port", got.Port, c.Port},
		{"Name", got.Name, c.Name},
		{"DSN", got.DSN, c.DSN},
		{"Create", got.Create, c.Create},
	})
}

// TestPostgresConfig_CopiesEveryField is seam 2 for PostgreSQL.
func TestPostgresConfig_CopiesEveryField(t *testing.T) {
	c := sourceConfig()
	got := postgresConfig(c)

	assertMapping(t, "postgresdb", got, []fieldCase{
		{"Type", got.Type, c.Type},
		{"Username", got.Username, c.Username},
		{"Password", got.Password, c.Password},
		{"Host", got.Host, c.Host},
		{"Port", got.Port, c.Port},
		{"Name", got.Name, c.Name},
		{"DSN", got.DSN, c.DSN},
		{"Create", got.Create, c.Create},
	})
}

// TestMssqlConfig_CopiesEveryField is seam 2 for SQL Server.
func TestMssqlConfig_CopiesEveryField(t *testing.T) {
	c := sourceConfig()
	got := mssqlConfig(c)

	assertMapping(t, "mssqldb", got, []fieldCase{
		{"Type", got.Type, c.Type},
		{"Username", got.Username, c.Username},
		{"Password", got.Password, c.Password},
		{"Host", got.Host, c.Host},
		{"Port", got.Port, c.Port},
		{"Name", got.Name, c.Name},
		{"DSN", got.DSN, c.DSN},
		{"Create", got.Create, c.Create},
	})
}

// TestSqliteConfig_CopiesSevenFieldsAndNotCreate is seam 2 for SQLite, which is seven fields
// rather than eight.
func TestSqliteConfig_CopiesSevenFieldsAndNotCreate(t *testing.T) {
	c := sourceConfig()
	got := sqliteConfig(c)

	assertMapping(t, "sqlitedb", got, []fieldCase{
		{"Type", got.Type, c.Type},
		{"Username", got.Username, c.Username},
		{"Password", got.Password, c.Password},
		{"Host", got.Host, c.Host},
		{"Port", got.Port, c.Port},
		{"Name", got.Name, c.Name},
		{"DSN", got.DSN, c.DSN},
	})

	// The absence of Create is a chosen leniency and not an oversight, so it is a case rather
	// than a comment: SQLite has no create statement and no maintenance connection to issue one
	// over, and mode=rw in the operator's DSN is the equivalent (#293). sourceConfig carries
	// Create: true, so this says GOIABADA_DB_CREATE cannot reach the SQLite driver by any route.
	_, declared := reflect.TypeOf(*got).FieldByName("Create")
	assert.Falsef(t, declared,
		"sqlitedb.DatabaseConfig declares a Create field: if the engine has grown one, sqliteConfig owes it a mapped case rather than silently dropping GOIABADA_DB_CREATE")
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
			why:      "GOIABADA_DB_CREATE changes nothing on SQLite because sqliteConfig does not carry it; what decides whether an absent file is created is mode=rw in the operator's own DSN (#293)",
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

			database, err := OpenDatabase(tc.cfg(t), false)

			if tc.wantErr == "" {
				require.NoErrorf(t, err, "the open must succeed: %s", tc.why)
				assert.IsTypef(t, &sqlitedb.SQLiteDatabase{}, database,
					"the returned handle names the engine reached: %s", tc.why)
			} else {
				require.Errorf(t, err, "the open must fail: %s", tc.why)
				// Compared against a nil interface rather than through assert.Nil, which reports
				// a typed nil pointer as nil: all four constructors answer one beside their
				// error, so an arm returning the call directly would put a non-nil data.Database
				// over it and this is the one assertion that can tell the difference (#353).
				var noDatabase Migratable
				assert.Equalf(t, noDatabase, database,
					"a failed open returns no database at all, not a typed nil behind a non-nil interface: %s", tc.why)

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
		concrete, ok := database.(*sqlitedb.SQLiteDatabase)
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

// TestOpenDatabase_PassesLogSQLToTheEngine covers the factory's other parameter, which every
// caller in the tree passes false for and which nothing else observes.
//
// CommonDatabase gates every SQL record on the flag, so a transaction opened on the returned
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
			database, err := OpenDatabase(
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
