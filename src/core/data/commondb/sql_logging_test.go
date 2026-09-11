package commondb

import (
	"database/sql"
	"log/slog"
	"strings"
	"testing"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "modernc.org/sqlite"
)

// The SQL logger, seam 6 of #320.
//
// Decision 8 took the bound arguments out: this used to write a second record listing every
// value bound to the statement, and nothing at this layer can tell a password hash, a TOTP seed
// or an encrypted client secret from a page size. Every value the product writes to the database
// passes through ExecSql or QuerySql, so the negative case below is the one that matters, and it
// binds a sentinel rather than asserting on the shape of the record alone.
//
// A real in-memory SQLite database rather than the scripted driver this package's other tests
// use: what is under test is what reaches the log for a statement that really ran with really
// bound arguments, and a driver that discards its arguments could not fail this.

// loggingDB opens an in-memory SQLite database behind a CommonDatabase with logSQL set as given.
func loggingDB(t *testing.T, logSQL bool) *CommonDatabase {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	database := NewCommonDatabase(db, sqlbuilder.SQLite, logSQL)
	_, err = database.DB.Exec(`CREATE TABLE secrets (id INTEGER PRIMARY KEY, value TEXT)`)
	require.NoError(t, err, "the table is created behind the logger's back, so nothing it writes is under test yet")
	return database
}

const boundSentinel = "SENTINEL-bound-credential"

func TestCommonDatabaseLog_ExecSqlWritesOneRecordAndNoBoundValue(t *testing.T) {
	logs := testutil.CaptureSlog(t)
	database := loggingDB(t, true)

	_, err := database.ExecSql(nil, `INSERT INTO secrets (value) VALUES (?)`, boundSentinel)
	require.NoError(t, err)

	records := logs.Records()
	require.Len(t, records, 1, "one statement must produce one record, where it used to produce two")
	assert.Equal(t, slog.LevelInfo, records[0].Level)
	assert.Equal(t, "sql", records[0].Message)
	assert.Equal(t, `INSERT INTO secrets (value) VALUES (?)`, records[0].Attrs["statement"],
		"the statement is the whole point of the flag and must survive intact")
	assert.NotContains(t, logs.Text(), boundSentinel,
		"a value bound to the statement must not reach the log: nothing here can tell a credential from a page size")
}

func TestCommonDatabaseLog_QuerySqlWritesOneRecordAndNoBoundValue(t *testing.T) {
	logs := testutil.CaptureSlog(t)
	database := loggingDB(t, true)

	rows, err := database.QuerySql(nil, `SELECT id FROM secrets WHERE value = ?`, boundSentinel)
	require.NoError(t, err)
	require.NoError(t, rows.Close())

	records := logs.Records()
	require.Len(t, records, 1, "the read path must be bounded exactly as the write path is")
	assert.Equal(t, "sql", records[0].Message)
	assert.Equal(t, `SELECT id FROM secrets WHERE value = ?`, records[0].Attrs["statement"])
	assert.NotContains(t, logs.Text(), boundSentinel)
}

// The off case, which is what makes the on case attributable: without it, a logger that wrote
// nothing at all would satisfy every assertion above about what is absent.
func TestCommonDatabaseLog_WritesNothingWhenLogSqlIsOff(t *testing.T) {
	logs := testutil.CaptureSlog(t)
	database := loggingDB(t, false)

	_, err := database.ExecSql(nil, `INSERT INTO secrets (value) VALUES (?)`, boundSentinel)
	require.NoError(t, err)
	rows, err := database.QuerySql(nil, `SELECT id FROM secrets WHERE value = ?`, boundSentinel)
	require.NoError(t, err)
	require.NoError(t, rows.Close())

	assert.Empty(t, logs.Records(), "the flag is off, so neither path may write anything")
}

// A statement carrying a literal is the one shape where the statement text is itself a value.
// It is logged, and deliberately: the flag exists to show which queries run, the statements this
// tree builds come from sqlbuilder with placeholders rather than interpolation, and a caller that
// concatenated a credential into a statement has a defect this logger is not the place to fix.
func TestCommonDatabaseLog_LogsTheStatementTextAsWritten(t *testing.T) {
	logs := testutil.CaptureSlog(t)
	database := loggingDB(t, true)

	_, err := database.ExecSql(nil, `INSERT INTO secrets (value) VALUES ('literal')`)
	require.NoError(t, err)

	require.Len(t, logs.Records(), 1)
	assert.True(t, strings.Contains(logs.Records()[0].Attrs["statement"].(string), "'literal'"),
		"the statement is logged as written, placeholders and all")
}
