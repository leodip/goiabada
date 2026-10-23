package commondb

import (
	"strconv"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/data"
)

// statement is one SQL statement written once per engine, each version spelled as that engine
// runs it: `?` placeholders on SQLite and MySQL, `$1…` on PostgreSQL, `@p1…` on SQL Server,
// backticks on MySQL where the other three quote with double quotes. The text in the source is
// the text the engine receives: nothing rewrites it between here and the driver (#644).
//
// The four versions sit side by side so that a difference between engines is read in one place,
// and the Go around them is written once. TestStatements_EveryEngineHasItsVersion refuses a
// literal missing any of the four, or one left empty.
type statement struct {
	sqlite   string
	mysql    string
	postgres string
	mssql    string
}

// text is the version of s the dialect runs. A dialect outside the four answers the empty
// string, which every engine refuses as a statement rather than running something else.
func (s statement) text(dialect data.Dialect) string {
	switch dialect {
	case data.SQLite:
		return s.sqlite
	case data.MySQL:
		return s.mysql
	case data.Postgres:
		return s.postgres
	case data.MSSQL:
		return s.mssql
	default:
		return ""
	}
}

// columnList is one record's read column list written once per engine, in the order its scan
// function takes the fields. The four versions differ only where MySQL quotes with backticks what
// the other three quote with double quotes, and they are spliced into otherwise plain statements.
// The `db` tags on the record are the column contract, and the record mapping test holds every
// list and scan function to them on all four engines.
type columnList struct {
	sqlite   string
	mysql    string
	postgres string
	mssql    string
}

// text is the version of l the dialect reads with, as statement.text.
func (l columnList) text(dialect data.Dialect) string {
	return statement(l).text(dialect)
}

// rowScanner is what a scan function reads one row from: *sql.Rows and *sql.Row both satisfy it.
type rowScanner interface {
	Scan(dest ...any) error
}

// inList writes the predicate `column IN (…)` with n placeholders in the dialect's style, the
// first of them numbered first on the two engines that number theirs, so the IN list can follow
// other arguments in the same statement. It is how every statement in this package spells an IN
// list, and the id-list lint holds each function calling it to forEachIdBatch, so no list grows
// past the parameters one statement may carry (#373).
//
// An empty list is `0 = 1`, which matches nothing on every engine, where `IN ()` is a syntax
// error on all four. forEachIdBatch never hands over an empty batch; this is what such a list
// would mean, and what the query builder this replaced wrote for one.
func inList(dialect data.Dialect, column string, first, n int) string {
	if n == 0 {
		return "0 = 1"
	}

	var b strings.Builder
	b.WriteString(column)
	b.WriteString(" IN (")
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(", ")
		}
		switch dialect {
		case data.Postgres:
			b.WriteString("$" + strconv.Itoa(first+i))
		case data.MSSQL:
			b.WriteString("@p" + strconv.Itoa(first+i))
		default:
			b.WriteString("?")
		}
	}
	b.WriteString(")")
	return b.String()
}

// int64Args turns a batch of ids into the arguments of an IN list.
func int64Args(ids []int64) []any {
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	return args
}
