package data

import (
	"strings"

	"github.com/leodip/goiabada/core/errs"
)

// Dialect names one of the four database engines the auth server runs on. It is the one
// vocabulary for that choice: the server's engine selection, the schema dumper, the test-database
// drop and the data tier all switch on it, rather than each comparing the raw configured string
// under its own trimming rule (#438).
type Dialect string

const (
	SQLite   Dialect = "sqlite"
	MySQL    Dialect = "mysql"
	Postgres Dialect = "postgres"
	MSSQL    Dialect = "mssql"
)

// ParseDialect maps a configured GOIABADA_DB_TYPE onto a Dialect. Surrounding single and double
// quotes are trimmed, because an environment variable often carries them, and nothing else is:
// no whitespace, no case folding.
//
// The empty string is refused rather than read as SQLite. A GOIABADA_DB_TYPE that is set but empty
// is a configuration mistake, and reading it as SQLite would start the server on its in-memory
// default, losing every write at the next restart with nothing having refused anything (#438
// decision 6). The refusal names the trimmed value and its length, so an invisible character in it
// shows as a length that does not match what the operator sees.
func ParseDialect(s string) (Dialect, error) {
	v := strings.Trim(s, "\"'")
	switch d := Dialect(v); d {
	case SQLite, MySQL, Postgres, MSSQL:
		return d, nil
	default:
		return "", errs.Errorf("unsupported database type: %s (string length %d). supported types are: mysql, sqlite, postgres, mssql", v, len(v))
	}
}
