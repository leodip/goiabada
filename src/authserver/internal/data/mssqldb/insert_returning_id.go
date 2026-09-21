package mssqldb

import (
	"strings"

	"github.com/leodip/goiabada/core/errs"
)

// insertReturningIdSQL is SQL Server's answer to "how does an INSERT report the id it generated".
// go-mssqldb does not implement LastInsertId -- it returns an error -- so the id has to come back
// as a row, and OUTPUT INSERTED.id is how SQL Server says that.
//
// It is wired onto commondb.CommonDatabase in the constructor, beside IsDeadlock and
// IsUniqueViolation, and commondb.insertReturningId owns everything around it: the query, the
// scan, and the rows.Err() check that catches a constraint violation the driver deferred to the
// result set. This function is only the grammar (#416).
//
// WHY A SPLIT RATHER THAN AN APPEND. OUTPUT belongs between the column list and VALUES in SQL
// Server's INSERT grammar, so unlike PostgreSQL's RETURNING it cannot be added at the end. The
// statement being rewritten always comes from sqlbuilder's InsertBuilder, which emits
// `INSERT INTO t (cols) VALUES (...)` with VALUES uppercase and once, so splitting on the first
// occurrence is exact rather than a guess at SQL parsing. Every value is a placeholder by then,
// so no literal can contain the word.
//
// The refusal is not decoration: an INSERT whose text this did not recognise would otherwise go
// to the engine with no OUTPUT clause, the query would return no rows, and commondb's caller
// would store id 0 over a row that exists. Failing here is the difference between a startup-time
// mistake and a silently wrong row.
func insertReturningIdSQL(insertSQL string) (string, error) {
	parts := strings.SplitN(insertSQL, "VALUES", 2)
	if len(parts) != 2 {
		return "", errs.New("unexpected SQL format from sqlbuilder")
	}
	return parts[0] + "OUTPUT INSERTED.id VALUES" + parts[1], nil
}
