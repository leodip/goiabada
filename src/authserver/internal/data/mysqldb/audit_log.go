package mysqldb

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/core/errs"
)

// DeleteOldAuditLogs deletes up to maxDeletions audit rows older than cutoff, oldest id first, and
// reports how many went. MySQL takes ORDER BY and LIMIT on DELETE natively, so it is one statement.
//
// commondb declares no DeleteOldAuditLogs, so each engine has to write its own and an engine that
// forgets fails to compile against data.Database rather than inheriting another engine's syntax
// (#438 decision 7).
func (d *Database) DeleteOldAuditLogs(ctx context.Context, tx *sql.Tx, cutoff time.Time, maxDeletions int) (int, error) {
	deleteSQL := "DELETE FROM audit_logs WHERE created_at < ? ORDER BY id LIMIT ?"

	result, err := d.ExecSQL(ctx, tx, deleteSQL, cutoff, maxDeletions)
	if err != nil {
		return 0, errs.Wrap(err, "unable to delete old audit logs")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, errs.Wrap(err, "unable to get rows affected")
	}

	return int(rowsAffected), nil
}
