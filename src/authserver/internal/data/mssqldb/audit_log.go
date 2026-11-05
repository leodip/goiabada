package mssqldb

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/core/errs"
)

// deleteOldAuditLogs binds the cutoff, then the bound. SQL Server has no LIMIT at all; DELETE TOP
// (n) is its bound on a delete, and n may be a parameter.
const deleteOldAuditLogs = "DELETE TOP (@p2) FROM audit_logs WHERE created_at < @p1"

// DeleteOldAuditLogs deletes up to maxDeletions audit rows older than cutoff and reports how many
// went.
//
// commondb declares no DeleteOldAuditLogs, so each engine has to write its own and an engine that
// forgets fails to compile against data.Database rather than inheriting another engine's syntax
// (#438 decision 7).
func (d *Database) DeleteOldAuditLogs(ctx context.Context, tx *sql.Tx, cutoff time.Time, maxDeletions int) (int, error) {
	result, err := d.ExecSQL(ctx, tx, deleteOldAuditLogs, cutoff, maxDeletions)
	if err != nil {
		return 0, errs.Wrap(err, "unable to delete old audit logs")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, errs.Wrap(err, "unable to get rows affected")
	}

	return int(rowsAffected), nil
}
