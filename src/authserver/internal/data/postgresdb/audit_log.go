package postgresdb

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/leodip/goiabada/core/errs"
)

// DeleteOldAuditLogs deletes up to maxDeletions audit rows older than cutoff and reports how many
// went. PostgreSQL has no LIMIT on DELETE, so a subquery picks the ids and the LIMIT sits there.
//
// commondb declares no DeleteOldAuditLogs, so each engine has to write its own and an engine that
// forgets fails to compile against data.Database rather than inheriting another engine's syntax
// (#438 decision 7).
func (d *Database) DeleteOldAuditLogs(ctx context.Context, tx *sql.Tx, cutoff time.Time, maxDeletions int) (int, error) {
	sqlStr := fmt.Sprintf(`DELETE FROM audit_logs WHERE id IN (SELECT id FROM audit_logs WHERE created_at < $1 LIMIT %d)`, maxDeletions)

	result, err := d.ExecSQL(ctx, tx, sqlStr, cutoff)
	if err != nil {
		return 0, errs.Wrap(err, "unable to delete old audit logs")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, errs.Wrap(err, "unable to get rows affected")
	}

	return int(rowsAffected), nil
}
