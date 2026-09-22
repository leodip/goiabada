package postgresdb

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/leodip/goiabada/core/errs"
)

func (d *PostgresDatabase) DeleteOldAuditLogs(ctx context.Context, tx *sql.Tx, cutoff time.Time, maxDeletions int) (int, error) {
	// PostgreSQL doesn't support LIMIT on DELETE directly
	// Use subquery: DELETE FROM audit_logs WHERE id IN (SELECT id FROM audit_logs WHERE created_at < ? LIMIT ?)
	sqlStr := fmt.Sprintf(`DELETE FROM audit_logs WHERE id IN (SELECT id FROM audit_logs WHERE created_at < $1 LIMIT %d)`, maxDeletions)

	result, err := d.ExecSql(ctx, tx, sqlStr, cutoff)
	if err != nil {
		return 0, errs.Wrap(err, "unable to delete old audit logs")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, errs.Wrap(err, "unable to get rows affected")
	}

	return int(rowsAffected), nil
}
