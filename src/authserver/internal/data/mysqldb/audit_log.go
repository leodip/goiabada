package mysqldb

import (
	"context"
	"database/sql"
	"time"
)

func (d *MySQLDatabase) DeleteOldAuditLogs(ctx context.Context, tx *sql.Tx, cutoff time.Time, maxDeletions int) (int, error) {
	// MySQL supports ORDER BY with LIMIT on DELETE
	deleteSQL := "DELETE FROM audit_logs WHERE created_at < ? ORDER BY id LIMIT ?"

	result, err := d.ExecSql(ctx, tx, deleteSQL, cutoff, maxDeletions)
	if err != nil {
		return 0, err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}

	return int(rowsAffected), nil
}
