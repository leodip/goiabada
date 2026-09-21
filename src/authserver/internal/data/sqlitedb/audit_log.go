package sqlitedb

import (
	"database/sql"
	"time"
)

func (d *SQLiteDatabase) DeleteOldAuditLogs(tx *sql.Tx, cutoff time.Time, maxDeletions int) (int, error) {
	// SQLite requires ORDER BY with LIMIT on DELETE
	deleteSQL := `DELETE FROM audit_logs WHERE id IN (
		SELECT id FROM audit_logs WHERE created_at < ? ORDER BY id LIMIT ?
	)`

	result, err := d.ExecSql(tx, deleteSQL, cutoff, maxDeletions)
	if err != nil {
		return 0, err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}

	return int(rowsAffected), nil
}
