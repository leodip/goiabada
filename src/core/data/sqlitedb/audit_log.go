package sqlitedb

import (
	"database/sql"
	"time"

	"github.com/leodip/goiabada/core/models"
)

func (d *SQLiteDatabase) CreateAuditLog(tx *sql.Tx, auditLog *models.AuditLog) error {
	return d.CommonDB.CreateAuditLog(tx, auditLog)
}

func (d *SQLiteDatabase) DeleteOldAuditLogs(tx *sql.Tx, cutoff time.Time, maxDeletions int) (int, error) {
	// SQLite requires ORDER BY with LIMIT on DELETE
	deleteSQL := `DELETE FROM audit_logs WHERE id IN (
		SELECT id FROM audit_logs WHERE created_at < ? ORDER BY id LIMIT ?
	)`

	result, err := d.CommonDB.ExecSql(tx, deleteSQL, cutoff, maxDeletions)
	if err != nil {
		return 0, err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}

	return int(rowsAffected), nil
}

func (d *SQLiteDatabase) GetAuditLogsPaginated(tx *sql.Tx, page int, pageSize int, auditEvent string) ([]models.AuditLog, int, error) {
	return d.CommonDB.GetAuditLogsPaginated(tx, page, pageSize, auditEvent)
}
