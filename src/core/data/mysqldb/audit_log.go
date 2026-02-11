package mysqldb

import (
	"database/sql"
	"time"

	"github.com/leodip/goiabada/core/models"
)

func (d *MySQLDatabase) CreateAuditLog(tx *sql.Tx, auditLog *models.AuditLog) error {
	return d.CommonDB.CreateAuditLog(tx, auditLog)
}

func (d *MySQLDatabase) DeleteOldAuditLogs(tx *sql.Tx, cutoff time.Time, maxDeletions int) (int, error) {
	// MySQL supports ORDER BY with LIMIT on DELETE
	deleteSQL := "DELETE FROM audit_logs WHERE created_at < ? ORDER BY id LIMIT ?"

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

func (d *MySQLDatabase) GetAuditLogsPaginated(tx *sql.Tx, page int, pageSize int, auditEvent string) ([]models.AuditLog, int, error) {
	return d.CommonDB.GetAuditLogsPaginated(tx, page, pageSize, auditEvent)
}
