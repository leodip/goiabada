package postgresdb

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

func (d *PostgresDatabase) CreateAuditLog(tx *sql.Tx, auditLog *models.AuditLog) error {
	if auditLog.AuditEvent == "" {
		return errors.WithStack(errors.New("can't create audit log with empty audit_event"))
	}

	// Always set CreatedAt to current time (ignore any incoming value)
	auditLog.CreatedAt = time.Now().UTC()

	auditLogStruct := sqlbuilder.NewStruct(new(models.AuditLog)).
		For(sqlbuilder.PostgreSQL)

	insertBuilder := auditLogStruct.WithoutTag("pk").InsertInto("audit_logs", auditLog)
	sqlStr, args := insertBuilder.Build()
	sqlStr = sqlStr + " RETURNING id"

	rows, err := d.CommonDB.QuerySql(tx, sqlStr, args...)
	if err != nil {
		return errors.Wrap(err, "unable to insert audit log")
	}
	defer func() { _ = rows.Close() }()

	if rows.Next() {
		err = rows.Scan(&auditLog.Id)
		if err != nil {
			return errors.Wrap(err, "unable to scan audit log id")
		}
	}

	return nil
}

func (d *PostgresDatabase) DeleteOldAuditLogs(tx *sql.Tx, cutoff time.Time, maxDeletions int) (int, error) {
	// PostgreSQL doesn't support LIMIT on DELETE directly
	// Use subquery: DELETE FROM audit_logs WHERE id IN (SELECT id FROM audit_logs WHERE created_at < ? LIMIT ?)
	sqlStr := fmt.Sprintf(`DELETE FROM audit_logs WHERE id IN (SELECT id FROM audit_logs WHERE created_at < $1 LIMIT %d)`, maxDeletions)

	result, err := d.CommonDB.ExecSql(tx, sqlStr, cutoff)
	if err != nil {
		return 0, errors.Wrap(err, "unable to delete old audit logs")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "unable to get rows affected")
	}

	return int(rowsAffected), nil
}

func (d *PostgresDatabase) GetAuditLogsPaginated(tx *sql.Tx, page int, pageSize int, auditEvent string) ([]models.AuditLog, int, error) {
	return d.CommonDB.GetAuditLogsPaginated(tx, page, pageSize, auditEvent)
}
