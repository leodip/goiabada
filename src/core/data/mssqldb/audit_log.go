package mssqldb

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

func (d *MsSQLDatabase) CreateAuditLog(tx *sql.Tx, auditLog *models.AuditLog) error {
	if auditLog.AuditEvent == "" {
		return errors.WithStack(errors.New("can't create audit log with empty audit_event"))
	}

	// Always set CreatedAt to current time (ignore any incoming value)
	auditLog.CreatedAt = time.Now().UTC()

	auditLogStruct := sqlbuilder.NewStruct(new(models.AuditLog)).
		For(sqlbuilder.SQLServer)

	insertBuilder := auditLogStruct.WithoutTag("pk").InsertInto("audit_logs", auditLog)
	sqlStr, args := insertBuilder.Build()

	// MSSQL doesn't support LastInsertId, use OUTPUT clause instead
	parts := strings.SplitN(sqlStr, "VALUES", 2)
	if len(parts) != 2 {
		return errors.New("unexpected SQL format from sqlbuilder")
	}
	sqlStr = parts[0] + "OUTPUT INSERTED.id VALUES" + parts[1]

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

func (d *MsSQLDatabase) DeleteOldAuditLogs(tx *sql.Tx, cutoff time.Time, maxDeletions int) (int, error) {
	// MSSQL uses DELETE TOP(n) syntax
	sqlStr := fmt.Sprintf("DELETE TOP (%d) FROM audit_logs WHERE created_at < @p1", maxDeletions)

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

func (d *MsSQLDatabase) GetAuditLogsPaginated(tx *sql.Tx, page int, pageSize int, auditEvent string) ([]models.AuditLog, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 200 {
		pageSize = 200
	}

	offset := (page - 1) * pageSize

	auditLogStruct := sqlbuilder.NewStruct(new(models.AuditLog)).
		For(sqlbuilder.SQLServer)

	selectBuilder := auditLogStruct.SelectFrom("audit_logs")
	if auditEvent != "" {
		selectBuilder.Where(selectBuilder.Equal("audit_event", auditEvent))
	}
	// MSSQL pagination: ORDER BY ... OFFSET n ROWS FETCH NEXT m ROWS ONLY
	selectBuilder.OrderBy("created_at DESC", "id DESC")

	sqlStr, args := selectBuilder.Build()
	// MSSQL requires OFFSET...FETCH syntax for pagination
	sqlStr = fmt.Sprintf("%s OFFSET %d ROWS FETCH NEXT %d ROWS ONLY", sqlStr, offset, pageSize)

	rows, err := d.CommonDB.QuerySql(tx, sqlStr, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var auditLogs []models.AuditLog
	for rows.Next() {
		var auditLog models.AuditLog
		addr := auditLogStruct.Addr(&auditLog)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, 0, errors.Wrap(err, "unable to scan audit log")
		}
		auditLogs = append(auditLogs, auditLog)
	}

	// Get total count
	countBuilder := sqlbuilder.SQLServer.NewSelectBuilder()
	countBuilder.Select("COUNT(*)").From("audit_logs")
	if auditEvent != "" {
		countBuilder.Where(countBuilder.Equal("audit_event", auditEvent))
	}

	countSql, countArgs := countBuilder.Build()
	countRows, err := d.CommonDB.QuerySql(tx, countSql, countArgs...)
	if err != nil {
		return nil, 0, errors.Wrap(err, "unable to query count")
	}
	defer func() { _ = countRows.Close() }()

	var total int
	if countRows.Next() {
		err = countRows.Scan(&total)
		if err != nil {
			return nil, 0, errors.Wrap(err, "unable to scan count")
		}
	}

	return auditLogs, total, nil
}
