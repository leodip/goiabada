package mssqldb

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/data/commondb"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/models"
)

func (d *MsSQLDatabase) CreateAuditLog(tx *sql.Tx, auditLog *models.AuditLog) error {
	if auditLog.AuditEvent == "" {
		return errs.New("can't create audit log with empty audit_event")
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
		return errs.New("unexpected SQL format from sqlbuilder")
	}
	sqlStr = parts[0] + "OUTPUT INSERTED.id VALUES" + parts[1]

	rows, err := d.CommonDB.QuerySql(tx, sqlStr, args...)
	if err != nil {
		return errs.Wrap(err, "unable to insert audit log")
	}
	defer func() { _ = rows.Close() }()

	if rows.Next() {
		err = rows.Scan(&auditLog.Id)
		if err != nil {
			return errs.Wrap(err, "unable to scan audit log id")
		}
	}

	// The driver can defer a constraint violation to the result set rather than
	// returning it from the query, in which case Next() simply reports no row.
	// Without this the insert would look like a success with id 0.
	if err := rows.Err(); err != nil {
		return d.CommonDB.WrapSQLError(err, "unable to insert audit log")
	}

	return nil
}

func (d *MsSQLDatabase) DeleteOldAuditLogs(tx *sql.Tx, cutoff time.Time, maxDeletions int) (int, error) {
	// MSSQL uses DELETE TOP(n) syntax
	sqlStr := fmt.Sprintf("DELETE TOP (%d) FROM audit_logs WHERE created_at < @p1", maxDeletions)

	result, err := d.CommonDB.ExecSql(tx, sqlStr, cutoff)
	if err != nil {
		return 0, errs.Wrap(err, "unable to delete old audit logs")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, errs.Wrap(err, "unable to get rows affected")
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

	offset := commondb.PageOffset(page, pageSize)

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
		return nil, 0, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var auditLogs []models.AuditLog
	for rows.Next() {
		var auditLog models.AuditLog
		addr := auditLogStruct.Addr(&auditLog)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, 0, errs.Wrap(err, "unable to scan audit log")
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
		return nil, 0, errs.Wrap(err, "unable to query count")
	}
	defer func() { _ = countRows.Close() }()

	var total int
	if countRows.Next() {
		err = countRows.Scan(&total)
		if err != nil {
			return nil, 0, errs.Wrap(err, "unable to scan count")
		}
	}

	if err := rows.Err(); err != nil {
		return nil, 0, errs.Wrap(err, "unable to read query results")
	}
	if err := countRows.Err(); err != nil {
		return nil, 0, errs.Wrap(err, "unable to read count results")
	}

	return auditLogs, total, nil
}
