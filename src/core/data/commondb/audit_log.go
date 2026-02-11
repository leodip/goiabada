package commondb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

func (d *CommonDatabase) CreateAuditLog(tx *sql.Tx, auditLog *models.AuditLog) error {

	if auditLog.AuditEvent == "" {
		return errors.WithStack(errors.New("can't create audit log with empty audit_event"))
	}

	// Always set CreatedAt to current time (ignore any incoming value)
	auditLog.CreatedAt = time.Now().UTC()

	auditLogStruct := sqlbuilder.NewStruct(new(models.AuditLog)).
		For(d.Flavor)

	insertBuilder := auditLogStruct.WithoutTag("pk").InsertInto("audit_logs", auditLog)

	sql, args := insertBuilder.Build()
	result, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to insert audit log")
	}

	id, err := result.LastInsertId()
	if err != nil {
		return errors.Wrap(err, "unable to get last insert id")
	}

	auditLog.Id = id
	return nil
}

func (d *CommonDatabase) DeleteOldAuditLogs(tx *sql.Tx, cutoff time.Time, maxDeletions int) (int, error) {

	// SQLite and MySQL support LIMIT on DELETE
	deleteBuilder := d.Flavor.NewDeleteBuilder()
	deleteBuilder.DeleteFrom("audit_logs")
	deleteBuilder.Where(deleteBuilder.LessThan("created_at", cutoff))
	deleteBuilder.Limit(maxDeletions)

	sql, args := deleteBuilder.Build()
	result, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		return 0, errors.Wrap(err, "unable to delete old audit logs")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "unable to get rows affected")
	}

	return int(rowsAffected), nil
}

func (d *CommonDatabase) GetAuditLogsPaginated(tx *sql.Tx, page int, pageSize int, auditEvent string) ([]models.AuditLog, int, error) {

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
		For(d.Flavor)

	selectBuilder := auditLogStruct.SelectFrom("audit_logs")
	if auditEvent != "" {
		selectBuilder.Where(selectBuilder.Equal("audit_event", auditEvent))
	}
	// Deterministic sort: created_at DESC, id DESC (id tiebreaker prevents pagination drift)
	selectBuilder.OrderBy("created_at DESC", "id DESC")
	selectBuilder.Limit(pageSize)
	selectBuilder.Offset(offset)

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
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
	countBuilder := d.Flavor.NewSelectBuilder()
	countBuilder.Select("COUNT(*)").From("audit_logs")
	if auditEvent != "" {
		countBuilder.Where(countBuilder.Equal("audit_event", auditEvent))
	}

	countSql, countArgs := countBuilder.Build()
	countRows, err := d.QuerySql(tx, countSql, countArgs...)
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
