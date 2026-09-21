package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/errs"
)

func (d *CommonDatabase) CreateAuditLog(tx *sql.Tx, auditLog *models.AuditLog) error {

	if auditLog.AuditEvent == "" {
		return errs.New("can't create audit log with empty audit_event")
	}

	// Always set CreatedAt to current time (ignore any incoming value)
	auditLog.CreatedAt = time.Now().UTC()

	auditLogStruct := sqlbuilder.NewStruct(new(models.AuditLog)).
		For(d.Flavor)

	insertBuilder := auditLogStruct.WithoutTag("pk").InsertInto("audit_logs", auditLog)

	id, err := d.insertReturningId(context.Background(), tx, insertBuilder, "audit log")
	if err != nil {
		return err
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
	result, err := d.ExecSql(context.Background(), tx, sql, args...)
	if err != nil {
		return 0, errs.Wrap(err, "unable to delete old audit logs")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, errs.Wrap(err, "unable to get rows affected")
	}

	return int(rowsAffected), nil
}

func (d *CommonDatabase) GetAuditLogsPaginated(tx *sql.Tx, page int, pageSize int, auditEvent string,
	requestId string) ([]models.AuditLog, int, error) {

	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 200 {
		pageSize = 200
	}

	offset := PageOffset(page, pageSize)

	auditLogStruct := sqlbuilder.NewStruct(new(models.AuditLog)).
		For(d.Flavor)

	selectBuilder := auditLogStruct.SelectFrom("audit_logs")
	if auditEvent != "" {
		selectBuilder.Where(selectBuilder.Equal("audit_event", auditEvent))
	}
	if requestId != "" {
		selectBuilder.Where(selectBuilder.Equal("request_id", requestId))
	}
	// Deterministic sort: created_at DESC, id DESC (id tiebreaker prevents pagination drift)
	selectBuilder.OrderBy("created_at DESC", "id DESC")
	selectBuilder.Limit(pageSize)
	selectBuilder.Offset(offset)

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(context.Background(), tx, sql, args...)
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
		// The request id is client-chosen and is looked up with `=`, so the engine and not
		// this package would otherwise decide which ids are the same id. A row the engine
		// folded in carries an id the caller did not ask for, and listing it would put one
		// request's audit entries under another request's id (#328, and see
		// engineFoldedTheMatch).
		if requestId != "" && engineFoldedTheMatch(auditLog.RequestId, requestId) {
			continue
		}
		auditLogs = append(auditLogs, auditLog)
	}

	// Get total count
	countBuilder := d.Flavor.NewSelectBuilder()
	countBuilder.Select("COUNT(*)").From("audit_logs")
	if auditEvent != "" {
		countBuilder.Where(countBuilder.Equal("audit_event", auditEvent))
	}
	if requestId != "" {
		// ceiling: the count cannot apply the guard above, which needs the rows, so on MySQL
		// a stored id that differs from the filter only by a fold `=` accepts at equal length
		// (a decomposed accent against its precomposed spelling) would be counted and not
		// listed, showing as a page total one higher than the rows shown. SQLite and
		// PostgreSQL have no such fold, and SQL Server's are closed in the statement by
		// mssqldb's own body. Nothing reaches it today: the only writer stores the id as
		// logging.FieldForLog renders it, which percent-escapes every byte outside printable
		// ASCII, so no combining mark survives into the column. Revisit when a second writer
		// can store a non-ASCII id, or when the total is read for anything but the pager; a
		// MySQL-only binary predicate beside this equality is the next shape (#328).
		countBuilder.Where(countBuilder.Equal("request_id", requestId))
	}

	countSql, countArgs := countBuilder.Build()
	countRows, err := d.QuerySql(context.Background(), tx, countSql, countArgs...)
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
