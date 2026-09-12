package commondb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/models"
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

	sql, args := insertBuilder.Build()
	result, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		return errs.Wrap(err, "unable to insert audit log")
	}

	id, err := result.LastInsertId()
	if err != nil {
		return errs.Wrap(err, "unable to get last insert id")
	}

	auditLog.Id = id
	return nil
}

// insertAuditLogWithoutId writes one audit_logs row and never reads its id back.
//
// It exists because CreateAuditLog cannot serve a caller inside this package. That method
// ends at result.LastInsertId(), which two of the four drivers refuse outright: pgx's stdlib
// wrapper answers with driver.RowsAffected, whose LastInsertId reports "not supported by this
// driver", and go-mssqldb reports "LastInsertId is not supported. Please use the OUTPUT
// clause". PostgresDatabase and MsSQLDatabase override CreateAuditLog with RETURNING and
// OUTPUT forms precisely for that reason.
//
// An override is only reached through the Database interface. A d.CreateAuditLog(...) call
// from inside commondb binds statically to the common implementation and cannot reach one, so
// on those two engines the INSERT lands and commits and the id read then fails, handing the
// caller an error that describes a write which in fact succeeded. Where the caller logs that
// error, every successful audit write reports itself as a failed one, and a genuine
// persistence failure becomes indistinguishable from normal operation (#283).
//
// The id is the whole of the difference: no caller in this package wants it, so this stops at
// the statement and reports only whether the statement itself failed. Anyone who does want the
// id keeps calling CreateAuditLog through the interface, where the override applies and the id
// is real. Relaxing CreateAuditLog to tolerate a missing id would instead hand MySQL and SQLite
// callers a silent zero for a value that is available there.
func (d *CommonDatabase) insertAuditLogWithoutId(tx *sql.Tx, auditLog *models.AuditLog) error {

	if auditLog.AuditEvent == "" {
		return errs.New("can't create audit log with empty audit_event")
	}

	// Always set CreatedAt to current time (ignore any incoming value), as CreateAuditLog does
	auditLog.CreatedAt = time.Now().UTC()

	auditLogStruct := sqlbuilder.NewStruct(new(models.AuditLog)).
		For(d.Flavor)

	insertBuilder := auditLogStruct.WithoutTag("pk").InsertInto("audit_logs", auditLog)

	sqlStr, args := insertBuilder.Build()
	if _, err := d.ExecSql(tx, sqlStr, args...); err != nil {
		return errs.Wrap(err, "unable to insert audit log")
	}

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
	rows, err := d.QuerySql(tx, sql, args...)
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
	countRows, err := d.QuerySql(tx, countSql, countArgs...)
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
