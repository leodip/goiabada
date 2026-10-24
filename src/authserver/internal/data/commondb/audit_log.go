package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// auditLogColumns is the audit_logs table as scanAuditLog reads it.
var auditLogColumns = columnList{
	sqlite:   "id, created_at, audit_event, details, request_id",
	mysql:    "id, created_at, audit_event, details, request_id",
	postgres: "id, created_at, audit_event, details, request_id",
	mssql:    "id, created_at, audit_event, details, request_id",
}

// scanAuditLog reads one row selected with auditLogColumns.
func scanAuditLog(row rowScanner, auditLog *record.AuditLog) error {
	return row.Scan(
		&auditLog.Id,
		&auditLog.CreatedAt,
		&auditLog.AuditEvent,
		&auditLog.Details,
		&auditLog.RequestId,
	)
}

var insertAuditLog = statement{
	sqlite: "INSERT INTO audit_logs (created_at, audit_event, details, request_id) VALUES (?, ?, ?, ?)",
	mysql:  "INSERT INTO audit_logs (created_at, audit_event, details, request_id) VALUES (?, ?, ?, ?)",
	postgres: "INSERT INTO audit_logs (created_at, audit_event, details, request_id) VALUES ($1, $2, $3, " +
		"$4) RETURNING id",
	mssql: "INSERT INTO audit_logs (created_at, audit_event, details, " +
		"request_id) OUTPUT INSERTED.id VALUES (@p1, @p2, @p3, @p4)",
}

// The page of audit logs and its count, one pair per combination of the two filters, each filter
// given only when the caller names one. A page binds the filters it carries, the event before the
// request id, then the page size, then the offset; SQL Server pages with OFFSET … FETCH after its
// ORDER BY, naming the offset first, so its text numbers the two the other way round. The order is
// total, created_at DESC and then id DESC, so tied rows cannot drift between pages.
//
// mssqldb declares its own GetAuditLogsPaginated, because SQL Server's `=` pads and its request-id
// filter has to compare the bytes in both statements, so SQL Server never runs these versions. They
// are spelled as SQL Server would run them all the same, so each statement carries its four
// versions and the record mapping test reads every one.
var selectAuditLogsPage = statement{
	sqlite: "SELECT " + auditLogColumns.sqlite + " FROM audit_logs " +
		"ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
	mysql: "SELECT " + auditLogColumns.mysql + " FROM audit_logs " +
		"ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
	postgres: "SELECT " + auditLogColumns.postgres + " FROM audit_logs " +
		"ORDER BY created_at DESC, id DESC LIMIT $1 OFFSET $2",
	mssql: "SELECT " + auditLogColumns.mssql + " FROM audit_logs " +
		"ORDER BY created_at DESC, id DESC OFFSET @p2 ROWS FETCH NEXT @p1 ROWS ONLY",
}

var countAuditLogs = statement{
	sqlite:   "SELECT COUNT(*) FROM audit_logs",
	mysql:    "SELECT COUNT(*) FROM audit_logs",
	postgres: "SELECT COUNT(*) FROM audit_logs",
	mssql:    "SELECT COUNT(*) FROM audit_logs",
}

var selectAuditLogsPageByEvent = statement{
	sqlite: "SELECT " + auditLogColumns.sqlite + " FROM audit_logs WHERE audit_event = ? " +
		"ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
	mysql: "SELECT " + auditLogColumns.mysql + " FROM audit_logs WHERE audit_event = ? " +
		"ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
	postgres: "SELECT " + auditLogColumns.postgres + " FROM audit_logs WHERE audit_event = $1 " +
		"ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3",
	mssql: "SELECT " + auditLogColumns.mssql + " FROM audit_logs WHERE audit_event = @p1 " +
		"ORDER BY created_at DESC, id DESC OFFSET @p3 ROWS FETCH NEXT @p2 ROWS ONLY",
}

var countAuditLogsByEvent = statement{
	sqlite:   "SELECT COUNT(*) FROM audit_logs WHERE audit_event = ?",
	mysql:    "SELECT COUNT(*) FROM audit_logs WHERE audit_event = ?",
	postgres: "SELECT COUNT(*) FROM audit_logs WHERE audit_event = $1",
	mssql:    "SELECT COUNT(*) FROM audit_logs WHERE audit_event = @p1",
}

var selectAuditLogsPageByRequestId = statement{
	sqlite: "SELECT " + auditLogColumns.sqlite + " FROM audit_logs WHERE request_id = ? " +
		"ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
	mysql: "SELECT " + auditLogColumns.mysql + " FROM audit_logs WHERE request_id = ? " +
		"ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
	postgres: "SELECT " + auditLogColumns.postgres + " FROM audit_logs WHERE request_id = $1 " +
		"ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3",
	mssql: "SELECT " + auditLogColumns.mssql + " FROM audit_logs WHERE request_id = @p1 " +
		"ORDER BY created_at DESC, id DESC OFFSET @p3 ROWS FETCH NEXT @p2 ROWS ONLY",
}

var countAuditLogsByRequestId = statement{
	sqlite:   "SELECT COUNT(*) FROM audit_logs WHERE request_id = ?",
	mysql:    "SELECT COUNT(*) FROM audit_logs WHERE request_id = ?",
	postgres: "SELECT COUNT(*) FROM audit_logs WHERE request_id = $1",
	mssql:    "SELECT COUNT(*) FROM audit_logs WHERE request_id = @p1",
}

var selectAuditLogsPageByEventAndRequestId = statement{
	sqlite: "SELECT " + auditLogColumns.sqlite + " FROM audit_logs WHERE audit_event = ? AND request_id = ? " +
		"ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
	mysql: "SELECT " + auditLogColumns.mysql + " FROM audit_logs WHERE audit_event = ? AND request_id = ? " +
		"ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
	postgres: "SELECT " + auditLogColumns.postgres + " FROM audit_logs WHERE audit_event = $1 AND request_id = $2 " +
		"ORDER BY created_at DESC, id DESC LIMIT $3 OFFSET $4",
	mssql: "SELECT " + auditLogColumns.mssql + " FROM audit_logs WHERE audit_event = @p1 AND request_id = @p2 " +
		"ORDER BY created_at DESC, id DESC OFFSET @p4 ROWS FETCH NEXT @p3 ROWS ONLY",
}

var countAuditLogsByEventAndRequestId = statement{
	sqlite:   "SELECT COUNT(*) FROM audit_logs WHERE audit_event = ? AND request_id = ?",
	mysql:    "SELECT COUNT(*) FROM audit_logs WHERE audit_event = ? AND request_id = ?",
	postgres: "SELECT COUNT(*) FROM audit_logs WHERE audit_event = $1 AND request_id = $2",
	mssql:    "SELECT COUNT(*) FROM audit_logs WHERE audit_event = @p1 AND request_id = @p2",
}

// auditLogsQueries answers the page and the count for the filters given.
func auditLogsQueries(byEvent, byRequestId bool) (page statement, count statement) {
	switch {
	case byEvent && byRequestId:
		return selectAuditLogsPageByEventAndRequestId, countAuditLogsByEventAndRequestId
	case byEvent:
		return selectAuditLogsPageByEvent, countAuditLogsByEvent
	case byRequestId:
		return selectAuditLogsPageByRequestId, countAuditLogsByRequestId
	default:
		return selectAuditLogsPage, countAuditLogs
	}
}

func (d *Database) CreateAuditLog(ctx context.Context, tx *sql.Tx, auditLog *record.AuditLog) error {

	if auditLog.AuditEvent == "" {
		return errs.New("can't create audit log with empty audit_event")
	}

	// Always set CreatedAt to current time (ignore any incoming value)
	auditLog.CreatedAt = time.Now().UTC()

	id, err := d.insert(ctx, tx, insertAuditLog, "audit log",
		auditLog.CreatedAt, auditLog.AuditEvent, auditLog.Details, auditLog.RequestId)
	if err != nil {
		return err
	}

	auditLog.Id = id
	return nil
}

func (d *Database) GetAuditLogsPaginated(ctx context.Context, tx *sql.Tx, page int, pageSize int, auditEvent string,
	requestId string) ([]record.AuditLog, int, error) {

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

	pageQuery, countQuery := auditLogsQueries(auditEvent != "", requestId != "")
	var filterArgs []any
	if auditEvent != "" {
		filterArgs = append(filterArgs, auditEvent)
	}
	if requestId != "" {
		filterArgs = append(filterArgs, requestId)
	}
	pageArgs := append(append([]any{}, filterArgs...), pageSize, offset)

	rows, err := d.QuerySQL(ctx, tx, pageQuery.text(d.Dialect), pageArgs...)
	if err != nil {
		return nil, 0, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var auditLogs []record.AuditLog
	for rows.Next() {
		var auditLog record.AuditLog
		if err := scanAuditLog(rows, &auditLog); err != nil {
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
	countRows, err := d.QuerySQL(ctx, tx, countQuery.text(d.Dialect), filterArgs...)
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
