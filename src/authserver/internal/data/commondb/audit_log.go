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
	sqlite:   "id, created_at, audit_event, details, request_id, user_id, logged_in_user_id",
	mysql:    "id, created_at, audit_event, details, request_id, user_id, logged_in_user_id",
	postgres: "id, created_at, audit_event, details, request_id, user_id, logged_in_user_id",
	mssql:    "id, created_at, audit_event, details, request_id, user_id, logged_in_user_id",
}

// scanAuditLog reads one row selected with auditLogColumns.
func scanAuditLog(row rowScanner, auditLog *record.AuditLog) error {
	return row.Scan(
		&auditLog.Id,
		&auditLog.CreatedAt,
		&auditLog.AuditEvent,
		&auditLog.Details,
		&auditLog.RequestId,
		&auditLog.UserId,
		&auditLog.LoggedInUserId,
	)
}

var insertAuditLog = statement{
	sqlite: "INSERT INTO audit_logs (created_at, audit_event, details, request_id, user_id, logged_in_user_id) " +
		"VALUES (?, ?, ?, ?, ?, ?)",
	mysql: "INSERT INTO audit_logs (created_at, audit_event, details, request_id, user_id, logged_in_user_id) " +
		"VALUES (?, ?, ?, ?, ?, ?)",
	postgres: "INSERT INTO audit_logs (created_at, audit_event, details, request_id, user_id, logged_in_user_id) " +
		"VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
	mssql: "INSERT INTO audit_logs (created_at, audit_event, details, request_id, user_id, logged_in_user_id) " +
		"OUTPUT INSERTED.id VALUES (@p1, @p2, @p3, @p4, @p5, @p6)",
}

// The page of audit logs and its count, one pair per combination of the three filters, each filter
// given only when the caller names one. A page binds the filters it carries, the event before the
// request id before the user, then the page size, then the offset; SQL Server pages with
// OFFSET … FETCH after its ORDER BY, naming the offset first, so its text numbers the two the other
// way round. The order is total, created_at DESC and then id DESC, so tied rows cannot drift
// between pages.
//
// THE USER FILTER MATCHES EITHER USER COLUMN (#780 decision 3): the rows about the user and the
// rows they made, user_id = N OR logged_in_user_id = N, a row naming the user in both listed once.
// The id is bound twice, once for each column, so the four engines bind the same values; each
// column has its own index, which every engine reads for its side of the OR. Each combination
// stays its own literal statement rather than one with `(? = 0 OR …)` predicates, because SQL
// Server caches one plan for every combination and SQLite chooses its index before it sees the
// values (#780 decision 7).
//
// SQL SERVER'S REQUEST-ID FILTER COMPARES THE BYTES, in the page and the count alike. `=` is not
// exact on that engine: it pads, so request_id = 'corr' is true of a row holding 'corr ' under
// every collation SQL Server has, Latin1_General_100_BIN2_UTF8 included, and no collation turns
// that off (see engineFoldedTheMatch). The guard GetAuditLogsPaginated applies after the scan
// cannot close it there: SQL Server pages with OFFSET/FETCH, so a row dropped after the fetch
// leaves a short page, and the count has no rows to drop at all. Measured against the live engine,
// a guard applied after the fetch gave an empty page under a total of 1 (#328). So the statement
// closes the fold, the equality staying beside it so the index on request_id can still seek, and
// the CAST, reading the same parameter, doing the filtering. VARBINARY(512) is the column's whole
// width: request_id is NVARCHAR(256), which stores UTF-16 even under the UTF-8 collation, so 256
// characters are 512 bytes and nothing that fits the column is clipped by the cast.
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
	mssql: "SELECT " + auditLogColumns.mssql + " FROM audit_logs " +
		"WHERE request_id = @p1 AND CAST(request_id AS VARBINARY(512)) = CAST(@p1 AS VARBINARY(512)) " +
		"ORDER BY created_at DESC, id DESC OFFSET @p3 ROWS FETCH NEXT @p2 ROWS ONLY",
}

var countAuditLogsByRequestId = statement{
	sqlite:   "SELECT COUNT(*) FROM audit_logs WHERE request_id = ?",
	mysql:    "SELECT COUNT(*) FROM audit_logs WHERE request_id = ?",
	postgres: "SELECT COUNT(*) FROM audit_logs WHERE request_id = $1",
	mssql: "SELECT COUNT(*) FROM audit_logs " +
		"WHERE request_id = @p1 AND CAST(request_id AS VARBINARY(512)) = CAST(@p1 AS VARBINARY(512))",
}

var selectAuditLogsPageByUser = statement{
	sqlite: "SELECT " + auditLogColumns.sqlite + " FROM audit_logs WHERE (user_id = ? OR logged_in_user_id = ?) " +
		"ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
	mysql: "SELECT " + auditLogColumns.mysql + " FROM audit_logs WHERE (user_id = ? OR logged_in_user_id = ?) " +
		"ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
	postgres: "SELECT " + auditLogColumns.postgres + " FROM audit_logs WHERE (user_id = $1 OR logged_in_user_id = $2) " +
		"ORDER BY created_at DESC, id DESC LIMIT $3 OFFSET $4",
	mssql: "SELECT " + auditLogColumns.mssql + " FROM audit_logs WHERE (user_id = @p1 OR logged_in_user_id = @p2) " +
		"ORDER BY created_at DESC, id DESC OFFSET @p4 ROWS FETCH NEXT @p3 ROWS ONLY",
}

var countAuditLogsByUser = statement{
	sqlite:   "SELECT COUNT(*) FROM audit_logs WHERE (user_id = ? OR logged_in_user_id = ?)",
	mysql:    "SELECT COUNT(*) FROM audit_logs WHERE (user_id = ? OR logged_in_user_id = ?)",
	postgres: "SELECT COUNT(*) FROM audit_logs WHERE (user_id = $1 OR logged_in_user_id = $2)",
	mssql:    "SELECT COUNT(*) FROM audit_logs WHERE (user_id = @p1 OR logged_in_user_id = @p2)",
}

var selectAuditLogsPageByEventAndRequestId = statement{
	sqlite: "SELECT " + auditLogColumns.sqlite + " FROM audit_logs WHERE audit_event = ? AND request_id = ? " +
		"ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
	mysql: "SELECT " + auditLogColumns.mysql + " FROM audit_logs WHERE audit_event = ? AND request_id = ? " +
		"ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
	postgres: "SELECT " + auditLogColumns.postgres + " FROM audit_logs WHERE audit_event = $1 AND request_id = $2 " +
		"ORDER BY created_at DESC, id DESC LIMIT $3 OFFSET $4",
	mssql: "SELECT " + auditLogColumns.mssql + " FROM audit_logs " +
		"WHERE audit_event = @p1 AND request_id = @p2 AND CAST(request_id AS VARBINARY(512)) = CAST(@p2 AS VARBINARY(512)) " +
		"ORDER BY created_at DESC, id DESC OFFSET @p4 ROWS FETCH NEXT @p3 ROWS ONLY",
}

var countAuditLogsByEventAndRequestId = statement{
	sqlite:   "SELECT COUNT(*) FROM audit_logs WHERE audit_event = ? AND request_id = ?",
	mysql:    "SELECT COUNT(*) FROM audit_logs WHERE audit_event = ? AND request_id = ?",
	postgres: "SELECT COUNT(*) FROM audit_logs WHERE audit_event = $1 AND request_id = $2",
	mssql: "SELECT COUNT(*) FROM audit_logs " +
		"WHERE audit_event = @p1 AND request_id = @p2 AND CAST(request_id AS VARBINARY(512)) = CAST(@p2 AS VARBINARY(512))",
}

var selectAuditLogsPageByEventAndUser = statement{
	sqlite: "SELECT " + auditLogColumns.sqlite + " FROM audit_logs WHERE audit_event = ? AND (user_id = ? OR logged_in_user_id = ?) " +
		"ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
	mysql: "SELECT " + auditLogColumns.mysql + " FROM audit_logs WHERE audit_event = ? AND (user_id = ? OR logged_in_user_id = ?) " +
		"ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
	postgres: "SELECT " + auditLogColumns.postgres + " FROM audit_logs WHERE audit_event = $1 AND (user_id = $2 OR logged_in_user_id = $3) " +
		"ORDER BY created_at DESC, id DESC LIMIT $4 OFFSET $5",
	mssql: "SELECT " + auditLogColumns.mssql + " FROM audit_logs WHERE audit_event = @p1 AND (user_id = @p2 OR logged_in_user_id = @p3) " +
		"ORDER BY created_at DESC, id DESC OFFSET @p5 ROWS FETCH NEXT @p4 ROWS ONLY",
}

var countAuditLogsByEventAndUser = statement{
	sqlite:   "SELECT COUNT(*) FROM audit_logs WHERE audit_event = ? AND (user_id = ? OR logged_in_user_id = ?)",
	mysql:    "SELECT COUNT(*) FROM audit_logs WHERE audit_event = ? AND (user_id = ? OR logged_in_user_id = ?)",
	postgres: "SELECT COUNT(*) FROM audit_logs WHERE audit_event = $1 AND (user_id = $2 OR logged_in_user_id = $3)",
	mssql:    "SELECT COUNT(*) FROM audit_logs WHERE audit_event = @p1 AND (user_id = @p2 OR logged_in_user_id = @p3)",
}

var selectAuditLogsPageByRequestIdAndUser = statement{
	sqlite: "SELECT " + auditLogColumns.sqlite + " FROM audit_logs WHERE request_id = ? AND (user_id = ? OR logged_in_user_id = ?) " +
		"ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
	mysql: "SELECT " + auditLogColumns.mysql + " FROM audit_logs WHERE request_id = ? AND (user_id = ? OR logged_in_user_id = ?) " +
		"ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
	postgres: "SELECT " + auditLogColumns.postgres + " FROM audit_logs WHERE request_id = $1 AND (user_id = $2 OR logged_in_user_id = $3) " +
		"ORDER BY created_at DESC, id DESC LIMIT $4 OFFSET $5",
	mssql: "SELECT " + auditLogColumns.mssql + " FROM audit_logs " +
		"WHERE request_id = @p1 AND CAST(request_id AS VARBINARY(512)) = CAST(@p1 AS VARBINARY(512)) AND (user_id = @p2 OR logged_in_user_id = @p3) " +
		"ORDER BY created_at DESC, id DESC OFFSET @p5 ROWS FETCH NEXT @p4 ROWS ONLY",
}

var countAuditLogsByRequestIdAndUser = statement{
	sqlite:   "SELECT COUNT(*) FROM audit_logs WHERE request_id = ? AND (user_id = ? OR logged_in_user_id = ?)",
	mysql:    "SELECT COUNT(*) FROM audit_logs WHERE request_id = ? AND (user_id = ? OR logged_in_user_id = ?)",
	postgres: "SELECT COUNT(*) FROM audit_logs WHERE request_id = $1 AND (user_id = $2 OR logged_in_user_id = $3)",
	mssql: "SELECT COUNT(*) FROM audit_logs " +
		"WHERE request_id = @p1 AND CAST(request_id AS VARBINARY(512)) = CAST(@p1 AS VARBINARY(512)) AND (user_id = @p2 OR logged_in_user_id = @p3)",
}

var selectAuditLogsPageByEventRequestIdAndUser = statement{
	sqlite: "SELECT " + auditLogColumns.sqlite + " FROM audit_logs WHERE audit_event = ? AND request_id = ? AND (user_id = ? OR logged_in_user_id = ?) " +
		"ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
	mysql: "SELECT " + auditLogColumns.mysql + " FROM audit_logs WHERE audit_event = ? AND request_id = ? AND (user_id = ? OR logged_in_user_id = ?) " +
		"ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
	postgres: "SELECT " + auditLogColumns.postgres + " FROM audit_logs WHERE audit_event = $1 AND request_id = $2 AND (user_id = $3 OR logged_in_user_id = $4) " +
		"ORDER BY created_at DESC, id DESC LIMIT $5 OFFSET $6",
	mssql: "SELECT " + auditLogColumns.mssql + " FROM audit_logs " +
		"WHERE audit_event = @p1 AND request_id = @p2 AND CAST(request_id AS VARBINARY(512)) = CAST(@p2 AS VARBINARY(512)) " +
		"AND (user_id = @p3 OR logged_in_user_id = @p4) " +
		"ORDER BY created_at DESC, id DESC OFFSET @p6 ROWS FETCH NEXT @p5 ROWS ONLY",
}

var countAuditLogsByEventRequestIdAndUser = statement{
	sqlite:   "SELECT COUNT(*) FROM audit_logs WHERE audit_event = ? AND request_id = ? AND (user_id = ? OR logged_in_user_id = ?)",
	mysql:    "SELECT COUNT(*) FROM audit_logs WHERE audit_event = ? AND request_id = ? AND (user_id = ? OR logged_in_user_id = ?)",
	postgres: "SELECT COUNT(*) FROM audit_logs WHERE audit_event = $1 AND request_id = $2 AND (user_id = $3 OR logged_in_user_id = $4)",
	mssql: "SELECT COUNT(*) FROM audit_logs " +
		"WHERE audit_event = @p1 AND request_id = @p2 AND CAST(request_id AS VARBINARY(512)) = CAST(@p2 AS VARBINARY(512)) " +
		"AND (user_id = @p3 OR logged_in_user_id = @p4)",
}

// selectAuditLogsByUser is one user's audit events, all of them, as a user's data export lists
// them (#781 decision 5): the user filter's match on either user column, a row naming the user in
// both listed once, with the id bound once for each. It is in id order, oldest first, and unpaged,
// so two reads of one user compare row by row; paging the newest-first page while rows arrive
// would list a row twice.
var selectAuditLogsByUser = statement{
	sqlite:   "SELECT " + auditLogColumns.sqlite + " FROM audit_logs WHERE (user_id = ? OR logged_in_user_id = ?) ORDER BY id",
	mysql:    "SELECT " + auditLogColumns.mysql + " FROM audit_logs WHERE (user_id = ? OR logged_in_user_id = ?) ORDER BY id",
	postgres: "SELECT " + auditLogColumns.postgres + " FROM audit_logs WHERE (user_id = $1 OR logged_in_user_id = $2) ORDER BY id",
	mssql:    "SELECT " + auditLogColumns.mssql + " FROM audit_logs WHERE (user_id = @p1 OR logged_in_user_id = @p2) ORDER BY id",
}

// auditLogsQueries answers the page and the count for the filters given.
func auditLogsQueries(byEvent, byRequestId, byUser bool) (page statement, count statement) {
	switch {
	case byEvent && byRequestId && byUser:
		return selectAuditLogsPageByEventRequestIdAndUser, countAuditLogsByEventRequestIdAndUser
	case byEvent && byRequestId:
		return selectAuditLogsPageByEventAndRequestId, countAuditLogsByEventAndRequestId
	case byEvent && byUser:
		return selectAuditLogsPageByEventAndUser, countAuditLogsByEventAndUser
	case byRequestId && byUser:
		return selectAuditLogsPageByRequestIdAndUser, countAuditLogsByRequestIdAndUser
	case byEvent:
		return selectAuditLogsPageByEvent, countAuditLogsByEvent
	case byRequestId:
		return selectAuditLogsPageByRequestId, countAuditLogsByRequestId
	case byUser:
		return selectAuditLogsPageByUser, countAuditLogsByUser
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
		auditLog.CreatedAt, auditLog.AuditEvent, auditLog.Details, auditLog.RequestId,
		auditLog.UserId, auditLog.LoggedInUserId)
	if err != nil {
		return err
	}

	auditLog.Id = id
	return nil
}

func (d *Database) GetAuditLogsPaginated(ctx context.Context, tx *sql.Tx, page int, pageSize int,
	filter record.AuditLogFilter) ([]record.AuditLog, int, error) {

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

	pageQuery, countQuery := auditLogsQueries(filter.AuditEvent != "", filter.RequestId != "", filter.UserId != 0)
	var filterArgs []any
	if filter.AuditEvent != "" {
		filterArgs = append(filterArgs, filter.AuditEvent)
	}
	if filter.RequestId != "" {
		filterArgs = append(filterArgs, filter.RequestId)
	}
	if filter.UserId != 0 {
		// Once for user_id and once for logged_in_user_id.
		filterArgs = append(filterArgs, filter.UserId, filter.UserId)
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
		if scanErr := scanAuditLog(rows, &auditLog); scanErr != nil {
			return nil, 0, errs.Wrap(scanErr, "unable to scan audit log")
		}
		// The request id is client-chosen and is looked up with `=`, so the engine and not
		// this package would otherwise decide which ids are the same id. A row the engine
		// folded in carries an id the caller did not ask for, and listing it would put one
		// request's audit entries under another request's id (#328, and see
		// engineFoldedTheMatch). On SQL Server the statement has already closed the fold, so
		// this finds nothing to drop there.
		if filter.RequestId != "" && engineFoldedTheMatch(auditLog.RequestId, filter.RequestId) {
			continue
		}
		auditLogs = append(auditLogs, auditLog)
	}

	// ceiling: the count cannot apply the guard above, which needs the rows, so on MySQL
	// a stored id that differs from the filter only by a fold `=` accepts at equal length
	// (a decomposed accent against its precomposed spelling) would be counted and not
	// listed, showing as a page total one higher than the rows shown. SQLite and
	// PostgreSQL have no such fold, and SQL Server's are closed in its statements above.
	// Nothing reaches it today: the only writer stores the id as
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

func (d *Database) GetAuditLogsByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]record.AuditLog, error) {
	// Once for user_id and once for logged_in_user_id.
	return queryAll(ctx, d, tx, nil, selectAuditLogsByUser.text(d.Dialect), []any{userId, userId},
		scanAuditLog, "audit log")
}
