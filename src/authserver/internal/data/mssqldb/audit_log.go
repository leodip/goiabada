package mssqldb

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data/commondb"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// deleteOldAuditLogs binds the cutoff, then the bound. SQL Server has no LIMIT at all; DELETE TOP
// (n) is its bound on a delete, and n may be a parameter.
const deleteOldAuditLogs = "DELETE TOP (@p2) FROM audit_logs WHERE created_at < @p1"

// DeleteOldAuditLogs deletes up to maxDeletions audit rows older than cutoff and reports how many
// went.
//
// commondb declares no DeleteOldAuditLogs, so each engine has to write its own and an engine that
// forgets fails to compile against data.Database rather than inheriting another engine's syntax
// (#438 decision 7).
func (d *Database) DeleteOldAuditLogs(ctx context.Context, tx *sql.Tx, cutoff time.Time, maxDeletions int) (int, error) {
	result, err := d.ExecSQL(ctx, tx, deleteOldAuditLogs, cutoff, maxDeletions)
	if err != nil {
		return 0, errs.Wrap(err, "unable to delete old audit logs")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, errs.Wrap(err, "unable to get rows affected")
	}

	return int(rowsAffected), nil
}

// The page of audit logs and its count, one pair per combination of the two filters, in SQL Server's
// own text. A page binds the filters it carries, the event before the request id, then the offset,
// then the page size, as OFFSET … FETCH names them. The order is total, created_at DESC and then
// id DESC, so tied rows cannot drift between pages.
//
// THE REQUEST-ID FILTER COMPARES THE BYTES, in the page and the count alike. `=` is not exact on
// this engine: it pads, so request_id = 'corr' is true of a row holding 'corr ' under every
// collation SQL Server has, Latin1_General_100_BIN2_UTF8 included, and no collation turns that off
// (see commondb.engineFoldedTheMatch). commondb answers that by dropping the folded rows after the
// scan, which cannot work here: this body pages with OFFSET/FETCH, so a row dropped after the fetch
// leaves a short page, and the count query has no rows to drop at all. Measured against the live
// engine, a guard applied after the fetch gave an empty page under a total of 1 (#328).
//
// So the fold is closed in the statement instead, and in both statements. The equality stays
// beside it so the index on request_id can still seek; the CAST is the filter, and reads the same
// parameter. VARBINARY(512) is the column's whole width: request_id is NVARCHAR(256), which stores
// UTF-16 even under the UTF-8 collation, so 256 characters are 512 bytes and nothing that fits the
// column is clipped by the cast.
const (
	auditLogColumns = "id, created_at, audit_event, details, request_id"

	selectAuditLogsPage = "SELECT " + auditLogColumns + " FROM audit_logs " +
		"ORDER BY created_at DESC, id DESC OFFSET @p1 ROWS FETCH NEXT @p2 ROWS ONLY"
	countAuditLogs = "SELECT COUNT(*) FROM audit_logs"

	selectAuditLogsPageByEvent = "SELECT " + auditLogColumns + " FROM audit_logs WHERE audit_event = @p1 " +
		"ORDER BY created_at DESC, id DESC OFFSET @p2 ROWS FETCH NEXT @p3 ROWS ONLY"
	countAuditLogsByEvent = "SELECT COUNT(*) FROM audit_logs WHERE audit_event = @p1"

	selectAuditLogsPageByRequestId = "SELECT " + auditLogColumns + " FROM audit_logs " +
		"WHERE request_id = @p1 AND CAST(request_id AS VARBINARY(512)) = CAST(@p1 AS VARBINARY(512)) " +
		"ORDER BY created_at DESC, id DESC OFFSET @p2 ROWS FETCH NEXT @p3 ROWS ONLY"
	countAuditLogsByRequestId = "SELECT COUNT(*) FROM audit_logs " +
		"WHERE request_id = @p1 AND CAST(request_id AS VARBINARY(512)) = CAST(@p1 AS VARBINARY(512))"

	selectAuditLogsPageByEventAndRequestId = "SELECT " + auditLogColumns + " FROM audit_logs " +
		"WHERE audit_event = @p1 AND request_id = @p2 AND CAST(request_id AS VARBINARY(512)) = CAST(@p2 AS VARBINARY(512)) " +
		"ORDER BY created_at DESC, id DESC OFFSET @p3 ROWS FETCH NEXT @p4 ROWS ONLY"
	countAuditLogsByEventAndRequestId = "SELECT COUNT(*) FROM audit_logs " +
		"WHERE audit_event = @p1 AND request_id = @p2 AND CAST(request_id AS VARBINARY(512)) = CAST(@p2 AS VARBINARY(512))"
)

// auditLogsQueries answers the page and the count for the filters given.
func auditLogsQueries(byEvent, byRequestId bool) (page string, count string) {
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

// GetAuditLogsPaginated replaces commondb's because SQL Server's `=` pads, so a request-id filter
// has to compare the bytes in the page query and the count query alike, where commondb drops the
// folded rows after the scan (#328).
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

	offset := commondb.PageOffset(page, pageSize)

	pageQuery, countQuery := auditLogsQueries(auditEvent != "", requestId != "")
	var filterArgs []any
	if auditEvent != "" {
		filterArgs = append(filterArgs, auditEvent)
	}
	if requestId != "" {
		filterArgs = append(filterArgs, requestId)
	}
	pageArgs := append(append([]any{}, filterArgs...), offset, pageSize)

	rows, err := d.QuerySQL(ctx, tx, pageQuery, pageArgs...)
	if err != nil {
		return nil, 0, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var auditLogs []record.AuditLog
	for rows.Next() {
		var auditLog record.AuditLog
		err = rows.Scan(&auditLog.Id, &auditLog.CreatedAt, &auditLog.AuditEvent, &auditLog.Details, &auditLog.RequestId)
		if err != nil {
			return nil, 0, errs.Wrap(err, "unable to scan audit log")
		}
		auditLogs = append(auditLogs, auditLog)
	}

	countRows, err := d.QuerySQL(ctx, tx, countQuery, filterArgs...)
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
