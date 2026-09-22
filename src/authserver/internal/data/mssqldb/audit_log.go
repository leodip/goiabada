package mssqldb

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/data/commondb"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/errs"
)

func (d *MsSQLDatabase) DeleteOldAuditLogs(ctx context.Context, tx *sql.Tx, cutoff time.Time, maxDeletions int) (int, error) {
	// MSSQL uses DELETE TOP(n) syntax
	sqlStr := fmt.Sprintf("DELETE TOP (%d) FROM audit_logs WHERE created_at < @p1", maxDeletions)

	result, err := d.ExecSql(ctx, tx, sqlStr, cutoff)
	if err != nil {
		return 0, errs.Wrap(err, "unable to delete old audit logs")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, errs.Wrap(err, "unable to get rows affected")
	}

	return int(rowsAffected), nil
}

// requestIdIsByteExact is the predicate that holds SQL Server to the bytes of the request id,
// written once because the page query and the count query must carry the same one.
//
// `=` is not exact on this engine: it pads, so request_id = 'corr' is true of a row holding
// 'corr ' under every collation SQL Server has, Latin1_General_100_BIN2_UTF8 included, and no
// collation turns that off (see commondb.engineFoldedTheMatch). commondb answers that by
// dropping the folded rows after the scan, which cannot work here: this body pages with
// OFFSET/FETCH, so a row dropped after the fetch leaves a short page, and the count query has
// no rows to drop at all. Measured against the live engine, a guard applied after the fetch
// gave an empty page under a total of 1 (#328).
//
// So the fold is closed in the statement instead, and in both statements. The equality stays
// beside it so the index on request_id can still seek; the CAST is the filter. VARBINARY(512)
// is the column's whole width: request_id is NVARCHAR(256), which stores UTF-16 even under the
// UTF-8 collation, so 256 characters are 512 bytes and nothing that fits the column is clipped
// by the cast.
func requestIdIsByteExact(b interface{ Var(arg interface{}) string }, requestId string) string {
	return "CAST(request_id AS VARBINARY(512)) = CAST(" + b.Var(requestId) + " AS VARBINARY(512))"
}

func (d *MsSQLDatabase) GetAuditLogsPaginated(ctx context.Context, tx *sql.Tx, page int, pageSize int, auditEvent string,
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

	offset := commondb.PageOffset(page, pageSize)

	auditLogStruct := sqlbuilder.NewStruct(new(models.AuditLog)).
		For(sqlbuilder.SQLServer)

	selectBuilder := auditLogStruct.SelectFrom("audit_logs")
	if auditEvent != "" {
		selectBuilder.Where(selectBuilder.Equal("audit_event", auditEvent))
	}
	if requestId != "" {
		selectBuilder.Where(selectBuilder.Equal("request_id", requestId),
			requestIdIsByteExact(selectBuilder, requestId))
	}
	// MSSQL pagination: ORDER BY ... OFFSET n ROWS FETCH NEXT m ROWS ONLY
	selectBuilder.OrderBy("created_at DESC", "id DESC")

	sqlStr, args := selectBuilder.Build()
	// MSSQL requires OFFSET...FETCH syntax for pagination
	sqlStr = fmt.Sprintf("%s OFFSET %d ROWS FETCH NEXT %d ROWS ONLY", sqlStr, offset, pageSize)

	rows, err := d.QuerySql(ctx, tx, sqlStr, args...)
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
	if requestId != "" {
		countBuilder.Where(countBuilder.Equal("request_id", requestId),
			requestIdIsByteExact(countBuilder, requestId))
	}

	countSql, countArgs := countBuilder.Build()
	countRows, err := d.QuerySql(ctx, tx, countSql, countArgs...)
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
