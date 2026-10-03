package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// A parked authorization request is found by handle_hash, the table's unique index, because the
// GET that consumes it holds only the handle the redirect carried, and the row keeps its digest
// (#246, #437). An empty hash is rejected rather than used as a filter, the rule the browser
// session methods state: no row carries one, so it can only be a caller bug, and matching on it
// would either return another request's row or sweep rows the caller never named.

func (d *Database) CreateAuthorizeRequest(ctx context.Context, tx *sql.Tx, authorizeRequest *record.AuthorizeRequest) error {

	if authorizeRequest.HandleHash == "" {
		return errs.New("can't create an authorize request with an empty handle hash")
	}

	if authorizeRequest.ExpiresAt.IsZero() {
		return errs.New("can't create an authorize request that never expires")
	}

	now := time.Now().UTC()

	originalCreatedAt := authorizeRequest.CreatedAt
	originalUpdatedAt := authorizeRequest.UpdatedAt
	authorizeRequest.CreatedAt = sql.NullTime{Time: now, Valid: true}
	authorizeRequest.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	authorizeRequestStruct := sqlbuilder.NewStruct(new(record.AuthorizeRequest)).
		For(d.Flavor)

	insertBuilder := authorizeRequestStruct.WithoutTag("pk").InsertInto("authorize_requests", authorizeRequest)

	id, err := d.insertReturningId(ctx, tx, insertBuilder, "authorize request")
	if err != nil {
		authorizeRequest.CreatedAt = originalCreatedAt
		authorizeRequest.UpdatedAt = originalUpdatedAt
		return err
	}

	authorizeRequest.Id = id
	return nil
}

// GetAuthorizeRequestByHandleHash returns the live parked request, or nil if there is none.
//
// `now` is an active-expiry predicate rather than a hint: the statement matches only
// expires_at > now, so an expired request reads as absent whether or not the sweep has reached it.
// Deciding liveness in the engine, in the same statement that reads the row, is what stops a
// Go-side comparison racing a concurrent sweep.
//
// The row that comes back is compared with the hash it was asked for in Go. SQL Server pads for
// `=` under every collation, so a hash with trailing spaces would find the row of the one
// without, and the column's collation cannot close that (reference/migrations.md, case handling).
//
// nil and an error are different answers. nil means there is no such request, which is a refusal
// the browser can act on; an error means the lookup could not be performed. Every failure below
// propagates instead of collapsing into nil, including rows.Err(), where a driver reports a fault
// it deferred to the result set.
func (d *Database) GetAuthorizeRequestByHandleHash(ctx context.Context, tx *sql.Tx, handleHash string,
	now time.Time) (*record.AuthorizeRequest, error) {

	if handleHash == "" {
		return nil, errs.New("can't get an authorize request with an empty handle hash")
	}

	authorizeRequestStruct := sqlbuilder.NewStruct(new(record.AuthorizeRequest)).
		For(d.Flavor)

	selectBuilder := authorizeRequestStruct.SelectFrom("authorize_requests")
	selectBuilder.Where(
		selectBuilder.Equal("handle_hash", handleHash),
		selectBuilder.GreaterThan("expires_at", now),
	)

	query, args := selectBuilder.Build()
	rows, err := d.QuerySQL(ctx, tx, query, args...)
	if err != nil {
		return nil, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var authorizeRequest record.AuthorizeRequest
	if rows.Next() {
		addr := authorizeRequestStruct.Addr(&authorizeRequest)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errs.Wrap(err, "unable to scan authorize request")
		}
		if authorizeRequest.HandleHash != handleHash {
			return nil, nil
		}
		return &authorizeRequest, nil
	}
	if err := rows.Err(); err != nil {
		return nil, errs.Wrap(err, "unable to read query results")
	}

	return nil, nil
}

// ClaimAuthorizeRequest consumes one parked request, and reports whether THIS call deleted it. It
// is the one-winner claim that makes a handle single use, in the shape of MarkCodeAsUsed: a
// request is read and then claimed, and the caller may act on what it read only when the claim
// says it was the one that took it.
//
// A false return means no row was deleted, which is the request having been claimed by another
// call between this caller's read and this statement, or swept. The caller's job on false is to
// refuse as it would for an unknown handle.
//
// The count is exact on all four engines: a DELETE reports the rows it removed, not the rows it
// matched, so MySQL's changed-rows quirk does not reach it. Two overlapping claims of one row are
// serialised by the engine's row lock on the DELETE, and the second finds no row to remove.
func (d *Database) ClaimAuthorizeRequest(ctx context.Context, tx *sql.Tx, authorizeRequestId int64) (bool, error) {

	if authorizeRequestId == 0 {
		return false, errs.New("can't claim the authorize request with id 0")
	}

	authorizeRequestStruct := sqlbuilder.NewStruct(new(record.AuthorizeRequest)).
		For(d.Flavor)

	deleteBuilder := authorizeRequestStruct.DeleteFrom("authorize_requests")
	deleteBuilder.Where(deleteBuilder.Equal("id", authorizeRequestId))

	query, args := deleteBuilder.Build()
	result, err := d.ExecSQL(ctx, tx, query, args...)
	if err != nil {
		return false, errs.Wrap(err, "unable to claim authorize request")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errs.Wrap(err, "unable to get rows affected when claiming authorize request")
	}

	return rowsAffected == 1, nil
}

// DeleteExpiredAuthorizeRequests reaps on expires_at alone. Every row it removes was already
// unusable, by the expires_at > now term the read carries; this is what stops the table growing
// rather than what makes a request expire.
func (d *Database) DeleteExpiredAuthorizeRequests(ctx context.Context, tx *sql.Tx, now time.Time) error {

	authorizeRequestStruct := sqlbuilder.NewStruct(new(record.AuthorizeRequest)).
		For(d.Flavor)

	deleteBuilder := authorizeRequestStruct.DeleteFrom("authorize_requests")
	deleteBuilder.Where(deleteBuilder.LessThan("expires_at", now))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSQL(ctx, tx, sql, args...)
	if err != nil {
		return errs.Wrap(err, "unable to delete expired authorize requests")
	}

	return nil
}
