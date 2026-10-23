package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// authorizeRequestColumns is the authorize_requests table as scanAuthorizeRequest reads it.
var authorizeRequestColumns = columnList{
	sqlite:   "id, created_at, updated_at, handle_hash, request_form, expires_at",
	mysql:    "id, created_at, updated_at, handle_hash, request_form, expires_at",
	postgres: "id, created_at, updated_at, handle_hash, request_form, expires_at",
	mssql:    "id, created_at, updated_at, handle_hash, request_form, expires_at",
}

// scanAuthorizeRequest reads one row selected with authorizeRequestColumns.
func scanAuthorizeRequest(row rowScanner, authorizeRequest *record.AuthorizeRequest) error {
	return row.Scan(
		&authorizeRequest.Id,
		&authorizeRequest.CreatedAt,
		&authorizeRequest.UpdatedAt,
		&authorizeRequest.HandleHash,
		&authorizeRequest.RequestForm,
		&authorizeRequest.ExpiresAt,
	)
}

var insertAuthorizeRequest = statement{
	sqlite: "INSERT INTO authorize_requests (created_at, updated_at, handle_hash, request_form, " +
		"expires_at) VALUES (?, ?, ?, ?, ?)",
	mysql: "INSERT INTO authorize_requests (created_at, updated_at, handle_hash, request_form, " +
		"expires_at) VALUES (?, ?, ?, ?, ?)",
	postgres: "INSERT INTO authorize_requests (created_at, updated_at, handle_hash, request_form, " +
		"expires_at) VALUES ($1, $2, $3, $4, $5) RETURNING id",
	mssql: "INSERT INTO authorize_requests (created_at, updated_at, handle_hash, request_form, " +
		"expires_at) OUTPUT INSERTED.id VALUES (@p1, @p2, @p3, @p4, @p5)",
}

// selectLiveAuthorizeRequest binds the hash, then the instant the request must expire after.
var selectLiveAuthorizeRequest = statement{
	sqlite: "SELECT " + authorizeRequestColumns.sqlite + " FROM authorize_requests " +
		"WHERE handle_hash = ? AND expires_at > ?",
	mysql: "SELECT " + authorizeRequestColumns.mysql + " FROM authorize_requests " +
		"WHERE handle_hash = ? AND expires_at > ?",
	postgres: "SELECT " + authorizeRequestColumns.postgres + " FROM authorize_requests " +
		"WHERE handle_hash = $1 AND expires_at > $2",
	mssql: "SELECT " + authorizeRequestColumns.mssql + " FROM authorize_requests " +
		"WHERE handle_hash = @p1 AND expires_at > @p2",
}

var claimAuthorizeRequest = statement{
	sqlite:   "DELETE FROM authorize_requests WHERE id = ?",
	mysql:    "DELETE FROM authorize_requests WHERE id = ?",
	postgres: "DELETE FROM authorize_requests WHERE id = $1",
	mssql:    "DELETE FROM authorize_requests WHERE id = @p1",
}

var deleteExpiredAuthorizeRequests = statement{
	sqlite:   "DELETE FROM authorize_requests WHERE expires_at < ?",
	mysql:    "DELETE FROM authorize_requests WHERE expires_at < ?",
	postgres: "DELETE FROM authorize_requests WHERE expires_at < $1",
	mssql:    "DELETE FROM authorize_requests WHERE expires_at < @p1",
}

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

	id, err := d.insert(ctx, tx, insertAuthorizeRequest, "authorize request",
		authorizeRequest.CreatedAt, authorizeRequest.UpdatedAt, authorizeRequest.HandleHash,
		authorizeRequest.RequestForm, authorizeRequest.ExpiresAt)
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

	authorizeRequest, err := queryOne(ctx, d, tx, selectLiveAuthorizeRequest.text(d.Dialect),
		[]any{handleHash, now}, scanAuthorizeRequest, "authorize request")
	if err != nil {
		return nil, err
	}
	if authorizeRequest == nil || authorizeRequest.HandleHash != handleHash {
		return nil, nil
	}

	return authorizeRequest, nil
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

	result, err := d.ExecSQL(ctx, tx, claimAuthorizeRequest.text(d.Dialect), authorizeRequestId)
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

	_, err := d.ExecSQL(ctx, tx, deleteExpiredAuthorizeRequests.text(d.Dialect), now)
	if err != nil {
		return errs.Wrap(err, "unable to delete expired authorize requests")
	}

	return nil
}
