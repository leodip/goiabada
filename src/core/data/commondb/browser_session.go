package commondb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

// A browser session is keyed on (owner, session_id_hash), the table's unique index,
// because the store never holds the surrogate id: all it has is an identifier taken
// from a cookie and the name of the application asking (#266).
//
// Both key parts are rejected when empty rather than used as a filter, the rule
// RevokeCodeIfSessionGone states. No row carries an empty owner or an empty hash, so an
// empty value can only be a caller bug, and matching on one would either return
// somebody else's row or sweep rows the caller never named.

func (d *CommonDatabase) CreateBrowserSession(tx *sql.Tx, browserSession *models.BrowserSession) error {

	if browserSession.Owner == "" {
		return errors.WithStack(errors.New("can't create a browser session with an empty owner"))
	}

	if browserSession.SessionIdHash == "" {
		return errors.WithStack(errors.New("can't create a browser session with an empty session id hash"))
	}

	now := time.Now().UTC()

	originalCreatedAt := browserSession.CreatedAt
	originalUpdatedAt := browserSession.UpdatedAt
	browserSession.CreatedAt = sql.NullTime{Time: now, Valid: true}
	browserSession.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	browserSessionStruct := sqlbuilder.NewStruct(new(models.BrowserSession)).
		For(d.Flavor)

	insertBuilder := browserSessionStruct.WithoutTag("pk").InsertInto("browser_sessions", browserSession)

	sql, args := insertBuilder.Build()
	result, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		browserSession.CreatedAt = originalCreatedAt
		browserSession.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert browser session")
	}

	id, err := result.LastInsertId()
	if err != nil {
		browserSession.CreatedAt = originalCreatedAt
		browserSession.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to get last insert id")
	}

	browserSession.Id = id
	return nil
}

// GetBrowserSessionByOwnerAndSessionIdHash returns the live session, or nil if there is
// none.
//
// `now` is an active-expiry predicate rather than a hint: the statement matches only
// expires_at > now, so an expired row reads as absent whether or not the reaper has
// reached it. Deciding liveness in the engine, in the same statement that reads the row,
// is also what stops a Go-side comparison racing a concurrent reap.
//
// nil and an error are different answers. nil means there is no such session, which is a
// fresh session; an error means the lookup could not be performed, which is a refused
// request. Every failure below therefore propagates instead of collapsing into a nil
// session, including rows.Err(), which is where a driver reports a fault it deferred to
// the result set rather than returning from the query.
func (d *CommonDatabase) GetBrowserSessionByOwnerAndSessionIdHash(tx *sql.Tx, owner, sessionIdHash string,
	now time.Time) (*models.BrowserSession, error) {

	if owner == "" {
		return nil, errors.WithStack(errors.New("can't get a browser session with an empty owner"))
	}

	if sessionIdHash == "" {
		return nil, errors.WithStack(errors.New("can't get a browser session with an empty session id hash"))
	}

	browserSessionStruct := sqlbuilder.NewStruct(new(models.BrowserSession)).
		For(d.Flavor)

	selectBuilder := browserSessionStruct.SelectFrom("browser_sessions")
	selectBuilder.Where(
		selectBuilder.Equal("owner", owner),
		selectBuilder.Equal("session_id_hash", sessionIdHash),
		selectBuilder.GreaterThan("expires_at", now),
	)

	query, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var browserSession models.BrowserSession
	if rows.Next() {
		addr := browserSessionStruct.Addr(&browserSession)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan browser session")
		}
		return &browserSession, nil
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "unable to read query results")
	}

	return nil, nil
}

// UpdateBrowserSessionData replaces one session's contents and moves its deadlines,
// reporting whether a row transitioned.
//
// Narrow rather than the house's full-row Update<Model> for the reason
// PromoteUserSessionOtpConfigGeneration is narrow: it sits on a per-request path, and the
// caller holds no surrogate id to write a whole row back by.
//
// The expires_at > now term is in the WHERE for the same reason it is in the read above.
// Without it a write would touch an expired row's deadline forward, and the idle timeout
// could never close a session anyone kept poking.
//
// A false return means no row transitioned: the session is gone, or it expired. That is
// the distinction the caller needs to tell "written" from "the row is no longer there".
//
// One caveat on what RowsAffected counts. SQLite, PostgreSQL and SQL Server report rows
// MATCHED; MySQL reports rows CHANGED, so a statement that matched a row and wrote it
// values identical to the ones already there reports zero. What rules that out here is
// that updated_at and last_accessed are both stamped with `now`, at microsecond
// resolution on every engine, and each save takes its own reading of the clock. Two
// saves of one session inside the same microsecond would have to carry identical
// contents as well, and would then report false and cost that browser a fresh session.
func (d *CommonDatabase) UpdateBrowserSessionData(tx *sql.Tx, owner, sessionIdHash, data string,
	now, expiresAt time.Time) (bool, error) {

	if owner == "" {
		return false, errors.WithStack(errors.New("can't update a browser session with an empty owner"))
	}

	if sessionIdHash == "" {
		return false, errors.WithStack(errors.New("can't update a browser session with an empty session id hash"))
	}

	ub := sqlbuilder.NewUpdateBuilder()
	ub.Update("browser_sessions")
	ub.Set(
		ub.Assign("data", data),
		ub.Assign("last_accessed", now),
		ub.Assign("expires_at", expiresAt),
		ub.Assign("updated_at", now),
	)
	ub.Where(
		ub.Equal("owner", owner),
		ub.Equal("session_id_hash", sessionIdHash),
		ub.GreaterThan("expires_at", now),
	)

	query, args := ub.BuildWithFlavor(d.Flavor)
	result, err := d.ExecSql(tx, query, args...)
	if err != nil {
		return false, errors.Wrap(err, "unable to update browser session data")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errors.Wrap(err, "unable to get rows affected when updating browser session data")
	}

	return rowsAffected == 1, nil
}

// TouchBrowserSession records that a live session was used, and reports whether a row
// transitioned.
//
// It moves expires_at as well as last_accessed, and that is not incidental: the idle
// window is expressed in expires_at, so a touch that left it alone would never extend
// the session and the idle timeout would behave as an absolute one.
//
// The expires_at > now term and the meaning of the false return are as
// UpdateBrowserSessionData above describes them. What RowsAffected counts is not: see
// below, because the argument that discharges it for that statement is absent for this
// one.
func (d *CommonDatabase) TouchBrowserSession(tx *sql.Tx, owner, sessionIdHash string,
	now, expiresAt time.Time) (bool, error) {

	if owner == "" {
		return false, errors.WithStack(errors.New("can't touch a browser session with an empty owner"))
	}

	if sessionIdHash == "" {
		return false, errors.WithStack(errors.New("can't touch a browser session with an empty session id hash"))
	}

	ub := sqlbuilder.NewUpdateBuilder()
	ub.Update("browser_sessions")
	ub.Set(
		ub.Assign("last_accessed", now),
		ub.Assign("expires_at", expiresAt),
		ub.Assign("updated_at", now),
	)
	ub.Where(
		ub.Equal("owner", owner),
		ub.Equal("session_id_hash", sessionIdHash),
		ub.GreaterThan("expires_at", now),
	)

	query, args := ub.BuildWithFlavor(d.Flavor)
	result, err := d.ExecSql(tx, query, args...)
	if err != nil {
		return false, errors.Wrap(err, "unable to touch browser session")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errors.Wrap(err, "unable to get rows affected when touching browser session")
	}

	if rowsAffected == 1 {
		return true, nil
	}

	// Zero is not by itself an answer here, and this is exactly where this statement
	// differs from UpdateBrowserSessionData. MySQL reports rows CHANGED rather than
	// MATCHED, and every column this one writes, last_accessed, expires_at and updated_at,
	// is derived from the single `now` it was handed. Two concurrent requests from one
	// browser that both find last_accessed stale and both stamp the same microsecond
	// therefore write byte-identical values, and MySQL answers zero for a row that is
	// plainly there. UpdateBrowserSessionData is safe from that because it also writes the
	// session blob, which is freshly encrypted on every save and so never repeats; a touch
	// writes no contents at all, so that clause simply does not exist for it.
	//
	// What a wrong false costs is the browser its session: the store reads it as "the row
	// is gone" and hands back a fresh one, signing a user out mid-session for no reason
	// they could see. So absence is confirmed rather than inferred, under the same
	// predicate the read uses, and the extra statement runs only where the caller was
	// already about to throw the session away (#266).
	browserSession, err := d.GetBrowserSessionByOwnerAndSessionIdHash(tx, owner, sessionIdHash, now)
	if err != nil {
		return false, errors.Wrap(err, "unable to confirm the browser session after touching it")
	}

	return browserSession != nil, nil
}

// DeleteBrowserSession removes one session, which is what logging out and rotating an
// identifier both do. It carries no expiry term: an expired row is already unusable, and
// deleting it is the intended outcome either way.
func (d *CommonDatabase) DeleteBrowserSession(tx *sql.Tx, owner, sessionIdHash string) error {

	if owner == "" {
		return errors.WithStack(errors.New("can't delete a browser session with an empty owner"))
	}

	if sessionIdHash == "" {
		return errors.WithStack(errors.New("can't delete a browser session with an empty session id hash"))
	}

	browserSessionStruct := sqlbuilder.NewStruct(new(models.BrowserSession)).
		For(d.Flavor)

	deleteBuilder := browserSessionStruct.DeleteFrom("browser_sessions")
	deleteBuilder.Where(
		deleteBuilder.Equal("owner", owner),
		deleteBuilder.Equal("session_id_hash", sessionIdHash),
	)

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete browser session")
	}

	return nil
}

// DeleteExpiredBrowserSessions reaps on expires_at alone, across both owners. Every row
// it removes was already unusable, by the expires_at > now term the read and both
// conditional updates carry; this is what stops the table growing rather than what makes
// a session end.
func (d *CommonDatabase) DeleteExpiredBrowserSessions(tx *sql.Tx, now time.Time) error {

	browserSessionStruct := sqlbuilder.NewStruct(new(models.BrowserSession)).
		For(d.Flavor)

	deleteBuilder := browserSessionStruct.DeleteFrom("browser_sessions")
	deleteBuilder.Where(deleteBuilder.LessThan("expires_at", now))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete expired browser sessions")
	}

	return nil
}
