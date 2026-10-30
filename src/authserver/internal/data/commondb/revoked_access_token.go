package commondb

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// insertRevokedAccessToken writes the whole record, which has no id: the jti is its key.
var insertRevokedAccessToken = statement{
	sqlite:   "INSERT INTO revoked_access_tokens (jti, expires_at) VALUES (?, ?)",
	mysql:    "INSERT INTO revoked_access_tokens (jti, expires_at) VALUES (?, ?)",
	postgres: "INSERT INTO revoked_access_tokens (jti, expires_at) VALUES ($1, $2)",
	mssql:    "INSERT INTO revoked_access_tokens (jti, expires_at) VALUES (@p1, @p2)",
}

var selectRevokedAccessToken = statement{
	sqlite:   "SELECT jti FROM revoked_access_tokens WHERE jti = ?",
	mysql:    "SELECT jti FROM revoked_access_tokens WHERE jti = ?",
	postgres: "SELECT jti FROM revoked_access_tokens WHERE jti = $1",
	mssql:    "SELECT jti FROM revoked_access_tokens WHERE jti = @p1",
}

var deleteExpiredRevokedAccessTokens = statement{
	sqlite:   "DELETE FROM revoked_access_tokens WHERE expires_at < ?",
	mysql:    "DELETE FROM revoked_access_tokens WHERE expires_at < ?",
	postgres: "DELETE FROM revoked_access_tokens WHERE expires_at < $1",
	mssql:    "DELETE FROM revoked_access_tokens WHERE expires_at < @p1",
}

// An access token without a grant, of the client credentials grant or the implicit flow, is revoked
// by storing its jti with its expiry (#676 decision 1): no refresh token family stands behind it to
// end. The access-token liveness check reads the row for every such token, and the background
// worker deletes it once the token has expired, when it has nothing left to refuse.
//
// An empty jti is an error in every method below: the auth server signs none, so it can only be a
// caller bug, and answering it would store or read a row that no token names.

// RecordAccessTokenRevoked stores the jti of one revoked access token with the token's expiry, and
// reports whether THIS call stored it. A jti already stored is left as it was: its first expiry
// stays, and the call reports false, which is what lets the revocation endpoint record its event
// only for the revocation that happened.
//
// The row is read before it is written, so a revocation of a token already revoked neither inserts
// nor trips the key. Two calls for one token that overlap can both read absent, and the second
// insert then loses on the key: that is reported false as well, since the token is revoked either
// way. On PostgreSQL the refused insert aborts the transaction it ran in, so a caller that passes
// one ends it there; the revocation endpoint passes none.
func (d *Database) RecordAccessTokenRevoked(ctx context.Context, tx *sql.Tx, jti string, expiresAt time.Time) (bool, error) {

	if jti == "" {
		return false, errs.New("can't record a revoked access token with an empty jti")
	}

	already, err := d.IsAccessTokenRevoked(ctx, tx, jti)
	if err != nil {
		return false, err
	}
	if already {
		return false, nil
	}

	revoked := &record.RevokedAccessToken{Jti: jti, ExpiresAt: expiresAt.UTC()}
	_, err = d.ExecSQL(ctx, tx, insertRevokedAccessToken.text(d.Dialect), revoked.Jti, revoked.ExpiresAt)
	if errors.Is(err, data.ErrUniqueViolation) {
		return false, nil
	}
	if err != nil {
		return false, errs.Wrap(err, "unable to record revoked access token")
	}

	return true, nil
}

// IsAccessTokenRevoked reports whether an access token's jti is stored as revoked.
//
// The row that comes back is compared with the jti it was asked for in Go, for the reason
// GetAuthorizeRequestByHandleHash states: SQL Server pads for `=` under every collation, so a jti
// with trailing spaces would find the row of the one without (#283).
//
// An error and false are different answers: false lets the token proceed, and an error says the
// lookup could not be performed, which refuses it. Every failure below propagates, rows.Err()
// included.
func (d *Database) IsAccessTokenRevoked(ctx context.Context, tx *sql.Tx, jti string) (bool, error) {

	if jti == "" {
		return false, errs.New("can't look up a revoked access token with an empty jti")
	}

	rows, err := d.QuerySQL(ctx, tx, selectRevokedAccessToken.text(d.Dialect), jti)
	if err != nil {
		return false, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	if rows.Next() {
		var found string
		if err := rows.Scan(&found); err != nil {
			return false, errs.Wrap(err, "unable to scan revoked access token")
		}
		return !engineFoldedTheMatch(found, jti), nil
	}
	if err := rows.Err(); err != nil {
		return false, errs.Wrap(err, "unable to read query results")
	}

	return false, nil
}

// DeleteExpiredRevokedAccessTokens reaps on expires_at alone. Every row it removes names a token
// already refused for its expiry; this is what stops the table growing rather than what ends a
// token. A row whose token expires at now itself is kept for the next sweep.
func (d *Database) DeleteExpiredRevokedAccessTokens(ctx context.Context, tx *sql.Tx, now time.Time) error {

	_, err := d.ExecSQL(ctx, tx, deleteExpiredRevokedAccessTokens.text(d.Dialect), now)
	if err != nil {
		return errs.Wrap(err, "unable to delete expired revoked access tokens")
	}

	return nil
}
