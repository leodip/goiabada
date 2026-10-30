package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// insertRefreshTokenFamilyRevocation writes the whole record, which has no id: the first token's
// jti is its key.
var insertRefreshTokenFamilyRevocation = statement{
	sqlite: "INSERT INTO refresh_token_family_revocations (first_refresh_token_jti, reason, revoked_at) " +
		"VALUES (?, ?, ?)",
	mysql: "INSERT INTO refresh_token_family_revocations (first_refresh_token_jti, reason, revoked_at) " +
		"VALUES (?, ?, ?)",
	postgres: "INSERT INTO refresh_token_family_revocations (first_refresh_token_jti, reason, revoked_at) " +
		"VALUES ($1, $2, $3)",
	mssql: "INSERT INTO refresh_token_family_revocations (first_refresh_token_jti, reason, revoked_at) " +
		"VALUES (@p1, @p2, @p3)",
}

var selectRefreshTokenFamilyRevocation = statement{
	sqlite: "SELECT first_refresh_token_jti FROM refresh_token_family_revocations " +
		"WHERE first_refresh_token_jti = ?",
	mysql: "SELECT first_refresh_token_jti FROM refresh_token_family_revocations " +
		"WHERE first_refresh_token_jti = ?",
	postgres: "SELECT first_refresh_token_jti FROM refresh_token_family_revocations " +
		"WHERE first_refresh_token_jti = $1",
	mssql: "SELECT first_refresh_token_jti FROM refresh_token_family_revocations " +
		"WHERE first_refresh_token_jti = @p1",
}

// selectRefreshTokenFamilyLiveness answers, in one row, the family's revocation record and one of
// its members that is not revoked, each as the identifier it matched or NULL. Both read by an
// index: the record by its key, the members by idx_refresh_tokens_first_refresh_token_jti.
var selectRefreshTokenFamilyLiveness = statement{
	sqlite: "SELECT (SELECT first_refresh_token_jti FROM refresh_token_family_revocations " +
		"WHERE first_refresh_token_jti = ?), " +
		"(SELECT MIN(first_refresh_token_jti) FROM refresh_tokens WHERE first_refresh_token_jti = ? AND revoked = ?)",
	mysql: "SELECT (SELECT first_refresh_token_jti FROM refresh_token_family_revocations " +
		"WHERE first_refresh_token_jti = ?), " +
		"(SELECT MIN(first_refresh_token_jti) FROM refresh_tokens WHERE first_refresh_token_jti = ? AND revoked = ?)",
	postgres: "SELECT (SELECT first_refresh_token_jti FROM refresh_token_family_revocations " +
		"WHERE first_refresh_token_jti = $1), " +
		"(SELECT MIN(first_refresh_token_jti) FROM refresh_tokens WHERE first_refresh_token_jti = $2 AND revoked = $3)",
	mssql: "SELECT (SELECT first_refresh_token_jti FROM refresh_token_family_revocations " +
		"WHERE first_refresh_token_jti = @p1), " +
		"(SELECT MIN(first_refresh_token_jti) FROM refresh_tokens WHERE first_refresh_token_jti = @p2 AND revoked = @p3)",
}

var deleteOrphanedRefreshTokenFamilyRevocations = statement{
	sqlite: "DELETE FROM refresh_token_family_revocations WHERE NOT EXISTS (SELECT 1 FROM refresh_tokens " +
		"WHERE refresh_tokens.first_refresh_token_jti = refresh_token_family_revocations.first_refresh_token_jti)",
	mysql: "DELETE FROM refresh_token_family_revocations WHERE NOT EXISTS (SELECT 1 FROM refresh_tokens " +
		"WHERE refresh_tokens.first_refresh_token_jti = refresh_token_family_revocations.first_refresh_token_jti)",
	postgres: "DELETE FROM refresh_token_family_revocations WHERE NOT EXISTS (SELECT 1 FROM refresh_tokens " +
		"WHERE refresh_tokens.first_refresh_token_jti = refresh_token_family_revocations.first_refresh_token_jti)",
	mssql: "DELETE FROM refresh_token_family_revocations WHERE NOT EXISTS (SELECT 1 FROM refresh_tokens " +
		"WHERE refresh_tokens.first_refresh_token_jti = refresh_token_family_revocations.first_refresh_token_jti)",
}

// A revoked rotation family is one row keyed by first_refresh_token_jti, written in the same
// transaction as the revocation it records and read by the refresh validator and by the
// rotation's own transaction (#132, #259, #437). The record is what a sweep of live rows cannot
// be: a rotation claims its parent and inserts its child in separate statements, so in between
// there is no live member of the family to find, and a revocation that arrived then would miss
// the child. A child that commits after the record exists is born refused.
//
// An empty jti is an error in every method below, for the reason RevokeRefreshTokenFamily states:
// on a revocation path it can only be a caller bug, and absorbing it would record, read or sweep
// the wrong family.

// RecordRefreshTokenFamilyRevoked writes the record for one family, and reports whether THIS call
// wrote it. A family already recorded is left as it was: its first reason and time stay, and the
// call reports false, which is what lets containment audit a replay that recorded the family
// without having revoked a live row.
//
// The row is read before it is written, so the common repeat, a replayed token presented again,
// neither inserts nor trips the unique key. Two calls for the same family that overlap can both
// read absent, and the second insert then loses on the key: that is reported as
// data.ErrUniqueViolation, and a caller reruns its transaction once, because on PostgreSQL the
// refused insert aborts the transaction it ran in.
func (d *Database) RecordRefreshTokenFamilyRevoked(ctx context.Context, tx *sql.Tx, firstRefreshTokenJti string,
	reason string) (bool, error) {

	if firstRefreshTokenJti == "" {
		return false, errs.New("can't record a revoked refresh token family with an empty first refresh token jti")
	}
	if reason == "" {
		return false, errs.New("can't record a revoked refresh token family without a reason")
	}

	already, err := d.IsRefreshTokenFamilyRevoked(ctx, tx, firstRefreshTokenJti)
	if err != nil {
		return false, err
	}
	if already {
		return false, nil
	}

	revocation := &record.RefreshTokenFamilyRevocation{
		FirstRefreshTokenJti: firstRefreshTokenJti,
		Reason:               reason,
		RevokedAt:            time.Now().UTC(),
	}
	_, err = d.ExecSQL(ctx, tx, insertRefreshTokenFamilyRevocation.text(d.Dialect),
		revocation.FirstRefreshTokenJti, revocation.Reason, revocation.RevokedAt)
	if err != nil {
		return false, errs.Wrap(err, "unable to record revoked refresh token family")
	}

	return true, nil
}

// IsRefreshTokenFamilyRevoked reports whether the family has a revocation record.
//
// The row that comes back is compared with the jti it was asked for in Go, for the reason
// GetAuthorizeRequestByHandleHash states: SQL Server pads for `=` under every collation, so a jti
// with trailing spaces would find the record of the one without (#283).
//
// An error and false are different answers: false means the family is not recorded, which lets the
// token proceed, and an error means the lookup could not be performed, which refuses it. Every
// failure below propagates, rows.Err() included.
func (d *Database) IsRefreshTokenFamilyRevoked(ctx context.Context, tx *sql.Tx, firstRefreshTokenJti string) (bool, error) {

	if firstRefreshTokenJti == "" {
		return false, errs.New("can't look up a refresh token family with an empty first refresh token jti")
	}

	rows, err := d.QuerySQL(ctx, tx, selectRefreshTokenFamilyRevocation.text(d.Dialect), firstRefreshTokenJti)
	if err != nil {
		return false, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	if rows.Next() {
		var found string
		if err := rows.Scan(&found); err != nil {
			return false, errs.Wrap(err, "unable to scan refresh token family revocation")
		}
		return !engineFoldedTheMatch(found, firstRefreshTokenJti), nil
	}
	if err := rows.Err(); err != nil {
		return false, errs.Wrap(err, "unable to read query results")
	}

	return false, nil
}

// IsRefreshTokenFamilyLive reports whether the family stands for a live grant, which is what an
// access token carrying grant_id lives by (#676 decision 1): it has no revocation record, and it
// still has a member that is not revoked. Every revocation that ends a grant writes the record, so
// a child a rotation inserts after the revocation's sweep read the family is refused with the rest,
// and a rotation keeps the grant live because it revokes the parent and inserts the child in one
// transaction. A family with no member left, one
// whose rows retention or a cascade removed, is no live grant.
//
// One statement answers both halves, each with the identifier it matched, and each is compared with
// the identifier asked for in Go, for the reason IsRefreshTokenFamilyRevoked states (#283). A match
// of another spelling is no match: a record of another spelling refuses nothing here, and a live
// member of another spelling is not this family's, so it answers not live.
//
// An error and false are different answers, as for IsRefreshTokenFamilyRevoked: false refuses the
// token as a dead grant, and an error says the lookup could not be performed.
func (d *Database) IsRefreshTokenFamilyLive(ctx context.Context, tx *sql.Tx, firstRefreshTokenJti string) (bool, error) {

	if firstRefreshTokenJti == "" {
		return false, errs.New("can't look up a refresh token family with an empty first refresh token jti")
	}

	rows, err := d.QuerySQL(ctx, tx, selectRefreshTokenFamilyLiveness.text(d.Dialect),
		firstRefreshTokenJti, firstRefreshTokenJti, false)
	if err != nil {
		return false, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return false, errs.Wrap(err, "unable to read query results")
		}
		return false, errs.New("the refresh token family liveness query returned no row")
	}
	var recorded, liveMember sql.NullString
	if err := rows.Scan(&recorded, &liveMember); err != nil {
		return false, errs.Wrap(err, "unable to scan refresh token family liveness")
	}
	if recorded.Valid && !engineFoldedTheMatch(recorded.String, firstRefreshTokenJti) {
		return false, nil
	}
	return liveMember.Valid && !engineFoldedTheMatch(liveMember.String, firstRefreshTokenJti), nil
}

// DeleteOrphanedRefreshTokenFamilyRevocations removes the records of families with no refresh
// token left. A family's tokens are reaped by DeleteExpiredRefreshTokens as they expire, and a
// record with no member has nothing to refuse: a token needs a parent row to be rotated from, and
// the last member is gone. A family with any member, live or revoked, keeps its record, so the
// sweep can never remove the record of a family a rotation in flight still holds the parent of.
func (d *Database) DeleteOrphanedRefreshTokenFamilyRevocations(ctx context.Context, tx *sql.Tx) error {

	_, err := d.ExecSQL(ctx, tx, deleteOrphanedRefreshTokenFamilyRevocations.text(d.Dialect))
	if err != nil {
		return errs.Wrap(err, "unable to delete orphaned refresh token family revocations")
	}

	return nil
}
