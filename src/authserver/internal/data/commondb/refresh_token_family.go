package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/errs"
)

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
func (d *CommonDatabase) RecordRefreshTokenFamilyRevoked(ctx context.Context, tx *sql.Tx, firstRefreshTokenJti string,
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

	revocation := &models.RefreshTokenFamilyRevocation{
		FirstRefreshTokenJti: firstRefreshTokenJti,
		Reason:               reason,
		RevokedAt:            time.Now().UTC(),
	}
	insertBuilder := sqlbuilder.NewStruct(new(models.RefreshTokenFamilyRevocation)).
		For(d.Flavor).
		InsertInto("refresh_token_family_revocations", revocation)

	query, args := insertBuilder.Build()
	_, err = d.ExecSql(ctx, tx, query, args...)
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
func (d *CommonDatabase) IsRefreshTokenFamilyRevoked(ctx context.Context, tx *sql.Tx, firstRefreshTokenJti string) (bool, error) {

	if firstRefreshTokenJti == "" {
		return false, errs.New("can't look up a refresh token family with an empty first refresh token jti")
	}

	selectBuilder := d.Flavor.NewSelectBuilder()
	selectBuilder.Select("first_refresh_token_jti").From("refresh_token_family_revocations")
	selectBuilder.Where(selectBuilder.Equal("first_refresh_token_jti", firstRefreshTokenJti))

	query, args := selectBuilder.BuildWithFlavor(d.Flavor)
	rows, err := d.QuerySql(ctx, tx, query, args...)
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

// DeleteOrphanedRefreshTokenFamilyRevocations removes the records of families with no refresh
// token left. A family's tokens are reaped by DeleteExpiredRefreshTokens as they expire, and a
// record with no member has nothing to refuse: a token needs a parent row to be rotated from, and
// the last member is gone. A family with any member, live or revoked, keeps its record, so the
// sweep can never remove the record of a family a rotation in flight still holds the parent of.
func (d *CommonDatabase) DeleteOrphanedRefreshTokenFamilyRevocations(ctx context.Context, tx *sql.Tx) error {

	members := d.Flavor.NewSelectBuilder()
	members.Select("1").From("refresh_tokens")
	members.Where("refresh_tokens.first_refresh_token_jti = refresh_token_family_revocations.first_refresh_token_jti")

	deleteBuilder := d.Flavor.NewDeleteBuilder()
	deleteBuilder.DeleteFrom("refresh_token_family_revocations")
	deleteBuilder.Where(deleteBuilder.NotExists(members))

	query, args := deleteBuilder.BuildWithFlavor(d.Flavor)
	_, err := d.ExecSql(ctx, tx, query, args...)
	if err != nil {
		return errs.Wrap(err, "unable to delete orphaned refresh token family revocations")
	}

	return nil
}
