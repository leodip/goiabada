package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// The type and algorithm columns are reserved words on some engine, so every statement quotes
// them, with backticks on MySQL and double quotes on the other three.

// keyPairColumns is the key_pairs table as scanKeyPair reads it.
var keyPairColumns = columnList{
	sqlite: `id, created_at, updated_at, state, key_identifier, "type", "algorithm", private_key_pem, ` +
		"public_key_pem, public_key_asn1_der, public_key_jwk",
	mysql: "id, created_at, updated_at, state, key_identifier, `type`, `algorithm`, private_key_pem, " +
		"public_key_pem, public_key_asn1_der, public_key_jwk",
	postgres: `id, created_at, updated_at, state, key_identifier, "type", "algorithm", private_key_pem, ` +
		"public_key_pem, public_key_asn1_der, public_key_jwk",
	mssql: `id, created_at, updated_at, state, key_identifier, "type", "algorithm", private_key_pem, ` +
		"public_key_pem, public_key_asn1_der, public_key_jwk",
}

// scanKeyPair reads one row selected with keyPairColumns.
func scanKeyPair(row rowScanner, keyPair *record.KeyPair) error {
	return row.Scan(
		&keyPair.Id,
		&keyPair.CreatedAt,
		&keyPair.UpdatedAt,
		&keyPair.State,
		&keyPair.KeyIdentifier,
		&keyPair.Type,
		&keyPair.Algorithm,
		&keyPair.PrivateKeyPEM,
		&keyPair.PublicKeyPEM,
		&keyPair.PublicKeyASN1_DER,
		&keyPair.PublicKeyJWK,
	)
}

var insertKeyPair = statement{
	sqlite: `INSERT INTO key_pairs (created_at, updated_at, state, key_identifier, "type", "algorithm", ` +
		"private_key_pem, public_key_pem, public_key_asn1_der, public_key_jwk) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
	mysql: "INSERT INTO key_pairs (created_at, updated_at, state, key_identifier, `type`, `algorithm`, " +
		"private_key_pem, public_key_pem, public_key_asn1_der, public_key_jwk) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
	postgres: `INSERT INTO key_pairs (created_at, updated_at, state, key_identifier, "type", "algorithm", ` +
		"private_key_pem, public_key_pem, public_key_asn1_der, public_key_jwk) VALUES ($1, $2, $3, $4, " +
		"$5, $6, $7, $8, $9, $10) RETURNING id",
	mssql: `INSERT INTO key_pairs (created_at, updated_at, state, key_identifier, "type", "algorithm", ` +
		"private_key_pem, public_key_pem, public_key_asn1_der, " +
		"public_key_jwk) OUTPUT INSERTED.id VALUES (@p1, @p2, @p3, @p4, @p5, @p6, @p7, @p8, @p9, @p10)",
}

// updateKeyPair writes the whole row but created_at, which is dont-update.
var updateKeyPair = statement{
	sqlite: `UPDATE key_pairs SET updated_at = ?, state = ?, key_identifier = ?, "type" = ?, ` +
		`"algorithm" = ?, private_key_pem = ?, public_key_pem = ?, public_key_asn1_der = ?, ` +
		"public_key_jwk = ? WHERE id = ?",
	mysql: "UPDATE key_pairs SET updated_at = ?, state = ?, key_identifier = ?, `type` = ?, " +
		"`algorithm` = ?, private_key_pem = ?, public_key_pem = ?, public_key_asn1_der = ?, " +
		"public_key_jwk = ? WHERE id = ?",
	postgres: `UPDATE key_pairs SET updated_at = $1, state = $2, key_identifier = $3, "type" = $4, ` +
		`"algorithm" = $5, private_key_pem = $6, public_key_pem = $7, public_key_asn1_der = $8, ` +
		"public_key_jwk = $9 WHERE id = $10",
	mssql: `UPDATE key_pairs SET updated_at = @p1, state = @p2, key_identifier = @p3, "type" = @p4, ` +
		`"algorithm" = @p5, private_key_pem = @p6, public_key_pem = @p7, public_key_asn1_der = @p8, ` +
		"public_key_jwk = @p9 WHERE id = @p10",
}

// updateKeyPairState binds the new state and the clock, then the key's id and the state the
// caller read.
var updateKeyPairState = statement{
	sqlite:   "UPDATE key_pairs SET state = ?, updated_at = ? WHERE id = ? AND state = ?",
	mysql:    "UPDATE key_pairs SET state = ?, updated_at = ? WHERE id = ? AND state = ?",
	postgres: "UPDATE key_pairs SET state = $1, updated_at = $2 WHERE id = $3 AND state = $4",
	mssql:    "UPDATE key_pairs SET state = @p1, updated_at = @p2 WHERE id = @p3 AND state = @p4",
}

var selectKeyPairById = statement{
	sqlite:   "SELECT " + keyPairColumns.sqlite + " FROM key_pairs WHERE id = ?",
	mysql:    "SELECT " + keyPairColumns.mysql + " FROM key_pairs WHERE id = ?",
	postgres: "SELECT " + keyPairColumns.postgres + " FROM key_pairs WHERE id = $1",
	mssql:    "SELECT " + keyPairColumns.mssql + " FROM key_pairs WHERE id = @p1",
}

var selectAllKeyPairs = statement{
	sqlite:   "SELECT " + keyPairColumns.sqlite + " FROM key_pairs",
	mysql:    "SELECT " + keyPairColumns.mysql + " FROM key_pairs",
	postgres: "SELECT " + keyPairColumns.postgres + " FROM key_pairs",
	mssql:    "SELECT " + keyPairColumns.mssql + " FROM key_pairs",
}

var selectKeyPairsByState = statement{
	sqlite:   "SELECT " + keyPairColumns.sqlite + " FROM key_pairs WHERE state = ?",
	mysql:    "SELECT " + keyPairColumns.mysql + " FROM key_pairs WHERE state = ?",
	postgres: "SELECT " + keyPairColumns.postgres + " FROM key_pairs WHERE state = $1",
	mssql:    "SELECT " + keyPairColumns.mssql + " FROM key_pairs WHERE state = @p1",
}

var deleteKeyPair = statement{
	sqlite:   "DELETE FROM key_pairs WHERE id = ?",
	mysql:    "DELETE FROM key_pairs WHERE id = ?",
	postgres: "DELETE FROM key_pairs WHERE id = $1",
	mssql:    "DELETE FROM key_pairs WHERE id = @p1",
}

func (d *Database) CreateKeyPair(ctx context.Context, tx *sql.Tx, keyPair *record.KeyPair) error {

	now := time.Now().UTC()

	originalCreatedAt := keyPair.CreatedAt
	originalUpdatedAt := keyPair.UpdatedAt
	keyPair.CreatedAt = sql.NullTime{Time: now, Valid: true}
	keyPair.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	id, err := d.insert(ctx, tx, insertKeyPair, "keyPair",
		keyPair.CreatedAt, keyPair.UpdatedAt, keyPair.State, keyPair.KeyIdentifier, keyPair.Type,
		keyPair.Algorithm, keyPair.PrivateKeyPEM, keyPair.PublicKeyPEM, keyPair.PublicKeyASN1_DER,
		keyPair.PublicKeyJWK)
	if err != nil {
		keyPair.CreatedAt = originalCreatedAt
		keyPair.UpdatedAt = originalUpdatedAt
		return err
	}

	keyPair.Id = id
	return nil
}

func (d *Database) UpdateKeyPair(ctx context.Context, tx *sql.Tx, keyPair *record.KeyPair) error {

	if keyPair.Id == 0 {
		return errs.New("can't update keyPair with id 0")
	}

	originalUpdatedAt := keyPair.UpdatedAt
	keyPair.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	_, err := d.ExecSQL(ctx, tx, updateKeyPair.text(d.Dialect),
		keyPair.UpdatedAt, keyPair.State, keyPair.KeyIdentifier, keyPair.Type, keyPair.Algorithm,
		keyPair.PrivateKeyPEM, keyPair.PublicKeyPEM, keyPair.PublicKeyASN1_DER, keyPair.PublicKeyJWK,
		keyPair.Id)
	if err != nil {
		keyPair.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to update keyPair")
	}

	return nil
}

// UpdateKeyPairState moves one key from fromState to toState, and reports whether this call
// is the one that made the transition. The state predicate is what makes it a compare-and-set:
// without it two concurrent rotations both write the snapshot they read, and the loser deletes
// the previous key the winner had just demoted, retiring every token that key signed (#251).
func (d *Database) UpdateKeyPairState(ctx context.Context, tx *sql.Tx, keyPairId int64, fromState string,
	toState string) (bool, error) {

	if keyPairId == 0 {
		return false, errs.New("can't update the state of a keyPair with id 0")
	}

	result, err := d.ExecSQL(ctx, tx, updateKeyPairState.text(d.Dialect), toState, time.Now().UTC(), keyPairId, fromState)
	if err != nil {
		return false, errs.Wrap(err, "unable to update keyPair state")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errs.Wrap(err, "unable to get rows affected when updating keyPair state")
	}

	return rowsAffected == 1, nil
}

func (d *Database) GetKeyPairById(ctx context.Context, tx *sql.Tx, keyPairId int64) (*record.KeyPair, error) {
	return queryOne(ctx, d, tx, selectKeyPairById.text(d.Dialect), []any{keyPairId}, scanKeyPair, "keyPair")
}

func (d *Database) GetAllSigningKeys(ctx context.Context, tx *sql.Tx) ([]record.KeyPair, error) {
	return queryAll(ctx, d, tx, nil, selectAllKeyPairs.text(d.Dialect), nil, scanKeyPair, "keyPair")
}

// GetCurrentSigningKey returns an error when no key is in the current state, departing from
// the (nil, nil) this package returns for a lookup that may legitimately miss. Every caller
// dereferences the result to read key material, so a nil pair is a panic rather than a
// diagnosable failure, and a deployment with no current key cannot validate the bearer token
// needed to repair itself. Returning the error here is what makes all of those sites correct
// at once, including ones added later (#251).
func (d *Database) GetCurrentSigningKey(ctx context.Context, tx *sql.Tx) (*record.KeyPair, error) {
	keyPair, err := queryOne(ctx, d, tx, selectKeyPairsByState.text(d.Dialect), []any{record.KeyStateCurrent.String()},
		scanKeyPair, "keyPair")
	if err != nil {
		return nil, err
	}

	if keyPair == nil {
		return nil, errs.New("no current signing key found")
	}

	return keyPair, nil
}

func (d *Database) DeleteKeyPair(ctx context.Context, tx *sql.Tx, keyPairId int64) error {

	_, err := d.ExecSQL(ctx, tx, deleteKeyPair.text(d.Dialect), keyPairId)
	if err != nil {
		return errs.Wrap(err, "unable to delete keyPair")
	}

	return nil
}
