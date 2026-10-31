package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/core/errs"
)

// A user's recovery codes (#257 decisions 2 and 3): one row per code of the user's current set,
// holding the code's SHA-256 in lowercase hex, never the code. A row is inserted with its set and
// deleted with it; the one write between is stamping used_at, once. There is no record type: no
// caller reads a row back, only whether a code was claimed and how many are left.

var deleteUserRecoveryCodes = statement{
	sqlite:   "DELETE FROM user_recovery_codes WHERE user_id = ?",
	mysql:    "DELETE FROM user_recovery_codes WHERE user_id = ?",
	postgres: "DELETE FROM user_recovery_codes WHERE user_id = $1",
	mssql:    "DELETE FROM user_recovery_codes WHERE user_id = @p1",
}

var insertUserRecoveryCode = statement{
	sqlite:   "INSERT INTO user_recovery_codes (user_id, code_hash, created_at) VALUES (?, ?, ?)",
	mysql:    "INSERT INTO user_recovery_codes (user_id, code_hash, created_at) VALUES (?, ?, ?)",
	postgres: "INSERT INTO user_recovery_codes (user_id, code_hash, created_at) VALUES ($1, $2, $3)",
	mssql:    "INSERT INTO user_recovery_codes (user_id, code_hash, created_at) VALUES (@p1, @p2, @p3)",
}

// tryUseUserRecoveryCode is TryUseUserRecoveryCode's claim: used_at IS NULL in the predicate is
// what makes it once.
var tryUseUserRecoveryCode = statement{
	sqlite:   "UPDATE user_recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL",
	mysql:    "UPDATE user_recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL",
	postgres: "UPDATE user_recovery_codes SET used_at = $1 WHERE user_id = $2 AND code_hash = $3 AND used_at IS NULL",
	mssql:    "UPDATE user_recovery_codes SET used_at = @p1 WHERE user_id = @p2 AND code_hash = @p3 AND used_at IS NULL",
}

var countUnusedUserRecoveryCodes = statement{
	sqlite:   "SELECT COUNT(*) FROM user_recovery_codes WHERE user_id = ? AND used_at IS NULL",
	mysql:    "SELECT COUNT(*) FROM user_recovery_codes WHERE user_id = ? AND used_at IS NULL",
	postgres: "SELECT COUNT(*) FROM user_recovery_codes WHERE user_id = $1 AND used_at IS NULL",
	mssql:    "SELECT COUNT(*) FROM user_recovery_codes WHERE user_id = @p1 AND used_at IS NULL",
}

// ReplaceUserRecoveryCodes deletes the user's set, used codes and unused alike, and inserts one
// unused row per hash. The transaction is required rather than optional: autocommitted, a failure
// between the deletion and the last insert would leave the user with part of a set, or none, and a
// set is shown once. An empty hash is refused before anything is written, since it can only be a
// caller that hashed nothing, and a row holding it would be claimed by one.
func (d *Database) ReplaceUserRecoveryCodes(ctx context.Context, tx *sql.Tx, userId int64, codeHashes []string) error {

	if tx == nil {
		return errs.New("replacing a user's recovery codes requires a transaction: autocommitted, a failure part way through leaves part of a set")
	}

	if userId == 0 {
		return errs.New("can't replace the recovery codes of a user with id 0")
	}

	for _, codeHash := range codeHashes {
		if codeHash == "" {
			return errs.New("can't store a recovery code with an empty hash")
		}
	}

	if err := d.DeleteUserRecoveryCodes(ctx, tx, userId); err != nil {
		return err
	}

	createdAt := time.Now().UTC()
	for _, codeHash := range codeHashes {
		if _, err := d.ExecSQL(ctx, tx, insertUserRecoveryCode.text(d.Dialect), userId, codeHash, createdAt); err != nil {
			return errs.Wrap(err, "unable to insert a recovery code")
		}
	}

	return nil
}

// DeleteUserRecoveryCodes deletes every code the user has. A user with none is no error.
func (d *Database) DeleteUserRecoveryCodes(ctx context.Context, tx *sql.Tx, userId int64) error {

	if _, err := d.ExecSQL(ctx, tx, deleteUserRecoveryCodes.text(d.Dialect), userId); err != nil {
		return errs.Wrap(err, "unable to delete the user's recovery codes")
	}

	return nil
}

// TryUseUserRecoveryCode stamps used_at on the user's unused code with this hash, and reports
// whether this call did. Compare-and-set for the reason TryConsumeUserOTPStep is: a read and then an
// unconditional write lets two submissions of one code both pass.
//
// rowsAffected == 1 means this call transitioned the row on all four engines: the predicate requires
// used_at to be NULL and the SET writes a time, so the row always changes and MySQL's changed-rows
// accounting agrees with matched rows. The unique index on the pair means at most one row matches.
//
// An empty hash or a zero user id is an error rather than a benign false, as for
// TryConsumeForgotPasswordCode: either can only be a caller bug.
func (d *Database) TryUseUserRecoveryCode(ctx context.Context, tx *sql.Tx, userId int64, codeHash string) (bool, error) {

	if userId == 0 {
		return false, errs.New("can't use a recovery code of a user with id 0")
	}
	if codeHash == "" {
		return false, errs.New("can't use a recovery code with an empty hash")
	}

	result, err := d.ExecSQL(ctx, tx, tryUseUserRecoveryCode.text(d.Dialect), time.Now().UTC(), userId, codeHash)
	if err != nil {
		return false, errs.Wrap(err, "unable to use a recovery code")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errs.Wrap(err, "unable to get rows affected when using a recovery code")
	}

	return rowsAffected == 1, nil
}

// CountUnusedUserRecoveryCodes is how many of the user's codes have no used_at.
func (d *Database) CountUnusedUserRecoveryCodes(ctx context.Context, tx *sql.Tx, userId int64) (int, error) {

	count, err := queryOne(ctx, d, tx, countUnusedUserRecoveryCodes.text(d.Dialect), []any{userId},
		func(row rowScanner, n *int) error { return row.Scan(n) }, "recovery code count")
	if err != nil {
		return 0, err
	}
	if count == nil {
		return 0, errs.New("the recovery code count returned no row")
	}

	return *count, nil
}
