package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// preRegistrationColumns is the pre_registrations table as scanPreRegistration reads it.
var preRegistrationColumns = columnList{
	sqlite: "id, created_at, updated_at, email, verification_code_encrypted, verification_code_issued_at, " +
		"verification_code_hash",
	mysql: "id, created_at, updated_at, email, verification_code_encrypted, verification_code_issued_at, " +
		"verification_code_hash",
	postgres: "id, created_at, updated_at, email, verification_code_encrypted, verification_code_issued_at, " +
		"verification_code_hash",
	mssql: "id, created_at, updated_at, email, verification_code_encrypted, verification_code_issued_at, " +
		"verification_code_hash",
}

// scanPreRegistration reads one row selected with preRegistrationColumns.
func scanPreRegistration(row rowScanner, preRegistration *record.PreRegistration) error {
	return row.Scan(
		&preRegistration.Id,
		&preRegistration.CreatedAt,
		&preRegistration.UpdatedAt,
		&preRegistration.Email,
		&preRegistration.VerificationCodeEncrypted,
		&preRegistration.VerificationCodeIssuedAt,
		&preRegistration.VerificationCodeHash,
	)
}

var insertPreRegistration = statement{
	sqlite: "INSERT INTO pre_registrations (created_at, updated_at, email, verification_code_encrypted, " +
		"verification_code_issued_at, verification_code_hash) VALUES (?, ?, ?, ?, ?, ?)",
	mysql: "INSERT INTO pre_registrations (created_at, updated_at, email, verification_code_encrypted, " +
		"verification_code_issued_at, verification_code_hash) VALUES (?, ?, ?, ?, ?, ?)",
	postgres: "INSERT INTO pre_registrations (created_at, updated_at, email, verification_code_encrypted, " +
		"verification_code_issued_at, verification_code_hash) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
	mssql: "INSERT INTO pre_registrations (created_at, updated_at, email, verification_code_encrypted, " +
		"verification_code_issued_at, verification_code_hash) OUTPUT INSERTED.id VALUES (@p1, @p2, @p3, @p4, @p5, @p6)",
}

// updatePreRegistration writes the whole row but created_at, which is dont-update.
var updatePreRegistration = statement{
	sqlite: "UPDATE pre_registrations SET updated_at = ?, email = ?, verification_code_encrypted = ?, " +
		"verification_code_issued_at = ?, verification_code_hash = ? WHERE id = ?",
	mysql: "UPDATE pre_registrations SET updated_at = ?, email = ?, verification_code_encrypted = ?, " +
		"verification_code_issued_at = ?, verification_code_hash = ? WHERE id = ?",
	postgres: "UPDATE pre_registrations SET updated_at = $1, email = $2, verification_code_encrypted = $3, " +
		"verification_code_issued_at = $4, verification_code_hash = $5 WHERE id = $6",
	mssql: "UPDATE pre_registrations SET updated_at = @p1, email = @p2, verification_code_encrypted = @p3, " +
		"verification_code_issued_at = @p4, verification_code_hash = @p5 WHERE id = @p6",
}

var selectPreRegistrationById = statement{
	sqlite:   "SELECT " + preRegistrationColumns.sqlite + " FROM pre_registrations WHERE id = ?",
	mysql:    "SELECT " + preRegistrationColumns.mysql + " FROM pre_registrations WHERE id = ?",
	postgres: "SELECT " + preRegistrationColumns.postgres + " FROM pre_registrations WHERE id = $1",
	mssql:    "SELECT " + preRegistrationColumns.mssql + " FROM pre_registrations WHERE id = @p1",
}

var selectPreRegistrationByVerificationCodeHash = statement{
	sqlite:   "SELECT " + preRegistrationColumns.sqlite + " FROM pre_registrations WHERE verification_code_hash = ?",
	mysql:    "SELECT " + preRegistrationColumns.mysql + " FROM pre_registrations WHERE verification_code_hash = ?",
	postgres: "SELECT " + preRegistrationColumns.postgres + " FROM pre_registrations WHERE verification_code_hash = $1",
	mssql:    "SELECT " + preRegistrationColumns.mssql + " FROM pre_registrations WHERE verification_code_hash = @p1",
}

var selectPreRegistrationByEmail = statement{
	sqlite:   "SELECT " + preRegistrationColumns.sqlite + " FROM pre_registrations WHERE email = ?",
	mysql:    "SELECT " + preRegistrationColumns.mysql + " FROM pre_registrations WHERE email = ?",
	postgres: "SELECT " + preRegistrationColumns.postgres + " FROM pre_registrations WHERE email = $1",
	mssql:    "SELECT " + preRegistrationColumns.mssql + " FROM pre_registrations WHERE email = @p1",
}

var deletePreRegistration = statement{
	sqlite:   "DELETE FROM pre_registrations WHERE id = ?",
	mysql:    "DELETE FROM pre_registrations WHERE id = ?",
	postgres: "DELETE FROM pre_registrations WHERE id = $1",
	mssql:    "DELETE FROM pre_registrations WHERE id = @p1",
}

var deletePreRegistrationHoldingCode = statement{
	sqlite:   "DELETE FROM pre_registrations WHERE id = ? AND verification_code_hash = ?",
	mysql:    "DELETE FROM pre_registrations WHERE id = ? AND verification_code_hash = ?",
	postgres: "DELETE FROM pre_registrations WHERE id = $1 AND verification_code_hash = $2",
	mssql:    "DELETE FROM pre_registrations WHERE id = @p1 AND verification_code_hash = @p2",
}

var deleteDeadPreRegistrations = statement{
	sqlite:   "DELETE FROM pre_registrations WHERE (verification_code_issued_at < ? OR verification_code_issued_at IS NULL)",
	mysql:    "DELETE FROM pre_registrations WHERE (verification_code_issued_at < ? OR verification_code_issued_at IS NULL)",
	postgres: "DELETE FROM pre_registrations WHERE (verification_code_issued_at < $1 OR verification_code_issued_at IS NULL)",
	mssql:    "DELETE FROM pre_registrations WHERE (verification_code_issued_at < @p1 OR verification_code_issued_at IS NULL)",
}

// replacePreRegistrationCode binds the fresh code, its hash, its issued-at and the clock, then the
// row's id and the dead code's hash the caller read.
var replacePreRegistrationCode = statement{
	sqlite: "UPDATE pre_registrations SET verification_code_encrypted = ?, verification_code_hash = ?, " +
		"verification_code_issued_at = ?, updated_at = ? WHERE id = ? AND verification_code_hash = ?",
	mysql: "UPDATE pre_registrations SET verification_code_encrypted = ?, verification_code_hash = ?, " +
		"verification_code_issued_at = ?, updated_at = ? WHERE id = ? AND verification_code_hash = ?",
	postgres: "UPDATE pre_registrations SET verification_code_encrypted = $1, verification_code_hash = $2, " +
		"verification_code_issued_at = $3, updated_at = $4 WHERE id = $5 AND verification_code_hash = $6",
	mssql: "UPDATE pre_registrations SET verification_code_encrypted = @p1, verification_code_hash = @p2, " +
		"verification_code_issued_at = @p3, updated_at = @p4 WHERE id = @p5 AND verification_code_hash = @p6",
}

func (d *Database) CreatePreRegistration(ctx context.Context, tx *sql.Tx, preRegistration *record.PreRegistration) error {

	now := time.Now().UTC()

	originalCreatedAt := preRegistration.CreatedAt
	originalUpdatedAt := preRegistration.UpdatedAt
	preRegistration.CreatedAt = sql.NullTime{Time: now, Valid: true}
	preRegistration.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	id, err := d.insert(ctx, tx, insertPreRegistration, "preRegistration",
		preRegistration.CreatedAt, preRegistration.UpdatedAt, preRegistration.Email,
		preRegistration.VerificationCodeEncrypted, preRegistration.VerificationCodeIssuedAt,
		preRegistration.VerificationCodeHash)
	if err != nil {
		preRegistration.CreatedAt = originalCreatedAt
		preRegistration.UpdatedAt = originalUpdatedAt
		return err
	}

	preRegistration.Id = id
	return nil
}

func (d *Database) UpdatePreRegistration(ctx context.Context, tx *sql.Tx, preRegistration *record.PreRegistration) error {

	if preRegistration.Id == 0 {
		return errs.New("can't update preRegistration with id 0")
	}

	originalUpdatedAt := preRegistration.UpdatedAt
	preRegistration.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	_, err := d.ExecSQL(ctx, tx, updatePreRegistration.text(d.Dialect),
		preRegistration.UpdatedAt, preRegistration.Email, preRegistration.VerificationCodeEncrypted,
		preRegistration.VerificationCodeIssuedAt, preRegistration.VerificationCodeHash, preRegistration.Id)
	if err != nil {
		preRegistration.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to update preRegistration")
	}

	return nil
}

func (d *Database) GetPreRegistrationById(ctx context.Context, tx *sql.Tx, preRegistrationId int64) (*record.PreRegistration, error) {
	return queryOne(ctx, d, tx, selectPreRegistrationById.text(d.Dialect), []any{preRegistrationId},
		scanPreRegistration, "preRegistration")
}

func (d *Database) DeletePreRegistration(ctx context.Context, tx *sql.Tx, preRegistrationId int64) error {

	_, err := d.ExecSQL(ctx, tx, deletePreRegistration.text(d.Dialect), preRegistrationId)
	if err != nil {
		return errs.Wrap(err, "unable to delete preRegistration")
	}

	return nil
}

// DeletePreRegistrationHoldingCode deletes a pending registration only while it still holds
// codeHash, the code the caller read and decided on, and reports whether this call deleted it.
//
// It is DeletePreRegistration fenced the way TryReplacePreRegistrationCode is: a replacement keeps
// the row's id and gives it a fresh code, so a caller that read the row before the replacement
// and deletes by id alone would delete the fresh link with it. Naming the code the caller read
// makes that caller's delete decline instead, as it does for a row consumed or swept meanwhile
// (#207 decision 6).
func (d *Database) DeletePreRegistrationHoldingCode(ctx context.Context, tx *sql.Tx, preRegistrationId int64,
	codeHash string) (bool, error) {

	// '' is the dormant value, which would match a row nobody issued a code for.
	if codeHash == "" {
		return false, errs.New("can't delete a preRegistration by an empty code hash")
	}

	result, err := d.ExecSQL(ctx, tx, deletePreRegistrationHoldingCode.text(d.Dialect), preRegistrationId, codeHash)
	if err != nil {
		return false, errs.Wrap(err, "unable to delete preRegistration")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errs.Wrap(err, "unable to get rows affected when deleting preRegistration")
	}

	return rowsAffected == 1, nil
}

// DeleteDeadPreRegistrations sweeps the pending registrations that can no longer complete: every
// row whose code was issued before deadBefore, and every row with no issued-at, which no link can
// activate. A row issued exactly at deadBefore is kept, as emaillinks.IsPreRegistrationDead keeps
// it; the next sweep has it (#207 decision 7).
func (d *Database) DeleteDeadPreRegistrations(ctx context.Context, tx *sql.Tx, deadBefore time.Time) error {

	_, err := d.ExecSQL(ctx, tx, deleteDeadPreRegistrations.text(d.Dialect), deadBefore)
	if err != nil {
		return errs.Wrap(err, "unable to delete dead preRegistrations")
	}

	return nil
}

// GetPreRegistrationByVerificationCodeHash finds the pre-registration an activation code
// belongs to, by an unsalted SHA-256 of that code. It is what lets the activation link
// carry the code and nothing else, so no email address travels in it and no part of the
// link ever needs percent-encoding (#112).
//
// Locating the row is not authenticating it. The caller still compares the submitted code
// against the encrypted column and checks the code's expiry.
func (d *Database) GetPreRegistrationByVerificationCodeHash(ctx context.Context, tx *sql.Tx, codeHash string) (*record.PreRegistration, error) {

	// As on the user lookup: '' is the dormant value, so an empty codeHash reaching the
	// query could match a row nobody supplied a code for.
	if codeHash == "" {
		return nil, nil
	}

	return queryOne(ctx, d, tx, selectPreRegistrationByVerificationCodeHash.text(d.Dialect), []any{codeHash},
		scanPreRegistration, "preRegistration")
}

// TryReplacePreRegistrationCode gives a dead pending registration a fresh code in one
// conditional UPDATE, taking effect only while the row still holds deadCodeHash, the code the
// caller read and judged dead, and reports whether this call is the one that wrote it.
//
// The condition is the code and not the issued-at: a row still holding the code the caller read
// is still the row the caller judged, and time only moves on, so it is still dead. A repeat that
// lost the race to another names a code the row no longer holds, and so does a caller whose row
// was consumed or swept meanwhile, and each is told false and sends nothing (#207 decision 6).
// The row keeps its id, its address and its created_at, so it is the same pending registration
// with a new link.
func (d *Database) TryReplacePreRegistrationCode(ctx context.Context, tx *sql.Tx, preRegistrationId int64,
	deadCodeHash string, codeEncrypted []byte, codeHash string, issuedAt time.Time) (bool, error) {

	if preRegistrationId == 0 {
		return false, errs.New("can't replace the code of preRegistration with id 0")
	}
	// '' is the dormant value, which no link can find, so a code stored with it could never be
	// activated; and a dead code of '' would match a row nobody issued a code for.
	if codeHash == "" || deadCodeHash == "" {
		return false, errs.New("can't replace a preRegistration code with an empty code hash")
	}

	result, err := d.ExecSQL(ctx, tx, replacePreRegistrationCode.text(d.Dialect),
		codeEncrypted, codeHash, issuedAt, time.Now().UTC(), preRegistrationId, deadCodeHash)
	if err != nil {
		return false, errs.Wrap(err, "unable to replace preRegistration code")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errs.Wrap(err, "unable to get rows affected when replacing preRegistration code")
	}

	// rowsAffected == 1 means the row was replaced on all four engines: the fresh code's hash
	// always differs from the dead one the row matched on, so the row always changes and MySQL's
	// changed-rows accounting agrees with matched rows.
	return rowsAffected == 1, nil
}

func (d *Database) GetPreRegistrationByEmail(ctx context.Context, tx *sql.Tx, email string) (*record.PreRegistration, error) {

	return queryOne(ctx, d, tx, selectPreRegistrationByEmail.text(d.Dialect), []any{email},
		scanPreRegistration, "preRegistration")
}
