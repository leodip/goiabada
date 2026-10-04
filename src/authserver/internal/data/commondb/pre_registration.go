package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

func (d *Database) CreatePreRegistration(ctx context.Context, tx *sql.Tx, preRegistration *record.PreRegistration) error {

	now := time.Now().UTC()

	originalCreatedAt := preRegistration.CreatedAt
	originalUpdatedAt := preRegistration.UpdatedAt
	preRegistration.CreatedAt = sql.NullTime{Time: now, Valid: true}
	preRegistration.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	preRegistrationStruct := sqlbuilder.NewStruct(new(record.PreRegistration)).
		For(d.Flavor)

	insertBuilder := preRegistrationStruct.WithoutTag("pk").InsertInto("pre_registrations", preRegistration)

	id, err := d.insertReturningId(ctx, tx, insertBuilder, "preRegistration")
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

	preRegistrationStruct := sqlbuilder.NewStruct(new(record.PreRegistration)).
		For(d.Flavor)

	updateBuilder := preRegistrationStruct.WithoutTag("pk").WithoutTag("dont-update").Update("pre_registrations", preRegistration)
	updateBuilder.Where(updateBuilder.Equal("id", preRegistration.Id))

	sql, args := updateBuilder.Build()
	_, err := d.ExecSQL(ctx, tx, sql, args...)
	if err != nil {
		preRegistration.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to update preRegistration")
	}

	return nil
}

func (d *Database) getPreRegistrationCommon(ctx context.Context, tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	preRegistrationStruct *sqlbuilder.Struct) (*record.PreRegistration, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySQL(ctx, tx, sql, args...)
	if err != nil {
		return nil, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var preRegistration record.PreRegistration
	if rows.Next() {
		addr := preRegistrationStruct.Addr(&preRegistration)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errs.Wrap(err, "unable to scan preRegistration")
		}
		return &preRegistration, nil
	}
	if err := rows.Err(); err != nil {
		return nil, errs.Wrap(err, "unable to read query results")
	}

	return nil, nil
}

func (d *Database) GetPreRegistrationById(ctx context.Context, tx *sql.Tx, preRegistrationId int64) (*record.PreRegistration, error) {

	preRegistrationStruct := sqlbuilder.NewStruct(new(record.PreRegistration)).
		For(d.Flavor)

	selectBuilder := preRegistrationStruct.SelectFrom("pre_registrations")
	selectBuilder.Where(selectBuilder.Equal("id", preRegistrationId))

	preRegistration, err := d.getPreRegistrationCommon(ctx, tx, selectBuilder, preRegistrationStruct)
	if err != nil {
		return nil, err
	}

	return preRegistration, nil
}

func (d *Database) DeletePreRegistration(ctx context.Context, tx *sql.Tx, preRegistrationId int64) error {

	clientStruct := sqlbuilder.NewStruct(new(record.PreRegistration)).
		For(d.Flavor)

	deleteBuilder := clientStruct.DeleteFrom("pre_registrations")
	deleteBuilder.Where(deleteBuilder.Equal("id", preRegistrationId))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSQL(ctx, tx, sql, args...)
	if err != nil {
		return errs.Wrap(err, "unable to delete preRegistration")
	}

	return nil
}

// DeleteDeadPreRegistrations sweeps the pending registrations that can no longer complete: every
// row whose code was issued before deadBefore, and every row with no issued-at, which no link can
// activate. A row issued exactly at deadBefore is kept, as emaillinks.IsPreRegistrationDead keeps
// it; the next sweep has it (#207 decision 7).
func (d *Database) DeleteDeadPreRegistrations(ctx context.Context, tx *sql.Tx, deadBefore time.Time) error {

	preRegistrationStruct := sqlbuilder.NewStruct(new(record.PreRegistration)).
		For(d.Flavor)

	deleteBuilder := preRegistrationStruct.DeleteFrom("pre_registrations")
	deleteBuilder.Where(deleteBuilder.Or(
		deleteBuilder.LessThan("verification_code_issued_at", deadBefore),
		deleteBuilder.IsNull("verification_code_issued_at"),
	))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSQL(ctx, tx, sql, args...)
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

	preRegistrationStruct := sqlbuilder.NewStruct(new(record.PreRegistration)).
		For(d.Flavor)

	selectBuilder := preRegistrationStruct.SelectFrom("pre_registrations")
	selectBuilder.Where(selectBuilder.Equal("verification_code_hash", codeHash))

	preRegistration, err := d.getPreRegistrationCommon(ctx, tx, selectBuilder, preRegistrationStruct)
	if err != nil {
		return nil, err
	}

	return preRegistration, nil
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

	ub := d.Flavor.NewUpdateBuilder()
	ub.Update("pre_registrations")
	ub.Set(
		ub.Assign("verification_code_encrypted", codeEncrypted),
		ub.Assign("verification_code_hash", codeHash),
		ub.Assign("verification_code_issued_at", issuedAt),
		ub.Assign("updated_at", time.Now().UTC()),
	)
	ub.Where(
		ub.Equal("id", preRegistrationId),
		ub.Equal("verification_code_hash", deadCodeHash),
	)

	query, args := ub.BuildWithFlavor(d.Flavor)
	result, err := d.ExecSQL(ctx, tx, query, args...)
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

	preRegistrationStruct := sqlbuilder.NewStruct(new(record.PreRegistration)).
		For(d.Flavor)

	selectBuilder := preRegistrationStruct.SelectFrom("pre_registrations")
	selectBuilder.Where(selectBuilder.Equal("email", email))

	preRegistration, err := d.getPreRegistrationCommon(ctx, tx, selectBuilder, preRegistrationStruct)
	if err != nil {
		return nil, err
	}

	return preRegistration, nil
}
