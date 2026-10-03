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
