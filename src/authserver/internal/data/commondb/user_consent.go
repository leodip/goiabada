package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

func (d *Database) CreateUserConsent(ctx context.Context, tx *sql.Tx, userConsent *record.UserConsent) error {

	if userConsent.ClientId == 0 {
		return errs.New("client id must be greater than 0")
	}

	if userConsent.UserId == 0 {
		return errs.New("user id must be greater than 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := userConsent.CreatedAt
	originalUpdatedAt := userConsent.UpdatedAt
	userConsent.CreatedAt = sql.NullTime{Time: now, Valid: true}
	userConsent.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	userConsentStruct := sqlbuilder.NewStruct(new(record.UserConsent)).
		For(d.Flavor)

	insertBuilder := userConsentStruct.WithoutTag("pk").InsertInto("user_consents", userConsent)

	id, err := d.insertReturningId(ctx, tx, insertBuilder, "userConsent")
	if err != nil {
		userConsent.CreatedAt = originalCreatedAt
		userConsent.UpdatedAt = originalUpdatedAt
		return err
	}

	userConsent.Id = id
	return nil
}

func (d *Database) UpdateUserConsent(ctx context.Context, tx *sql.Tx, userConsent *record.UserConsent) error {

	if userConsent.Id == 0 {
		return errs.New("can't update userConsent with id 0")
	}

	originalUpdatedAt := userConsent.UpdatedAt
	userConsent.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	userConsentStruct := sqlbuilder.NewStruct(new(record.UserConsent)).
		For(d.Flavor)

	updateBuilder := userConsentStruct.WithoutTag("pk").WithoutTag("dont-update").Update("user_consents", userConsent)
	updateBuilder.Where(updateBuilder.Equal("id", userConsent.Id))

	sql, args := updateBuilder.Build()
	_, err := d.ExecSQL(ctx, tx, sql, args...)
	if err != nil {
		userConsent.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to update userConsent")
	}

	return nil
}

func (d *Database) getUserConsentCommon(ctx context.Context, tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	userConsentStruct *sqlbuilder.Struct) (*record.UserConsent, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySQL(ctx, tx, sql, args...)
	if err != nil {
		return nil, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var userConsent record.UserConsent
	if rows.Next() {
		addr := userConsentStruct.Addr(&userConsent)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errs.Wrap(err, "unable to scan userConsent")
		}
		return &userConsent, nil
	}
	if err := rows.Err(); err != nil {
		return nil, errs.Wrap(err, "unable to read query results")
	}

	return nil, nil
}

func (d *Database) GetUserConsentById(ctx context.Context, tx *sql.Tx, userConsentId int64) (*record.UserConsent, error) {

	userConsentStruct := sqlbuilder.NewStruct(new(record.UserConsent)).
		For(d.Flavor)

	selectBuilder := userConsentStruct.SelectFrom("user_consents")
	selectBuilder.Where(selectBuilder.Equal("id", userConsentId))

	userConsent, err := d.getUserConsentCommon(ctx, tx, selectBuilder, userConsentStruct)
	if err != nil {
		return nil, err
	}

	return userConsent, nil
}

func (d *Database) GetConsentByUserIdAndClientId(ctx context.Context, tx *sql.Tx, userId int64, clientId int64) (*record.UserConsent, error) {

	userConsentStruct := sqlbuilder.NewStruct(new(record.UserConsent)).
		For(d.Flavor)

	selectBuilder := userConsentStruct.SelectFrom("user_consents")
	selectBuilder.Where(selectBuilder.Equal("user_id", userId))
	selectBuilder.Where(selectBuilder.Equal("client_id", clientId))

	userConsent, err := d.getUserConsentCommon(ctx, tx, selectBuilder, userConsentStruct)
	if err != nil {
		return nil, err
	}

	return userConsent, nil
}

func (d *Database) UserConsentsLoadClients(ctx context.Context, tx *sql.Tx, userConsents []record.UserConsent) error {

	if userConsents == nil {
		return nil
	}

	clientIds := make([]int64, len(userConsents))
	for i, userConsent := range userConsents {
		clientIds[i] = userConsent.ClientId
	}

	clients, err := d.GetClientsByIds(ctx, tx, clientIds)
	if err != nil {
		return errs.Wrap(err, "unable to load clients")
	}

	clientsById := make(map[int64]record.Client)
	for _, client := range clients {
		clientsById[client.Id] = client
	}

	for i, userConsent := range userConsents {
		client, ok := clientsById[userConsent.ClientId]
		if !ok {
			return errs.Errorf("unable to find client with id %v", userConsent.ClientId)
		}
		userConsents[i].Client = client
	}

	return nil
}

func (d *Database) GetConsentsByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]record.UserConsent, error) {

	userConsentStruct := sqlbuilder.NewStruct(new(record.UserConsent)).
		For(d.Flavor)

	selectBuilder := userConsentStruct.SelectFrom("user_consents")
	selectBuilder.Where(selectBuilder.Equal("user_id", userId))

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySQL(ctx, tx, sql, args...)
	if err != nil {
		return nil, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var userConsents []record.UserConsent
	for rows.Next() {
		var userConsent record.UserConsent
		addr := userConsentStruct.Addr(&userConsent)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errs.Wrap(err, "unable to scan userConsent")
		}
		userConsents = append(userConsents, userConsent)
	}

	if err := rows.Err(); err != nil {
		return nil, errs.Wrap(err, "unable to read query results")
	}

	return userConsents, nil
}

func (d *Database) DeleteUserConsent(ctx context.Context, tx *sql.Tx, userConsentId int64) error {

	userConsentStruct := sqlbuilder.NewStruct(new(record.UserConsent)).
		For(d.Flavor)

	deleteBuilder := userConsentStruct.DeleteFrom("user_consents")
	deleteBuilder.Where(deleteBuilder.Equal("id", userConsentId))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSQL(ctx, tx, sql, args...)
	if err != nil {
		return errs.Wrap(err, "unable to delete userConsent")
	}

	return nil
}

func (d *Database) DeleteAllUserConsent(ctx context.Context, tx *sql.Tx) error {
	userConsentStruct := sqlbuilder.NewStruct(new(record.UserConsent)).
		For(d.Flavor)

	deleteBuilder := userConsentStruct.DeleteFrom("user_consents")

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSQL(ctx, tx, sql, args...)
	if err != nil {
		return errs.Wrap(err, "unable to delete userConsent")
	}

	return nil
}
