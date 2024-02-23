package commondb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/pkg/errors"
)

func (d *CommonDatabase) CreateUserConsent(tx *sql.Tx, userConsent *entities.UserConsent) error {

	if userConsent.ClientId == 0 {
		return errors.WithStack(errors.New("client id must be greater than 0"))
	}

	if userConsent.UserId == 0 {
		return errors.WithStack(errors.New("user id must be greater than 0"))
	}

	now := time.Now().UTC()

	originalCreatedAt := userConsent.CreatedAt
	originalUpdatedAt := userConsent.UpdatedAt
	userConsent.CreatedAt = sql.NullTime{Time: now, Valid: true}
	userConsent.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	userConsentStruct := sqlbuilder.NewStruct(new(entities.UserConsent)).
		For(d.Flavor)

	insertBuilder := userConsentStruct.WithoutTag("pk").InsertInto("user_consents", userConsent)

	sql, args := insertBuilder.Build()
	result, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		userConsent.CreatedAt = originalCreatedAt
		userConsent.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert userConsent")
	}

	id, err := result.LastInsertId()
	if err != nil {
		userConsent.CreatedAt = originalCreatedAt
		userConsent.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to get last insert id")
	}

	userConsent.Id = id
	return nil
}

func (d *CommonDatabase) UpdateUserConsent(tx *sql.Tx, userConsent *entities.UserConsent) error {

	if userConsent.Id == 0 {
		return errors.WithStack(errors.New("can't update userConsent with id 0"))
	}

	originalUpdatedAt := userConsent.UpdatedAt
	userConsent.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	userConsentStruct := sqlbuilder.NewStruct(new(entities.UserConsent)).
		For(d.Flavor)

	updateBuilder := userConsentStruct.WithoutTag("pk").Update("user_consents", userConsent)
	updateBuilder.Where(updateBuilder.Equal("id", userConsent.Id))

	sql, args := updateBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		userConsent.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update userConsent")
	}

	return nil
}

func (d *CommonDatabase) getUserConsentCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	userConsentStruct *sqlbuilder.Struct) (*entities.UserConsent, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var userConsent entities.UserConsent
	if rows.Next() {
		addr := userConsentStruct.Addr(&userConsent)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan userConsent")
		}
		return &userConsent, nil
	}
	return nil, nil
}

func (d *CommonDatabase) GetUserConsentById(tx *sql.Tx, userConsentId int64) (*entities.UserConsent, error) {

	userConsentStruct := sqlbuilder.NewStruct(new(entities.UserConsent)).
		For(d.Flavor)

	selectBuilder := userConsentStruct.SelectFrom("user_consents")
	selectBuilder.Where(selectBuilder.Equal("id", userConsentId))

	userConsent, err := d.getUserConsentCommon(tx, selectBuilder, userConsentStruct)
	if err != nil {
		return nil, err
	}

	return userConsent, nil
}

func (d *CommonDatabase) GetConsentByUserIdAndClientId(tx *sql.Tx, userId int64, clientId int64) (*entities.UserConsent, error) {

	userConsentStruct := sqlbuilder.NewStruct(new(entities.UserConsent)).
		For(d.Flavor)

	selectBuilder := userConsentStruct.SelectFrom("user_consents")
	selectBuilder.Where(selectBuilder.Equal("user_id", userId))
	selectBuilder.Where(selectBuilder.Equal("client_id", clientId))

	userConsent, err := d.getUserConsentCommon(tx, selectBuilder, userConsentStruct)
	if err != nil {
		return nil, err
	}

	return userConsent, nil
}

func (d *CommonDatabase) UserConsentsLoadClients(tx *sql.Tx, userConsents []entities.UserConsent) error {

	if userConsents == nil {
		return nil
	}

	clientIds := make([]int64, len(userConsents))
	for i, userConsent := range userConsents {
		clientIds[i] = userConsent.ClientId
	}

	clients, err := d.GetClientsByIds(tx, clientIds)
	if err != nil {
		return errors.Wrap(err, "unable to load clients")
	}

	clientsById := make(map[int64]entities.Client)
	for _, client := range clients {
		clientsById[client.Id] = client
	}

	for i, userConsent := range userConsents {
		client, ok := clientsById[userConsent.ClientId]
		if !ok {
			return errors.Errorf("unable to find client with id %v", userConsent.ClientId)
		}
		userConsents[i].Client = client
	}

	return nil
}

func (d *CommonDatabase) GetConsentsByUserId(tx *sql.Tx, userId int64) ([]entities.UserConsent, error) {

	userConsentStruct := sqlbuilder.NewStruct(new(entities.UserConsent)).
		For(d.Flavor)

	selectBuilder := userConsentStruct.SelectFrom("user_consents")
	selectBuilder.Where(selectBuilder.Equal("user_id", userId))

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var userConsents []entities.UserConsent
	for rows.Next() {
		var userConsent entities.UserConsent
		addr := userConsentStruct.Addr(&userConsent)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan userConsent")
		}
		userConsents = append(userConsents, userConsent)
	}

	return userConsents, nil
}

func (d *CommonDatabase) DeleteUserConsent(tx *sql.Tx, userConsentId int64) error {

	userConsentStruct := sqlbuilder.NewStruct(new(entities.UserConsent)).
		For(d.Flavor)

	deleteBuilder := userConsentStruct.DeleteFrom("user_consents")
	deleteBuilder.Where(deleteBuilder.Equal("id", userConsentId))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete userConsent")
	}

	return nil
}

func (d *CommonDatabase) DeleteAllUserConsent(tx *sql.Tx) error {
	userConsentStruct := sqlbuilder.NewStruct(new(entities.UserConsent)).
		For(d.Flavor)

	deleteBuilder := userConsentStruct.DeleteFrom("user_consents")

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete userConsent")
	}

	return nil
}
