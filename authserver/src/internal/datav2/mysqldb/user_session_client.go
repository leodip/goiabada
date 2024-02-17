package mysqldb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func (d *MySQLDatabase) CreateUserSessionClient(tx *sql.Tx, userSessionClient *entitiesv2.UserSessionClient) error {

	now := time.Now().UTC()

	originalCreatedAt := userSessionClient.CreatedAt
	originalUpdatedAt := userSessionClient.UpdatedAt
	userSessionClient.CreatedAt = sql.NullTime{Time: now, Valid: true}
	userSessionClient.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	userSessionClientStruct := sqlbuilder.NewStruct(new(entitiesv2.UserSessionClient)).
		For(sqlbuilder.MySQL)

	insertBuilder := userSessionClientStruct.WithoutTag("pk").InsertInto("user_session_clients", userSessionClient)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
	if err != nil {
		userSessionClient.CreatedAt = originalCreatedAt
		userSessionClient.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert userSessionClient")
	}

	id, err := result.LastInsertId()
	if err != nil {
		userSessionClient.CreatedAt = originalCreatedAt
		userSessionClient.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to get last insert id")
	}

	userSessionClient.Id = id
	return nil
}

func (d *MySQLDatabase) UpdateUserSessionClient(tx *sql.Tx, userSessionClient *entitiesv2.UserSessionClient) error {

	if userSessionClient.Id == 0 {
		return errors.New("can't update userSessionClient with id 0")
	}

	originalUpdatedAt := userSessionClient.UpdatedAt
	userSessionClient.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	userSessionClientStruct := sqlbuilder.NewStruct(new(entitiesv2.UserSessionClient)).
		For(sqlbuilder.MySQL)

	updateBuilder := userSessionClientStruct.WithoutTag("pk").Update("user_session_clients", userSessionClient)
	updateBuilder.Where(updateBuilder.Equal("id", userSessionClient.Id))

	sql, args := updateBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		userSessionClient.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update userSessionClient")
	}

	return nil
}

func (d *MySQLDatabase) getUserSessionClientCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	userSessionClientStruct *sqlbuilder.Struct) (*entitiesv2.UserSessionClient, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var userSessionClient entitiesv2.UserSessionClient
	if rows.Next() {
		addr := userSessionClientStruct.Addr(&userSessionClient)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan userSessionClient")
		}
		return &userSessionClient, nil
	}
	return nil, nil
}

func (d *MySQLDatabase) GetUserSessionClientById(tx *sql.Tx, userSessionClientId int64) (*entitiesv2.UserSessionClient, error) {

	if userSessionClientId <= 0 {
		return nil, errors.New("userSessionClientId must be greater than 0")
	}

	userSessionClientStruct := sqlbuilder.NewStruct(new(entitiesv2.UserSessionClient)).
		For(sqlbuilder.MySQL)

	selectBuilder := userSessionClientStruct.SelectFrom("user_session_clients")
	selectBuilder.Where(selectBuilder.Equal("id", userSessionClientId))

	userSessionClient, err := d.getUserSessionClientCommon(tx, selectBuilder, userSessionClientStruct)
	if err != nil {
		return nil, err
	}

	return userSessionClient, nil
}

func (d *MySQLDatabase) DeleteUserSessionClient(tx *sql.Tx, userSessionClientId int64) error {
	if userSessionClientId <= 0 {
		return errors.New("userSessionClientId must be greater than 0")
	}

	clientStruct := sqlbuilder.NewStruct(new(entitiesv2.UserSessionClient)).
		For(sqlbuilder.MySQL)

	deleteBuilder := clientStruct.DeleteFrom("user_session_clients")
	deleteBuilder.Where(deleteBuilder.Equal("id", userSessionClientId))

	sql, args := deleteBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete userSessionClient")
	}

	return nil
}
