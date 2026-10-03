package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

func (d *Database) CreateUserSessionClient(ctx context.Context, tx *sql.Tx, userSessionClient *record.UserSessionClient) error {

	now := time.Now().UTC()

	originalCreatedAt := userSessionClient.CreatedAt
	originalUpdatedAt := userSessionClient.UpdatedAt
	userSessionClient.CreatedAt = sql.NullTime{Time: now, Valid: true}
	userSessionClient.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	userSessionClientStruct := sqlbuilder.NewStruct(new(record.UserSessionClient)).
		For(d.Flavor)

	insertBuilder := userSessionClientStruct.WithoutTag("pk").InsertInto("user_session_clients", userSessionClient)

	id, err := d.insertReturningId(ctx, tx, insertBuilder, "userSessionClient")
	if err != nil {
		userSessionClient.CreatedAt = originalCreatedAt
		userSessionClient.UpdatedAt = originalUpdatedAt
		return err
	}

	userSessionClient.Id = id
	return nil
}

func (d *Database) UpdateUserSessionClient(ctx context.Context, tx *sql.Tx, userSessionClient *record.UserSessionClient) error {

	if userSessionClient.Id == 0 {
		return errs.New("can't update userSessionClient with id 0")
	}

	originalUpdatedAt := userSessionClient.UpdatedAt
	userSessionClient.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	userSessionClientStruct := sqlbuilder.NewStruct(new(record.UserSessionClient)).
		For(d.Flavor)

	updateBuilder := userSessionClientStruct.WithoutTag("pk").WithoutTag("dont-update").Update("user_session_clients", userSessionClient)
	updateBuilder.Where(updateBuilder.Equal("id", userSessionClient.Id))

	sql, args := updateBuilder.Build()
	_, err := d.ExecSQL(ctx, tx, sql, args...)
	if err != nil {
		userSessionClient.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to update userSessionClient")
	}

	return nil
}

func (d *Database) getUserSessionClientCommon(ctx context.Context, tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	userSessionClientStruct *sqlbuilder.Struct) (*record.UserSessionClient, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySQL(ctx, tx, sql, args...)
	if err != nil {
		return nil, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var userSessionClient record.UserSessionClient
	if rows.Next() {
		addr := userSessionClientStruct.Addr(&userSessionClient)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errs.Wrap(err, "unable to scan userSessionClient")
		}
		return &userSessionClient, nil
	}
	if err := rows.Err(); err != nil {
		return nil, errs.Wrap(err, "unable to read query results")
	}

	return nil, nil
}

func (d *Database) UserSessionClientsLoadClients(ctx context.Context, tx *sql.Tx, userSessionClients []record.UserSessionClient) error {

	if userSessionClients == nil {
		return nil
	}

	clientIds := make([]int64, 0)
	for _, userSessionClient := range userSessionClients {
		clientIds = append(clientIds, userSessionClient.ClientId)
	}

	clients, err := d.GetClientsByIds(ctx, tx, clientIds)
	if err != nil {
		return errs.Wrap(err, "unable to get clients by ids")
	}

	clientsMap := make(map[int64]record.Client)
	for _, client := range clients {
		clientsMap[client.Id] = client
	}

	for i, userSessionClient := range userSessionClients {
		client, ok := clientsMap[userSessionClient.ClientId]
		if !ok {
			return errs.Errorf("client with id %d not found", userSessionClient.ClientId)
		}
		userSessionClients[i].Client = client
	}

	return nil
}

func (d *Database) GetUserSessionClientsByUserSessionIds(ctx context.Context, tx *sql.Tx, userSessionIds []int64) ([]record.UserSessionClient, error) {

	if len(userSessionIds) == 0 {
		return nil, nil
	}

	var userSessionClients []record.UserSessionClient

	err := forEachIdBatch(userSessionIds, func(batch []int64) error {
		userSessionClientStruct := sqlbuilder.NewStruct(new(record.UserSessionClient)).
			For(d.Flavor)

		selectBuilder := userSessionClientStruct.SelectFrom("user_session_clients")
		selectBuilder.Where(selectBuilder.In("user_session_id", sqlbuilder.Flatten(batch)...))

		sql, args := selectBuilder.Build()
		rows, err := d.QuerySQL(ctx, tx, sql, args...)
		if err != nil {
			return errs.Wrap(err, "unable to query database")
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var userSessionClient record.UserSessionClient
			addr := userSessionClientStruct.Addr(&userSessionClient)
			err = rows.Scan(addr...)
			if err != nil {
				return errs.Wrap(err, "unable to scan userSessionClient")
			}
			userSessionClients = append(userSessionClients, userSessionClient)
		}

		if err := rows.Err(); err != nil {
			return errs.Wrap(err, "unable to read query results")
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return userSessionClients, nil
}

func (d *Database) GetUserSessionClientsByUserSessionId(ctx context.Context, tx *sql.Tx, userSessionId int64) ([]record.UserSessionClient, error) {

	userSessionClientStruct := sqlbuilder.NewStruct(new(record.UserSessionClient)).
		For(d.Flavor)

	selectBuilder := userSessionClientStruct.SelectFrom("user_session_clients")
	selectBuilder.Where(selectBuilder.Equal("user_session_id", userSessionId))

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySQL(ctx, tx, sql, args...)
	if err != nil {
		return nil, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var userSessionClients []record.UserSessionClient
	for rows.Next() {
		var userSessionClient record.UserSessionClient
		addr := userSessionClientStruct.Addr(&userSessionClient)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errs.Wrap(err, "unable to scan userSessionClient")
		}
		userSessionClients = append(userSessionClients, userSessionClient)
	}

	if err := rows.Err(); err != nil {
		return nil, errs.Wrap(err, "unable to read query results")
	}

	return userSessionClients, nil
}

func (d *Database) GetUserSessionsClientByIds(ctx context.Context, tx *sql.Tx, userSessionClientIds []int64) ([]record.UserSessionClient, error) {

	if len(userSessionClientIds) == 0 {
		return nil, nil
	}

	var userSessionClients []record.UserSessionClient

	err := forEachIdBatch(userSessionClientIds, func(batch []int64) error {
		userSessionClientStruct := sqlbuilder.NewStruct(new(record.UserSessionClient)).
			For(d.Flavor)

		selectBuilder := userSessionClientStruct.SelectFrom("user_session_clients")
		selectBuilder.Where(selectBuilder.In("id", sqlbuilder.Flatten(batch)...))

		sql, args := selectBuilder.Build()
		rows, err := d.QuerySQL(ctx, tx, sql, args...)
		if err != nil {
			return errs.Wrap(err, "unable to query database")
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var userSessionClient record.UserSessionClient
			addr := userSessionClientStruct.Addr(&userSessionClient)
			err = rows.Scan(addr...)
			if err != nil {
				return errs.Wrap(err, "unable to scan userSessionClient")
			}
			userSessionClients = append(userSessionClients, userSessionClient)
		}

		if err := rows.Err(); err != nil {
			return errs.Wrap(err, "unable to read query results")
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return userSessionClients, nil
}

func (d *Database) GetUserSessionClientById(ctx context.Context, tx *sql.Tx, userSessionClientId int64) (*record.UserSessionClient, error) {

	userSessionClientStruct := sqlbuilder.NewStruct(new(record.UserSessionClient)).
		For(d.Flavor)

	selectBuilder := userSessionClientStruct.SelectFrom("user_session_clients")
	selectBuilder.Where(selectBuilder.Equal("id", userSessionClientId))

	userSessionClient, err := d.getUserSessionClientCommon(ctx, tx, selectBuilder, userSessionClientStruct)
	if err != nil {
		return nil, err
	}

	return userSessionClient, nil
}

func (d *Database) DeleteUserSessionClient(ctx context.Context, tx *sql.Tx, userSessionClientId int64) error {

	clientStruct := sqlbuilder.NewStruct(new(record.UserSessionClient)).
		For(d.Flavor)

	deleteBuilder := clientStruct.DeleteFrom("user_session_clients")
	deleteBuilder.Where(deleteBuilder.Equal("id", userSessionClientId))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSQL(ctx, tx, sql, args...)
	if err != nil {
		return errs.Wrap(err, "unable to delete userSessionClient")
	}

	return nil
}
