package mysqldb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func (d *MySQLDatabase) CreateClient(tx *sql.Tx, client *entitiesv2.Client) error {

	now := time.Now().UTC()

	originalCreatedAt := client.CreatedAt
	originalUpdatedAt := client.UpdatedAt
	client.CreatedAt = now
	client.UpdatedAt = now

	clientStruct := sqlbuilder.NewStruct(new(entitiesv2.Client)).
		For(sqlbuilder.MySQL)

	insertBuilder := clientStruct.WithoutTag("pk").InsertInto("clients", client)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
	if err != nil {
		client.CreatedAt = originalCreatedAt
		client.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert client")
	}

	id, err := result.LastInsertId()
	if err != nil {
		client.CreatedAt = originalCreatedAt
		client.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to get last insert id")
	}

	client.Id = id
	return nil
}

func (d *MySQLDatabase) UpdateClient(tx *sql.Tx, client *entitiesv2.Client) error {

	if client.Id == 0 {
		return errors.New("can't update client with id 0")
	}

	originalUpdatedAt := client.UpdatedAt
	client.UpdatedAt = time.Now().UTC()

	clientStruct := sqlbuilder.NewStruct(new(entitiesv2.Client)).
		For(sqlbuilder.MySQL)

	updateBuilder := clientStruct.WithoutTag("pk").Update("clients", client)
	updateBuilder.Where(updateBuilder.Equal("id", client.Id))

	sql, args := updateBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		client.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update client")
	}

	return nil
}

func (d *MySQLDatabase) getClientCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	clientStruct *sqlbuilder.Struct) (*entitiesv2.Client, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var client entitiesv2.Client
	if rows.Next() {
		aaa := clientStruct.Addr(&client)
		rows.Scan(aaa...)
	}

	return &client, nil
}

func (d *MySQLDatabase) GetClientById(tx *sql.Tx, clientId int64) (*entitiesv2.Client, error) {

	if clientId <= 0 {
		return nil, errors.New("client id must be greater than 0")
	}

	clientStruct := sqlbuilder.NewStruct(new(entitiesv2.Client)).
		For(sqlbuilder.MySQL)

	selectBuilder := clientStruct.SelectFrom("clients")
	selectBuilder.Where(selectBuilder.Equal("id", clientId))

	client, err := d.getClientCommon(tx, selectBuilder, clientStruct)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func (d *MySQLDatabase) GetClientByClientIdentifier(tx *sql.Tx, clientIdentifier string) (*entitiesv2.Client, error) {

	if clientIdentifier == "" {
		return nil, errors.New("client identifier must not be empty")
	}

	clientStruct := sqlbuilder.NewStruct(new(entitiesv2.Client)).
		For(sqlbuilder.MySQL)

	selectBuilder := clientStruct.SelectFrom("clients")
	selectBuilder.Where(selectBuilder.Equal("client_identifier", clientIdentifier))

	client, err := d.getClientCommon(tx, selectBuilder, clientStruct)
	if err != nil {
		return nil, err
	}

	return client, nil
}
