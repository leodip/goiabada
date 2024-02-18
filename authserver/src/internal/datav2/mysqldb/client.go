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
	client.CreatedAt = sql.NullTime{Time: now, Valid: true}
	client.UpdatedAt = sql.NullTime{Time: now, Valid: true}

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
	client.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

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
		addr := clientStruct.Addr(&client)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan client")
		}
		return &client, nil
	}
	return nil, nil
}

func (d *MySQLDatabase) GetClientById(tx *sql.Tx, clientId int64) (*entitiesv2.Client, error) {

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

func (d *MySQLDatabase) ClientLoadRedirectURIs(tx *sql.Tx, client *entitiesv2.Client) error {

	if client == nil {
		return nil
	}

	var err error
	client.RedirectURIs, err = d.GetRedirectURIsByClientId(tx, client.Id)
	if err != nil {
		return errors.Wrap(err, "unable to get redirect URIs")
	}

	return nil
}

func (d *MySQLDatabase) ClientLoadWebOrigins(tx *sql.Tx, client *entitiesv2.Client) error {

	if client == nil {
		return nil
	}

	var err error
	client.WebOrigins, err = d.GetWebOriginsByClientId(tx, client.Id)
	if err != nil {
		return errors.Wrap(err, "unable to get web origins")
	}

	return nil
}

func (d *MySQLDatabase) ClientLoadPermissions(tx *sql.Tx, client *entitiesv2.Client) error {

	if client == nil {
		return nil
	}

	clientPermissions, err := d.GetClientPermissionsByClientId(nil, client.Id)
	if err != nil {
		return err
	}

	permissionIds := make([]int64, 0)
	for _, clientPermission := range clientPermissions {
		permissionIds = append(permissionIds, clientPermission.PermissionId)
	}

	client.Permissions, err = d.GetPermissionsByIds(nil, permissionIds)
	if err != nil {
		return err
	}

	return nil
}

func (d *MySQLDatabase) GetAllClients(tx *sql.Tx) ([]*entitiesv2.Client, error) {

	clientStruct := sqlbuilder.NewStruct(new(entitiesv2.Client)).
		For(sqlbuilder.MySQL)

	selectBuilder := clientStruct.SelectFrom("clients")

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	clients := make([]*entitiesv2.Client, 0)
	for rows.Next() {
		var client entitiesv2.Client
		addr := clientStruct.Addr(&client)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan client")
		}
		clients = append(clients, &client)
	}

	return clients, nil
}

func (d *MySQLDatabase) DeleteClient(tx *sql.Tx, clientId int64) error {

	clientStruct := sqlbuilder.NewStruct(new(entitiesv2.Client)).
		For(sqlbuilder.MySQL)

	deleteBuilder := clientStruct.DeleteFrom("clients")
	deleteBuilder.Where(deleteBuilder.Equal("id", clientId))

	sql, args := deleteBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete client")
	}

	return nil
}
