package commondb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

func (d *CommonDatabase) CreateClient(tx *sql.Tx, client *models.Client) error {

	now := time.Now().UTC()

	originalCreatedAt := client.CreatedAt
	originalUpdatedAt := client.UpdatedAt
	client.CreatedAt = sql.NullTime{Time: now, Valid: true}
	client.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	clientStruct := sqlbuilder.NewStruct(new(models.Client)).
		For(d.Flavor)

	insertBuilder := clientStruct.WithoutTag("pk").InsertInto("clients", client)

	sql, args := insertBuilder.Build()
	result, err := d.ExecSql(tx, sql, args...)
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

func (d *CommonDatabase) UpdateClient(tx *sql.Tx, client *models.Client) error {

	if client.Id == 0 {
		return errors.WithStack(errors.New("can't update client with id 0"))
	}

	originalUpdatedAt := client.UpdatedAt
	client.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	clientStruct := sqlbuilder.NewStruct(new(models.Client)).
		For(d.Flavor)

	updateBuilder := clientStruct.WithoutTag("pk").WithoutTag("dont-update").Update("clients", client)
	updateBuilder.Where(updateBuilder.Equal("id", client.Id))

	sql, args := updateBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		client.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update client")
	}

	return nil
}

func (d *CommonDatabase) getClientCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	clientStruct *sqlbuilder.Struct) (*models.Client, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var client models.Client
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

func (d *CommonDatabase) GetClientById(tx *sql.Tx, clientId int64) (*models.Client, error) {

	clientStruct := sqlbuilder.NewStruct(new(models.Client)).
		For(d.Flavor)

	selectBuilder := clientStruct.SelectFrom("clients")
	selectBuilder.Where(selectBuilder.Equal("id", clientId))

	client, err := d.getClientCommon(tx, selectBuilder, clientStruct)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func (d *CommonDatabase) GetClientByClientIdentifier(tx *sql.Tx, clientIdentifier string) (*models.Client, error) {

	clientStruct := sqlbuilder.NewStruct(new(models.Client)).
		For(d.Flavor)

	selectBuilder := clientStruct.SelectFrom("clients")
	selectBuilder.Where(selectBuilder.Equal("client_identifier", clientIdentifier))

	client, err := d.getClientCommon(tx, selectBuilder, clientStruct)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func (d *CommonDatabase) ClientLoadRedirectURIs(tx *sql.Tx, client *models.Client) error {

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

func (d *CommonDatabase) ClientLoadWebOrigins(tx *sql.Tx, client *models.Client) error {

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

func (d *CommonDatabase) GetClientsByIds(tx *sql.Tx, clientIds []int64) ([]models.Client, error) {

	if len(clientIds) == 0 {
		return []models.Client{}, nil
	}

	clientStruct := sqlbuilder.NewStruct(new(models.Client)).
		For(d.Flavor)

	selectBuilder := clientStruct.SelectFrom("clients")
	selectBuilder.Where(selectBuilder.In("id", sqlbuilder.Flatten(clientIds)...))

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	clients := make([]models.Client, 0)
	for rows.Next() {
		var client models.Client
		addr := clientStruct.Addr(&client)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan client")
		}
		clients = append(clients, client)
	}

	return clients, nil
}

func (d *CommonDatabase) ClientLoadPermissions(tx *sql.Tx, client *models.Client) error {

	if client == nil {
		return nil
	}

	clientPermissions, err := d.GetClientPermissionsByClientId(tx, client.Id)
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

func (d *CommonDatabase) GetAllClients(tx *sql.Tx) ([]models.Client, error) {

	clientStruct := sqlbuilder.NewStruct(new(models.Client)).
		For(d.Flavor)

	selectBuilder := clientStruct.SelectFrom("clients")

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	clients := make([]models.Client, 0)
	for rows.Next() {
		var client models.Client
		addr := clientStruct.Addr(&client)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan client")
		}
		clients = append(clients, client)
	}

	return clients, nil
}

func (d *CommonDatabase) DeleteClient(tx *sql.Tx, clientId int64) error {

	clientStruct := sqlbuilder.NewStruct(new(models.Client)).
		For(d.Flavor)

	deleteBuilder := clientStruct.DeleteFrom("clients")
	deleteBuilder.Where(deleteBuilder.Equal("id", clientId))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete client")
	}

	return nil
}
