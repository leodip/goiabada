package mssqldb

import (
	"database/sql"
	"strings"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

func (d *MsSQLDatabase) CreateClient(tx *sql.Tx, client *models.Client) error {
	now := time.Now().UTC()

	originalCreatedAt := client.CreatedAt
	originalUpdatedAt := client.UpdatedAt
	client.CreatedAt = sql.NullTime{Time: now, Valid: true}
	client.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	clientStruct := sqlbuilder.NewStruct(new(models.Client)).
		For(sqlbuilder.SQLServer)

	insertBuilder := clientStruct.WithoutTag("pk").InsertInto("clients", client)
	sql, args := insertBuilder.Build()

	parts := strings.SplitN(sql, "VALUES", 2)
	if len(parts) != 2 {
		return errors.New("unexpected SQL format from sqlbuilder")
	}
	sql = parts[0] + "OUTPUT INSERTED.id VALUES" + parts[1]

	rows, err := d.CommonDB.QuerySql(tx, sql, args...)
	if err != nil {
		client.CreatedAt = originalCreatedAt
		client.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert client")
	}
	defer func() { _ = rows.Close() }()

	if rows.Next() {
		err = rows.Scan(&client.Id)
		if err != nil {
			client.CreatedAt = originalCreatedAt
			client.UpdatedAt = originalUpdatedAt
			return errors.Wrap(err, "unable to scan client id")
		}
	}

	return nil
}

func (d *MsSQLDatabase) UpdateClient(tx *sql.Tx, client *models.Client) error {
	return d.CommonDB.UpdateClient(tx, client)
}

func (d *MsSQLDatabase) GetClientById(tx *sql.Tx, clientId int64) (*models.Client, error) {
	return d.CommonDB.GetClientById(tx, clientId)
}

func (d *MsSQLDatabase) GetClientByClientIdentifier(tx *sql.Tx, clientIdentifier string) (*models.Client, error) {
	return d.CommonDB.GetClientByClientIdentifier(tx, clientIdentifier)
}

func (d *MsSQLDatabase) ClientLoadRedirectURIs(tx *sql.Tx, client *models.Client) error {
	return d.CommonDB.ClientLoadRedirectURIs(tx, client)
}

func (d *MsSQLDatabase) ClientLoadWebOrigins(tx *sql.Tx, client *models.Client) error {
	return d.CommonDB.ClientLoadWebOrigins(tx, client)
}

func (d *MsSQLDatabase) GetClientsByIds(tx *sql.Tx, clientIds []int64) ([]models.Client, error) {
	return d.CommonDB.GetClientsByIds(tx, clientIds)
}

func (d *MsSQLDatabase) ClientLoadPermissions(tx *sql.Tx, client *models.Client) error {
	return d.CommonDB.ClientLoadPermissions(tx, client)
}

func (d *MsSQLDatabase) GetAllClients(tx *sql.Tx) ([]models.Client, error) {
	return d.CommonDB.GetAllClients(tx)
}

func (d *MsSQLDatabase) DeleteClient(tx *sql.Tx, clientId int64) error {
	return d.CommonDB.DeleteClient(tx, clientId)
}
