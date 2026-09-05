package postgresdb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

func (d *PostgresDatabase) CreateClient(tx *sql.Tx, client *models.Client) error {
	now := time.Now().UTC()

	originalCreatedAt := client.CreatedAt
	originalUpdatedAt := client.UpdatedAt
	client.CreatedAt = sql.NullTime{Time: now, Valid: true}
	client.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	clientStruct := sqlbuilder.NewStruct(new(models.Client)).
		For(sqlbuilder.PostgreSQL)

	insertBuilder := clientStruct.WithoutTag("pk").InsertInto("clients", client)

	sql, args := insertBuilder.Build()
	sql = sql + " RETURNING id"

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

	// The driver can defer a constraint violation to the result set rather than
	// returning it from the query, in which case Next() simply reports no row.
	// Without this the insert would look like a success with id 0.
	if err := rows.Err(); err != nil {
		client.CreatedAt = originalCreatedAt
		client.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert client")
	}

	return nil
}

func (d *PostgresDatabase) UpdateClient(tx *sql.Tx, client *models.Client) error {
	return d.CommonDB.UpdateClient(tx, client)
}

func (d *PostgresDatabase) SetClientPublic(tx *sql.Tx, clientId int64) (bool, error) {
	return d.CommonDB.SetClientPublic(tx, clientId)
}

func (d *PostgresDatabase) AcquireClientRow(tx *sql.Tx, clientId int64) error {
	return d.CommonDB.AcquireClientRow(tx, clientId)
}

// AcquireClientRowShared takes FOR SHARE, and the strength matters. FOR KEY SHARE, which is what a
// foreign key reference takes, does NOT conflict with the FOR NO KEY UPDATE that AcquireClientRow's
// timestamp UPDATE takes, so a reference to this client is no barrier at all here. FOR SHARE does
// conflict with it, which is why the acquisition is an explicit statement on this engine rather
// than something the caller gets for free from its own insert.
func (d *PostgresDatabase) AcquireClientRowShared(tx *sql.Tx, clientId int64) error {
	return d.CommonDB.AcquireClientRowSharedWith(tx, clientId, "SELECT id FROM clients WHERE id = $1 FOR SHARE")
}

func (d *PostgresDatabase) GetClientById(tx *sql.Tx, clientId int64) (*models.Client, error) {
	return d.CommonDB.GetClientById(tx, clientId)
}

func (d *PostgresDatabase) GetClientByClientIdentifier(tx *sql.Tx, clientIdentifier string) (*models.Client, error) {
	return d.CommonDB.GetClientByClientIdentifier(tx, clientIdentifier)
}

func (d *PostgresDatabase) ClientLoadRedirectURIs(tx *sql.Tx, client *models.Client) error {
	return d.CommonDB.ClientLoadRedirectURIs(tx, client)
}

func (d *PostgresDatabase) ClientLoadWebOrigins(tx *sql.Tx, client *models.Client) error {
	return d.CommonDB.ClientLoadWebOrigins(tx, client)
}

func (d *PostgresDatabase) GetClientsByIds(tx *sql.Tx, clientIds []int64) ([]models.Client, error) {
	return d.CommonDB.GetClientsByIds(tx, clientIds)
}

func (d *PostgresDatabase) ClientLoadPermissions(tx *sql.Tx, client *models.Client) error {
	return d.CommonDB.ClientLoadPermissions(tx, client)
}

func (d *PostgresDatabase) GetAllClients(tx *sql.Tx) ([]models.Client, error) {
	return d.CommonDB.GetAllClients(tx)
}

func (d *PostgresDatabase) DeleteClient(tx *sql.Tx, clientId int64) error {
	return d.CommonDB.DeleteClient(tx, clientId)
}
