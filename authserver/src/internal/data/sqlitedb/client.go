package sqlitedb

import (
	"database/sql"

	"github.com/leodip/goiabada/internal/entities"
)

func (d *SQLiteDatabase) CreateClient(tx *sql.Tx, client *entities.Client) error {
	return d.CommonDB.CreateClient(tx, client)
}

func (d *SQLiteDatabase) UpdateClient(tx *sql.Tx, client *entities.Client) error {
	return d.CommonDB.UpdateClient(tx, client)
}

func (d *SQLiteDatabase) GetClientById(tx *sql.Tx, clientId int64) (*entities.Client, error) {
	return d.CommonDB.GetClientById(tx, clientId)
}

func (d *SQLiteDatabase) GetClientByClientIdentifier(tx *sql.Tx, clientIdentifier string) (*entities.Client, error) {
	return d.CommonDB.GetClientByClientIdentifier(tx, clientIdentifier)
}

func (d *SQLiteDatabase) ClientLoadRedirectURIs(tx *sql.Tx, client *entities.Client) error {
	return d.CommonDB.ClientLoadRedirectURIs(tx, client)
}

func (d *SQLiteDatabase) ClientLoadWebOrigins(tx *sql.Tx, client *entities.Client) error {
	return d.CommonDB.ClientLoadWebOrigins(tx, client)
}

func (d *SQLiteDatabase) GetClientsByIds(tx *sql.Tx, clientIds []int64) ([]entities.Client, error) {
	return d.CommonDB.GetClientsByIds(tx, clientIds)
}

func (d *SQLiteDatabase) ClientLoadPermissions(tx *sql.Tx, client *entities.Client) error {
	return d.CommonDB.ClientLoadPermissions(tx, client)
}

func (d *SQLiteDatabase) GetAllClients(tx *sql.Tx) ([]*entities.Client, error) {
	return d.CommonDB.GetAllClients(tx)
}

func (d *SQLiteDatabase) DeleteClient(tx *sql.Tx, clientId int64) error {
	return d.CommonDB.DeleteClient(tx, clientId)
}
