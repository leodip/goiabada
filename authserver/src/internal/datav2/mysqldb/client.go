package mysqldb

import (
	"database/sql"

	"github.com/leodip/goiabada/internal/entitiesv2"
)

func (d *MySQLDatabase) CreateClient(tx *sql.Tx, client *entitiesv2.Client) error {
	return d.CommonDB.CreateClient(tx, client)
}

func (d *MySQLDatabase) UpdateClient(tx *sql.Tx, client *entitiesv2.Client) error {
	return d.CommonDB.UpdateClient(tx, client)
}

func (d *MySQLDatabase) GetClientById(tx *sql.Tx, clientId int64) (*entitiesv2.Client, error) {
	return d.CommonDB.GetClientById(tx, clientId)
}

func (d *MySQLDatabase) GetClientByClientIdentifier(tx *sql.Tx, clientIdentifier string) (*entitiesv2.Client, error) {
	return d.CommonDB.GetClientByClientIdentifier(tx, clientIdentifier)
}

func (d *MySQLDatabase) ClientLoadRedirectURIs(tx *sql.Tx, client *entitiesv2.Client) error {
	return d.CommonDB.ClientLoadRedirectURIs(tx, client)
}

func (d *MySQLDatabase) ClientLoadWebOrigins(tx *sql.Tx, client *entitiesv2.Client) error {
	return d.CommonDB.ClientLoadWebOrigins(tx, client)
}

func (d *MySQLDatabase) GetClientsByIds(tx *sql.Tx, clientIds []int64) ([]entitiesv2.Client, error) {
	return d.CommonDB.GetClientsByIds(tx, clientIds)
}

func (d *MySQLDatabase) ClientLoadPermissions(tx *sql.Tx, client *entitiesv2.Client) error {
	return d.CommonDB.ClientLoadPermissions(tx, client)
}

func (d *MySQLDatabase) GetAllClients(tx *sql.Tx) ([]*entitiesv2.Client, error) {
	return d.CommonDB.GetAllClients(tx)
}

func (d *MySQLDatabase) DeleteClient(tx *sql.Tx, clientId int64) error {
	return d.CommonDB.DeleteClient(tx, clientId)
}
