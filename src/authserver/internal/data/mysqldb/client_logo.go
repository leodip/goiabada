package mysqldb

import (
	"database/sql"

	"github.com/leodip/goiabada/core/models"
)

func (d *MySQLDatabase) CreateClientLogo(tx *sql.Tx, clientLogo *models.ClientLogo) error {
	return d.CommonDB.CreateClientLogo(tx, clientLogo)
}

func (d *MySQLDatabase) UpdateClientLogo(tx *sql.Tx, clientLogo *models.ClientLogo) error {
	return d.CommonDB.UpdateClientLogo(tx, clientLogo)
}

func (d *MySQLDatabase) GetClientLogoByClientId(tx *sql.Tx, clientId int64) (*models.ClientLogo, error) {
	return d.CommonDB.GetClientLogoByClientId(tx, clientId)
}

func (d *MySQLDatabase) DeleteClientLogo(tx *sql.Tx, clientId int64) error {
	return d.CommonDB.DeleteClientLogo(tx, clientId)
}

func (d *MySQLDatabase) ClientHasLogo(tx *sql.Tx, clientId int64) (bool, error) {
	return d.CommonDB.ClientHasLogo(tx, clientId)
}
