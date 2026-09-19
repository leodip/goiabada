package sqlitedb

import (
	"database/sql"

	"github.com/leodip/goiabada/core/models"
)

func (d *SQLiteDatabase) CreateClientLogo(tx *sql.Tx, clientLogo *models.ClientLogo) error {
	return d.CommonDB.CreateClientLogo(tx, clientLogo)
}

func (d *SQLiteDatabase) UpdateClientLogo(tx *sql.Tx, clientLogo *models.ClientLogo) error {
	return d.CommonDB.UpdateClientLogo(tx, clientLogo)
}

func (d *SQLiteDatabase) GetClientLogoByClientId(tx *sql.Tx, clientId int64) (*models.ClientLogo, error) {
	return d.CommonDB.GetClientLogoByClientId(tx, clientId)
}

func (d *SQLiteDatabase) DeleteClientLogo(tx *sql.Tx, clientId int64) error {
	return d.CommonDB.DeleteClientLogo(tx, clientId)
}

func (d *SQLiteDatabase) ClientHasLogo(tx *sql.Tx, clientId int64) (bool, error) {
	return d.CommonDB.ClientHasLogo(tx, clientId)
}
