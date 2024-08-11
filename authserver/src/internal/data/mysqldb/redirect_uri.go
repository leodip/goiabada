package mysqldb

import (
	"database/sql"

	"github.com/leodip/goiabada/authserver/internal/models"
)

func (d *MySQLDatabase) CreateRedirectURI(tx *sql.Tx, redirectURI *models.RedirectURI) error {
	return d.CommonDB.CreateRedirectURI(tx, redirectURI)
}

func (d *MySQLDatabase) GetRedirectURIById(tx *sql.Tx, redirectURIId int64) (*models.RedirectURI, error) {
	return d.CommonDB.GetRedirectURIById(tx, redirectURIId)
}

func (d *MySQLDatabase) GetRedirectURIsByClientId(tx *sql.Tx, clientId int64) ([]models.RedirectURI, error) {
	return d.CommonDB.GetRedirectURIsByClientId(tx, clientId)
}

func (d *MySQLDatabase) DeleteRedirectURI(tx *sql.Tx, redirectURIId int64) error {
	return d.CommonDB.DeleteRedirectURI(tx, redirectURIId)
}
