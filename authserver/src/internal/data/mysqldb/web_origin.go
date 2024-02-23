package mysqldb

import (
	"database/sql"

	"github.com/leodip/goiabada/internal/entities"
)

func (d *MySQLDatabase) CreateWebOrigin(tx *sql.Tx, webOrigin *entities.WebOrigin) error {
	return d.CommonDB.CreateWebOrigin(tx, webOrigin)
}

func (d *MySQLDatabase) GetWebOriginById(tx *sql.Tx, webOriginId int64) (*entities.WebOrigin, error) {
	return d.CommonDB.GetWebOriginById(tx, webOriginId)
}

func (d *MySQLDatabase) GetWebOriginsByClientId(tx *sql.Tx, clientId int64) ([]entities.WebOrigin, error) {
	return d.CommonDB.GetWebOriginsByClientId(tx, clientId)
}

func (d *MySQLDatabase) GetAllWebOrigins(tx *sql.Tx) ([]*entities.WebOrigin, error) {
	return d.CommonDB.GetAllWebOrigins(tx)
}

func (d *MySQLDatabase) DeleteWebOrigin(tx *sql.Tx, webOriginId int64) error {
	return d.CommonDB.DeleteWebOrigin(tx, webOriginId)
}
