package sqlitedb

import (
	"database/sql"

	"github.com/leodip/goiabada/internal/entitiesv2"
)

func (d *SQLiteDatabase) CreateWebOrigin(tx *sql.Tx, webOrigin *entitiesv2.WebOrigin) error {
	return d.CommonDB.CreateWebOrigin(tx, webOrigin)
}

func (d *SQLiteDatabase) GetWebOriginById(tx *sql.Tx, webOriginId int64) (*entitiesv2.WebOrigin, error) {
	return d.CommonDB.GetWebOriginById(tx, webOriginId)
}

func (d *SQLiteDatabase) GetWebOriginsByClientId(tx *sql.Tx, clientId int64) ([]entitiesv2.WebOrigin, error) {
	return d.CommonDB.GetWebOriginsByClientId(tx, clientId)
}

func (d *SQLiteDatabase) GetAllWebOrigins(tx *sql.Tx) ([]*entitiesv2.WebOrigin, error) {
	return d.CommonDB.GetAllWebOrigins(tx)
}

func (d *SQLiteDatabase) DeleteWebOrigin(tx *sql.Tx, webOriginId int64) error {
	return d.CommonDB.DeleteWebOrigin(tx, webOriginId)
}
