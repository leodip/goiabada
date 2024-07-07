package sqlitedb

import (
	"database/sql"

	"github.com/leodip/goiabada/internal/models"
)

func (d *SQLiteDatabase) CreateClientPermission(tx *sql.Tx, clientPermission *models.ClientPermission) error {
	return d.CommonDB.CreateClientPermission(tx, clientPermission)
}

func (d *SQLiteDatabase) UpdateClientPermission(tx *sql.Tx, clientPermission *models.ClientPermission) error {
	return d.CommonDB.UpdateClientPermission(tx, clientPermission)
}

func (d *SQLiteDatabase) GetClientPermissionById(tx *sql.Tx, clientPermissionId int64) (*models.ClientPermission, error) {
	return d.CommonDB.GetClientPermissionById(tx, clientPermissionId)
}

func (d *SQLiteDatabase) GetClientPermissionByClientIdAndPermissionId(tx *sql.Tx, clientId, permissionId int64) (*models.ClientPermission, error) {
	return d.CommonDB.GetClientPermissionByClientIdAndPermissionId(tx, clientId, permissionId)
}

func (d *SQLiteDatabase) GetClientPermissionsByClientId(tx *sql.Tx, clientId int64) ([]models.ClientPermission, error) {
	return d.CommonDB.GetClientPermissionsByClientId(tx, clientId)
}

func (d *SQLiteDatabase) DeleteClientPermission(tx *sql.Tx, clientPermissionId int64) error {
	return d.CommonDB.DeleteClientPermission(tx, clientPermissionId)
}
