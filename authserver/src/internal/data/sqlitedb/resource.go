package sqlitedb

import (
	"database/sql"

	"github.com/leodip/goiabada/internal/entities"
)

func (d *SQLiteDatabase) CreateResource(tx *sql.Tx, resource *entities.Resource) error {
	return d.CommonDB.CreateResource(tx, resource)
}

func (d *SQLiteDatabase) UpdateResource(tx *sql.Tx, resource *entities.Resource) error {
	return d.CommonDB.UpdateResource(tx, resource)
}

func (d *SQLiteDatabase) GetResourceById(tx *sql.Tx, resourceId int64) (*entities.Resource, error) {
	return d.CommonDB.GetResourceById(tx, resourceId)
}

func (d *SQLiteDatabase) GetResourceByResourceIdentifier(tx *sql.Tx, resourceIdentifier string) (*entities.Resource, error) {
	return d.CommonDB.GetResourceByResourceIdentifier(tx, resourceIdentifier)
}

func (d *SQLiteDatabase) GetResourcesByIds(tx *sql.Tx, resourceIds []int64) ([]entities.Resource, error) {
	return d.CommonDB.GetResourcesByIds(tx, resourceIds)
}

func (d *SQLiteDatabase) GetAllResources(tx *sql.Tx) ([]entities.Resource, error) {
	return d.CommonDB.GetAllResources(tx)
}

func (d *SQLiteDatabase) DeleteResource(tx *sql.Tx, resourceId int64) error {
	return d.CommonDB.DeleteResource(tx, resourceId)
}
