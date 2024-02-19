package sqlitedb

import (
	"database/sql"

	"github.com/leodip/goiabada/internal/entitiesv2"
)

func (d *SQLiteDatabase) CreateResource(tx *sql.Tx, resource *entitiesv2.Resource) error {
	return d.CommonDB.CreateResource(tx, resource)
}

func (d *SQLiteDatabase) UpdateResource(tx *sql.Tx, resource *entitiesv2.Resource) error {
	return d.CommonDB.UpdateResource(tx, resource)
}

func (d *SQLiteDatabase) GetResourceById(tx *sql.Tx, resourceId int64) (*entitiesv2.Resource, error) {
	return d.CommonDB.GetResourceById(tx, resourceId)
}

func (d *SQLiteDatabase) GetResourceByResourceIdentifier(tx *sql.Tx, resourceIdentifier string) (*entitiesv2.Resource, error) {
	return d.CommonDB.GetResourceByResourceIdentifier(tx, resourceIdentifier)
}

func (d *SQLiteDatabase) GetResourcesByIds(tx *sql.Tx, resourceIds []int64) ([]entitiesv2.Resource, error) {
	return d.CommonDB.GetResourcesByIds(tx, resourceIds)
}

func (d *SQLiteDatabase) GetAllResources(tx *sql.Tx) ([]entitiesv2.Resource, error) {
	return d.CommonDB.GetAllResources(tx)
}

func (d *SQLiteDatabase) DeleteResource(tx *sql.Tx, resourceId int64) error {
	return d.CommonDB.DeleteResource(tx, resourceId)
}
