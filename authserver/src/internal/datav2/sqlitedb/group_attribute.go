package sqlitedb

import (
	"database/sql"

	"github.com/leodip/goiabada/internal/entitiesv2"
)

func (d *SQLiteDatabase) CreateGroupAttribute(tx *sql.Tx, groupAttribute *entitiesv2.GroupAttribute) error {
	return d.CommonDB.CreateGroupAttribute(tx, groupAttribute)
}

func (d *SQLiteDatabase) UpdateGroupAttribute(tx *sql.Tx, groupAttribute *entitiesv2.GroupAttribute) error {
	return d.CommonDB.UpdateGroupAttribute(tx, groupAttribute)
}

func (d *SQLiteDatabase) GetGroupAttributeById(tx *sql.Tx, groupAttributeId int64) (*entitiesv2.GroupAttribute, error) {
	return d.CommonDB.GetGroupAttributeById(tx, groupAttributeId)
}

func (d *SQLiteDatabase) GetGroupAttributesByGroupIds(tx *sql.Tx, groupIds []int64) ([]entitiesv2.GroupAttribute, error) {
	return d.CommonDB.GetGroupAttributesByGroupIds(tx, groupIds)
}

func (d *SQLiteDatabase) GetGroupAttributesByGroupId(tx *sql.Tx, groupId int64) ([]entitiesv2.GroupAttribute, error) {
	return d.CommonDB.GetGroupAttributesByGroupId(tx, groupId)
}

func (d *SQLiteDatabase) DeleteGroupAttribute(tx *sql.Tx, groupAttributeId int64) error {
	return d.CommonDB.DeleteGroupAttribute(tx, groupAttributeId)
}