package mysqldb

import (
	"database/sql"

	"github.com/leodip/goiabada/internal/entitiesv2"
)

func (d *MySQLDatabase) CreateGroupAttribute(tx *sql.Tx, groupAttribute *entitiesv2.GroupAttribute) error {
	return d.CommonDB.CreateGroupAttribute(tx, groupAttribute)
}

func (d *MySQLDatabase) UpdateGroupAttribute(tx *sql.Tx, groupAttribute *entitiesv2.GroupAttribute) error {
	return d.CommonDB.UpdateGroupAttribute(tx, groupAttribute)
}

func (d *MySQLDatabase) GetGroupAttributeById(tx *sql.Tx, groupAttributeId int64) (*entitiesv2.GroupAttribute, error) {
	return d.CommonDB.GetGroupAttributeById(tx, groupAttributeId)
}

func (d *MySQLDatabase) GetGroupAttributesByGroupIds(tx *sql.Tx, groupIds []int64) ([]entitiesv2.GroupAttribute, error) {
	return d.CommonDB.GetGroupAttributesByGroupIds(tx, groupIds)
}

func (d *MySQLDatabase) GetGroupAttributesByGroupId(tx *sql.Tx, groupId int64) ([]entitiesv2.GroupAttribute, error) {
	return d.CommonDB.GetGroupAttributesByGroupId(tx, groupId)
}

func (d *MySQLDatabase) DeleteGroupAttribute(tx *sql.Tx, groupAttributeId int64) error {
	return d.CommonDB.DeleteGroupAttribute(tx, groupAttributeId)
}
