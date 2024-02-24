package mysqldb

import (
	"database/sql"

	"github.com/leodip/goiabada/internal/entities"
)

func (d *MySQLDatabase) CreateGroupAttribute(tx *sql.Tx, groupAttribute *entities.GroupAttribute) error {
	return d.CommonDB.CreateGroupAttribute(tx, groupAttribute)
}

func (d *MySQLDatabase) UpdateGroupAttribute(tx *sql.Tx, groupAttribute *entities.GroupAttribute) error {
	return d.CommonDB.UpdateGroupAttribute(tx, groupAttribute)
}

func (d *MySQLDatabase) GetGroupAttributeById(tx *sql.Tx, groupAttributeId int64) (*entities.GroupAttribute, error) {
	return d.CommonDB.GetGroupAttributeById(tx, groupAttributeId)
}

func (d *MySQLDatabase) GetGroupAttributesByGroupIds(tx *sql.Tx, groupIds []int64) ([]entities.GroupAttribute, error) {
	return d.CommonDB.GetGroupAttributesByGroupIds(tx, groupIds)
}

func (d *MySQLDatabase) GetGroupAttributesByGroupId(tx *sql.Tx, groupId int64) ([]entities.GroupAttribute, error) {
	return d.CommonDB.GetGroupAttributesByGroupId(tx, groupId)
}

func (d *MySQLDatabase) DeleteGroupAttribute(tx *sql.Tx, groupAttributeId int64) error {
	return d.CommonDB.DeleteGroupAttribute(tx, groupAttributeId)
}
