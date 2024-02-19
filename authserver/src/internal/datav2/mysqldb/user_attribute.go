package mysqldb

import (
	"database/sql"

	"github.com/leodip/goiabada/internal/entitiesv2"
)

func (d *MySQLDatabase) CreateUserAttribute(tx *sql.Tx, userAttribute *entitiesv2.UserAttribute) error {
	return d.CommonDB.CreateUserAttribute(tx, userAttribute)
}

func (d *MySQLDatabase) UpdateUserAttribute(tx *sql.Tx, userAttribute *entitiesv2.UserAttribute) error {
	return d.CommonDB.UpdateUserAttribute(tx, userAttribute)
}

func (d *MySQLDatabase) GetUserAttributeById(tx *sql.Tx, userAttributeId int64) (*entitiesv2.UserAttribute, error) {
	return d.CommonDB.GetUserAttributeById(tx, userAttributeId)
}

func (d *MySQLDatabase) GetUserAttributesByUserId(tx *sql.Tx, userId int64) ([]entitiesv2.UserAttribute, error) {
	return d.CommonDB.GetUserAttributesByUserId(tx, userId)
}

func (d *MySQLDatabase) DeleteUserAttribute(tx *sql.Tx, userAttributeId int64) error {
	return d.CommonDB.DeleteUserAttribute(tx, userAttributeId)
}
