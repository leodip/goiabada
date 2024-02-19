package sqlitedb

import (
	"database/sql"

	"github.com/leodip/goiabada/internal/entitiesv2"
)

func (d *SQLiteDatabase) CreateUserAttribute(tx *sql.Tx, userAttribute *entitiesv2.UserAttribute) error {
	return d.CommonDB.CreateUserAttribute(tx, userAttribute)
}

func (d *SQLiteDatabase) UpdateUserAttribute(tx *sql.Tx, userAttribute *entitiesv2.UserAttribute) error {
	return d.CommonDB.UpdateUserAttribute(tx, userAttribute)
}

func (d *SQLiteDatabase) GetUserAttributeById(tx *sql.Tx, userAttributeId int64) (*entitiesv2.UserAttribute, error) {
	return d.CommonDB.GetUserAttributeById(tx, userAttributeId)
}

func (d *SQLiteDatabase) GetUserAttributesByUserId(tx *sql.Tx, userId int64) ([]entitiesv2.UserAttribute, error) {
	return d.CommonDB.GetUserAttributesByUserId(tx, userId)
}

func (d *SQLiteDatabase) DeleteUserAttribute(tx *sql.Tx, userAttributeId int64) error {
	return d.CommonDB.DeleteUserAttribute(tx, userAttributeId)
}
