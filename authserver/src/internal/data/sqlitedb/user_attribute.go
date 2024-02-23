package sqlitedb

import (
	"database/sql"

	"github.com/leodip/goiabada/internal/entities"
)

func (d *SQLiteDatabase) CreateUserAttribute(tx *sql.Tx, userAttribute *entities.UserAttribute) error {
	return d.CommonDB.CreateUserAttribute(tx, userAttribute)
}

func (d *SQLiteDatabase) UpdateUserAttribute(tx *sql.Tx, userAttribute *entities.UserAttribute) error {
	return d.CommonDB.UpdateUserAttribute(tx, userAttribute)
}

func (d *SQLiteDatabase) GetUserAttributeById(tx *sql.Tx, userAttributeId int64) (*entities.UserAttribute, error) {
	return d.CommonDB.GetUserAttributeById(tx, userAttributeId)
}

func (d *SQLiteDatabase) GetUserAttributesByUserId(tx *sql.Tx, userId int64) ([]entities.UserAttribute, error) {
	return d.CommonDB.GetUserAttributesByUserId(tx, userId)
}

func (d *SQLiteDatabase) DeleteUserAttribute(tx *sql.Tx, userAttributeId int64) error {
	return d.CommonDB.DeleteUserAttribute(tx, userAttributeId)
}
