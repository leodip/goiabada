package sqlitedb

import (
	"database/sql"

	"github.com/leodip/goiabada/authserver/internal/models"
)

func (d *SQLiteDatabase) CreateUserAttribute(tx *sql.Tx, userAttribute *models.UserAttribute) error {
	return d.CommonDB.CreateUserAttribute(tx, userAttribute)
}

func (d *SQLiteDatabase) UpdateUserAttribute(tx *sql.Tx, userAttribute *models.UserAttribute) error {
	return d.CommonDB.UpdateUserAttribute(tx, userAttribute)
}

func (d *SQLiteDatabase) GetUserAttributeById(tx *sql.Tx, userAttributeId int64) (*models.UserAttribute, error) {
	return d.CommonDB.GetUserAttributeById(tx, userAttributeId)
}

func (d *SQLiteDatabase) GetUserAttributesByUserId(tx *sql.Tx, userId int64) ([]models.UserAttribute, error) {
	return d.CommonDB.GetUserAttributesByUserId(tx, userId)
}

func (d *SQLiteDatabase) DeleteUserAttribute(tx *sql.Tx, userAttributeId int64) error {
	return d.CommonDB.DeleteUserAttribute(tx, userAttributeId)
}
