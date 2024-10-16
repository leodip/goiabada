package sqlitedb

import (
	"database/sql"

	"github.com/leodip/goiabada/core/models"
)

func (d *SQLiteDatabase) CreatePreRegistration(tx *sql.Tx, preRegistration *models.PreRegistration) error {
	return d.CommonDB.CreatePreRegistration(tx, preRegistration)
}

func (d *SQLiteDatabase) UpdatePreRegistration(tx *sql.Tx, preRegistration *models.PreRegistration) error {
	return d.CommonDB.UpdatePreRegistration(tx, preRegistration)
}

func (d *SQLiteDatabase) GetPreRegistrationById(tx *sql.Tx, preRegistrationId int64) (*models.PreRegistration, error) {
	return d.CommonDB.GetPreRegistrationById(tx, preRegistrationId)
}

func (d *SQLiteDatabase) DeletePreRegistration(tx *sql.Tx, preRegistrationId int64) error {
	return d.CommonDB.DeletePreRegistration(tx, preRegistrationId)
}

func (d *SQLiteDatabase) GetPreRegistrationByEmail(tx *sql.Tx, email string) (*models.PreRegistration, error) {
	return d.CommonDB.GetPreRegistrationByEmail(tx, email)
}
