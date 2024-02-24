package sqlitedb

import (
	"database/sql"

	"github.com/leodip/goiabada/internal/entities"
)

func (d *SQLiteDatabase) CreatePreRegistration(tx *sql.Tx, preRegistration *entities.PreRegistration) error {
	return d.CommonDB.CreatePreRegistration(tx, preRegistration)
}

func (d *SQLiteDatabase) UpdatePreRegistration(tx *sql.Tx, preRegistration *entities.PreRegistration) error {
	return d.CommonDB.UpdatePreRegistration(tx, preRegistration)
}

func (d *SQLiteDatabase) GetPreRegistrationById(tx *sql.Tx, preRegistrationId int64) (*entities.PreRegistration, error) {
	return d.CommonDB.GetPreRegistrationById(tx, preRegistrationId)
}

func (d *SQLiteDatabase) DeletePreRegistration(tx *sql.Tx, preRegistrationId int64) error {
	return d.CommonDB.DeletePreRegistration(tx, preRegistrationId)
}

func (d *SQLiteDatabase) GetPreRegistrationByEmail(tx *sql.Tx, email string) (*entities.PreRegistration, error) {
	return d.CommonDB.GetPreRegistrationByEmail(tx, email)
}
