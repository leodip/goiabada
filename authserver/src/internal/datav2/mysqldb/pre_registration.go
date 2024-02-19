package mysqldb

import (
	"database/sql"

	"github.com/leodip/goiabada/internal/entitiesv2"
)

func (d *MySQLDatabase) CreatePreRegistration(tx *sql.Tx, preRegistration *entitiesv2.PreRegistration) error {
	return d.CommonDB.CreatePreRegistration(tx, preRegistration)
}

func (d *MySQLDatabase) UpdatePreRegistration(tx *sql.Tx, preRegistration *entitiesv2.PreRegistration) error {
	return d.CommonDB.UpdatePreRegistration(tx, preRegistration)
}

func (d *MySQLDatabase) GetPreRegistrationById(tx *sql.Tx, preRegistrationId int64) (*entitiesv2.PreRegistration, error) {
	return d.CommonDB.GetPreRegistrationById(tx, preRegistrationId)
}

func (d *MySQLDatabase) DeletePreRegistration(tx *sql.Tx, preRegistrationId int64) error {
	return d.CommonDB.DeletePreRegistration(tx, preRegistrationId)
}

func (d *MySQLDatabase) GetPreRegistrationByEmail(tx *sql.Tx, email string) (*entitiesv2.PreRegistration, error) {
	return d.CommonDB.GetPreRegistrationByEmail(tx, email)
}
