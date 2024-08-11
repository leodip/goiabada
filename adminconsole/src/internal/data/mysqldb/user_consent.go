package mysqldb

import (
	"database/sql"

	"github.com/leodip/goiabada/adminconsole/internal/models"
)

func (d *MySQLDatabase) CreateUserConsent(tx *sql.Tx, userConsent *models.UserConsent) error {
	return d.CommonDB.CreateUserConsent(tx, userConsent)
}

func (d *MySQLDatabase) UpdateUserConsent(tx *sql.Tx, userConsent *models.UserConsent) error {
	return d.CommonDB.UpdateUserConsent(tx, userConsent)
}

func (d *MySQLDatabase) GetUserConsentById(tx *sql.Tx, userConsentId int64) (*models.UserConsent, error) {
	return d.CommonDB.GetUserConsentById(tx, userConsentId)
}

func (d *MySQLDatabase) GetConsentByUserIdAndClientId(tx *sql.Tx, userId int64, clientId int64) (*models.UserConsent, error) {
	return d.CommonDB.GetConsentByUserIdAndClientId(tx, userId, clientId)
}

func (d *MySQLDatabase) UserConsentsLoadClients(tx *sql.Tx, userConsents []models.UserConsent) error {
	return d.CommonDB.UserConsentsLoadClients(tx, userConsents)
}

func (d *MySQLDatabase) GetConsentsByUserId(tx *sql.Tx, userId int64) ([]models.UserConsent, error) {
	return d.CommonDB.GetConsentsByUserId(tx, userId)
}

func (d *MySQLDatabase) DeleteUserConsent(tx *sql.Tx, userConsentId int64) error {
	return d.CommonDB.DeleteUserConsent(tx, userConsentId)
}

func (d *MySQLDatabase) DeleteAllUserConsent(tx *sql.Tx) error {
	return d.CommonDB.DeleteAllUserConsent(tx)
}
