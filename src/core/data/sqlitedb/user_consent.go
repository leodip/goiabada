package sqlitedb

import (
	"database/sql"

	"github.com/leodip/goiabada/core/models"
)

func (d *SQLiteDatabase) CreateUserConsent(tx *sql.Tx, userConsent *models.UserConsent) error {
	return d.CommonDB.CreateUserConsent(tx, userConsent)
}

func (d *SQLiteDatabase) UpdateUserConsent(tx *sql.Tx, userConsent *models.UserConsent) error {
	return d.CommonDB.UpdateUserConsent(tx, userConsent)
}

func (d *SQLiteDatabase) GetUserConsentById(tx *sql.Tx, userConsentId int64) (*models.UserConsent, error) {
	return d.CommonDB.GetUserConsentById(tx, userConsentId)
}

func (d *SQLiteDatabase) GetConsentByUserIdAndClientId(tx *sql.Tx, userId int64, clientId int64) (*models.UserConsent, error) {
	return d.CommonDB.GetConsentByUserIdAndClientId(tx, userId, clientId)
}

func (d *SQLiteDatabase) UserConsentsLoadClients(tx *sql.Tx, userConsents []models.UserConsent) error {
	return d.CommonDB.UserConsentsLoadClients(tx, userConsents)
}

func (d *SQLiteDatabase) GetConsentsByUserId(tx *sql.Tx, userId int64) ([]models.UserConsent, error) {
	return d.CommonDB.GetConsentsByUserId(tx, userId)
}

func (d *SQLiteDatabase) DeleteUserConsent(tx *sql.Tx, userConsentId int64) error {
	return d.CommonDB.DeleteUserConsent(tx, userConsentId)
}

func (d *SQLiteDatabase) DeleteAllUserConsent(tx *sql.Tx) error {
	return d.CommonDB.DeleteAllUserConsent(tx)
}
