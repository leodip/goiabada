package mysqldb

import (
	"database/sql"

	"github.com/leodip/goiabada/core/models"
)

func (d *MySQLDatabase) CreateSettings(tx *sql.Tx, settings *models.Settings) error {
	return d.CommonDB.CreateSettings(tx, settings)
}

func (d *MySQLDatabase) UpdateSettings(tx *sql.Tx, settings *models.Settings) error {
	return d.CommonDB.UpdateSettings(tx, settings)
}

func (d *MySQLDatabase) GetSettingsById(tx *sql.Tx, settingsId int64) (*models.Settings, error) {
	return d.CommonDB.GetSettingsById(tx, settingsId)
}
