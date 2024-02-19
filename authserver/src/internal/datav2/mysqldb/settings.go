package mysqldb

import (
	"database/sql"

	"github.com/leodip/goiabada/internal/entitiesv2"
)

func (d *MySQLDatabase) CreateSettings(tx *sql.Tx, settings *entitiesv2.Settings) error {
	return d.CommonDB.CreateSettings(tx, settings)
}

func (d *MySQLDatabase) UpdateSettings(tx *sql.Tx, settings *entitiesv2.Settings) error {
	return d.CommonDB.UpdateSettings(tx, settings)
}

func (d *MySQLDatabase) GetSettingsById(tx *sql.Tx, settingsId int64) (*entitiesv2.Settings, error) {
	return d.CommonDB.GetSettingsById(tx, settingsId)
}
