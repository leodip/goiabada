package sqlitedb

import (
	"database/sql"

	"github.com/leodip/goiabada/internal/entitiesv2"
)

func (d *SQLiteDatabase) CreateSettings(tx *sql.Tx, settings *entitiesv2.Settings) error {
	return d.CommonDB.CreateSettings(tx, settings)
}

func (d *SQLiteDatabase) UpdateSettings(tx *sql.Tx, settings *entitiesv2.Settings) error {
	return d.CommonDB.UpdateSettings(tx, settings)
}

func (d *SQLiteDatabase) GetSettingsById(tx *sql.Tx, settingsId int64) (*entitiesv2.Settings, error) {
	return d.CommonDB.GetSettingsById(tx, settingsId)
}
