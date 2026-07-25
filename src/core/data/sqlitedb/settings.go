package sqlitedb

import (
	"database/sql"
	"time"

	"github.com/leodip/goiabada/core/models"
)

func (d *SQLiteDatabase) CreateSettings(tx *sql.Tx, settings *models.Settings) error {
	return d.CommonDB.CreateSettings(tx, settings)
}

func (d *SQLiteDatabase) UpdateSettings(tx *sql.Tx, settings *models.Settings) error {
	return d.CommonDB.UpdateSettings(tx, settings)
}

func (d *SQLiteDatabase) GetSettingsById(tx *sql.Tx, settingsId int64) (*models.Settings, error) {
	return d.CommonDB.GetSettingsById(tx, settingsId)
}

func (d *SQLiteDatabase) TryClaimCleanupRun(tx *sql.Tx, now time.Time, claimableBefore time.Time) (bool, error) {
	return d.CommonDB.TryClaimCleanupRun(tx, now, claimableBefore)
}
