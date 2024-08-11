package commondb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/pkg/errors"
)

func (d *CommonDatabase) CreateSettings(tx *sql.Tx, settings *models.Settings) error {

	now := time.Now().UTC()

	originalCreatedAt := settings.CreatedAt
	originalUpdatedAt := settings.UpdatedAt
	settings.CreatedAt = sql.NullTime{Time: now, Valid: true}
	settings.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	settingsStruct := sqlbuilder.NewStruct(new(models.Settings)).
		For(d.Flavor)

	insertBuilder := settingsStruct.WithoutTag("pk").InsertInto("settings", settings)

	sql, args := insertBuilder.Build()
	result, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		settings.CreatedAt = originalCreatedAt
		settings.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert settings")
	}

	id, err := result.LastInsertId()
	if err != nil {
		settings.CreatedAt = originalCreatedAt
		settings.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to get last insert id")
	}

	settings.Id = id
	return nil
}

func (d *CommonDatabase) UpdateSettings(tx *sql.Tx, settings *models.Settings) error {

	if settings.Id == 0 {
		return errors.WithStack(errors.New("can't update settings with id 0"))
	}

	originalUpdatedAt := settings.UpdatedAt
	settings.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	settingsStruct := sqlbuilder.NewStruct(new(models.Settings)).
		For(d.Flavor)

	updateBuilder := settingsStruct.WithoutTag("pk").Update("settings", settings)
	updateBuilder.Where(updateBuilder.Equal("id", settings.Id))

	sql, args := updateBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		settings.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update settings")
	}

	return nil
}

func (d *CommonDatabase) getSettingsCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	settingsStruct *sqlbuilder.Struct) (*models.Settings, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var settings models.Settings
	if rows.Next() {
		addr := settingsStruct.Addr(&settings)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan settings")
		}
		return &settings, nil
	}
	return nil, nil
}

func (d *CommonDatabase) GetSettingsById(tx *sql.Tx, settingsId int64) (*models.Settings, error) {

	settingsStruct := sqlbuilder.NewStruct(new(models.Settings)).
		For(d.Flavor)

	selectBuilder := settingsStruct.SelectFrom("settings")
	selectBuilder.Where(selectBuilder.Equal("id", settingsId))

	settings, err := d.getSettingsCommon(tx, selectBuilder, settingsStruct)
	if err != nil {
		return nil, err
	}

	return settings, nil
}
