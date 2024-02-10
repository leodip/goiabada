package mysqldb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func (d *MySQLDatabase) CreateSettings(tx *sql.Tx, settings *entitiesv2.Settings) error {

	now := time.Now().UTC()

	originalCreatedAt := settings.CreatedAt
	originalUpdatedAt := settings.UpdatedAt
	settings.CreatedAt = now
	settings.UpdatedAt = now

	settingsStruct := sqlbuilder.NewStruct(new(entitiesv2.Settings)).
		For(sqlbuilder.MySQL)

	insertBuilder := settingsStruct.WithoutTag("pk").InsertInto("settings", settings)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
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

func (d *MySQLDatabase) UpdateSettings(tx *sql.Tx, settings *entitiesv2.Settings) error {

	if settings.Id == 0 {
		return errors.New("can't update settings with id 0")
	}

	originalUpdatedAt := settings.UpdatedAt
	settings.UpdatedAt = time.Now().UTC()

	settingsStruct := sqlbuilder.NewStruct(new(entitiesv2.Settings)).
		For(sqlbuilder.MySQL)

	updateBuilder := settingsStruct.WithoutTag("pk").Update("settings", settings)
	updateBuilder.Where(updateBuilder.Equal("id", settings.Id))

	sql, args := updateBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		settings.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update settings")
	}

	return nil
}

func (d *MySQLDatabase) getSettingsCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	settingsStruct *sqlbuilder.Struct) (*entitiesv2.Settings, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var settings entitiesv2.Settings
	if rows.Next() {
		addr := settingsStruct.Addr(&settings)
		rows.Scan(addr...)
		return &settings, nil
	}
	return nil, nil
}

func (d *MySQLDatabase) GetSettingsById(tx *sql.Tx, settingsId int64) (*entitiesv2.Settings, error) {

	if settingsId <= 0 {
		return nil, errors.New("settings id must be greater than 0")
	}

	settingsStruct := sqlbuilder.NewStruct(new(entitiesv2.Settings)).
		For(sqlbuilder.MySQL)

	selectBuilder := settingsStruct.SelectFrom("settings")
	selectBuilder.Where(selectBuilder.Equal("id", settingsId))

	settings, err := d.getSettingsCommon(tx, selectBuilder, settingsStruct)
	if err != nil {
		return nil, err
	}

	return settings, nil
}
