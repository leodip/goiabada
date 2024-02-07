package mysqldb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func (d *MySQLDatabase) CreateSettings(tx *sql.Tx, settings entitiesv2.Settings) (*entitiesv2.Settings, error) {

	now := time.Now().UTC()
	settings.CreatedAt = now
	settings.UpdatedAt = now

	settingsStruct := sqlbuilder.NewStruct(new(entitiesv2.Settings)).
		For(sqlbuilder.MySQL)

	insertBuilder := settingsStruct.WithoutTag("pk").InsertInto("settingss", settings)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to insert settings")
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, errors.Wrap(err, "unable to get last insert id")
	}
	settings.Id = id

	return &settings, nil
}

func (d *MySQLDatabase) UpdateSettings(tx *sql.Tx, settings entitiesv2.Settings) (*entitiesv2.Settings, error) {

	if settings.Id == 0 {
		return nil, errors.New("can't update settings with id 0")
	}

	settings.UpdatedAt = time.Now().UTC()

	settingsStruct := sqlbuilder.NewStruct(new(entitiesv2.Settings)).
		For(sqlbuilder.MySQL)

	updateBuilder := settingsStruct.WithoutTag("pk").Update("settingss", settings)
	updateBuilder.Where(updateBuilder.Equal("id", settings.Id))

	sql, args := updateBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to update settings")
	}

	return &settings, nil
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
		aaa := settingsStruct.Addr(&settings)
		rows.Scan(aaa...)
	}

	return &settings, nil
}

func (d *MySQLDatabase) GetSettingsById(tx *sql.Tx, settingsId int64) (*entitiesv2.Settings, error) {

	if settingsId <= 0 {
		return nil, errors.New("settings id must be greater than 0")
	}

	settingsStruct := sqlbuilder.NewStruct(new(entitiesv2.Settings)).
		For(sqlbuilder.MySQL)

	selectBuilder := settingsStruct.SelectFrom("settingss")
	selectBuilder.Where(selectBuilder.Equal("id", settingsId))

	settings, err := d.getSettingsCommon(tx, selectBuilder, settingsStruct)
	if err != nil {
		return nil, err
	}

	return settings, nil
}
