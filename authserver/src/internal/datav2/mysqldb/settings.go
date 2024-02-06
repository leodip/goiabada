package mysqldb

import (
	"database/sql"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/datav2/commondb"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func (d *MySQLDatabase) CreateSettings(tx *sql.Tx, settings *entitiesv2.Settings) (*entitiesv2.Settings, error) {

	insertBuilder := sqlbuilder.MySQL.NewInsertBuilder()
	insertBuilder = commondb.SetSettingsInsertColsAndValues(insertBuilder, settings)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to insert settings")
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, errors.Wrap(err, "unable to get last insert id")
	}

	settings, err = d.GetSettingsById(tx, id)
	if err != nil {
		return nil, errors.Wrap(err, "unable to get settings by id")
	}
	return settings, nil
}

func (d *MySQLDatabase) GetSettingsById(tx *sql.Tx, settingsId int64) (*entitiesv2.Settings, error) {

	selectBuilder := sqlbuilder.MySQL.NewSelectBuilder()
	selectBuilder.
		Select("*").
		From("settings").
		Where(selectBuilder.Equal("id", settingsId))

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var settings *entitiesv2.Settings
	if rows.Next() {
		settings, err = commondb.ScanSettings(rows)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan row")
		}
	}

	return settings, nil
}
