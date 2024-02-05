package mysqldb

import (
	"database/sql"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/datav2/commondb"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func (d *MySQLDatabase) CreateClient(tx *sql.Tx, client *entitiesv2.Client) (*entitiesv2.Client, error) {

	insertBuilder := sqlbuilder.MySQL.NewInsertBuilder()
	insertBuilder = commondb.ClientSetColsAndValues(insertBuilder, client)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to insert client")
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, errors.Wrap(err, "unable to get last insert id")
	}

	client, err = d.GetClientById(tx, id)
	if err != nil {
		return nil, errors.Wrap(err, "unable to get client by id")
	}
	return client, nil
}

func (d *MySQLDatabase) GetClientById(tx *sql.Tx, clientId int64) (*entitiesv2.Client, error) {

	selectBuilder := sqlbuilder.MySQL.NewSelectBuilder()
	selectBuilder.
		Select("*").
		From("clients").
		Where(selectBuilder.Equal("id", clientId))

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var client *entitiesv2.Client
	if rows.Next() {
		client, err = commondb.ClientScan(rows)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan row")
		}
	}

	return client, nil
}
