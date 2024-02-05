package mysqldb

import (
	"database/sql"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/datav2/commondb"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func (d *MySQLDatabase) CreateResource(tx *sql.Tx, resource *entitiesv2.Resource) (*entitiesv2.Resource, error) {

	insertBuilder := sqlbuilder.MySQL.NewInsertBuilder()
	insertBuilder = commondb.ResourceSetColsAndValues(insertBuilder, resource)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to insert resource")
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, errors.Wrap(err, "unable to get last insert id")
	}

	resource, err = d.GetResourceById(tx, id)
	if err != nil {
		return nil, errors.Wrap(err, "unable to get resource by id")
	}
	return resource, nil
}

func (d *MySQLDatabase) GetResourceById(tx *sql.Tx, resourceId int64) (*entitiesv2.Resource, error) {

	selectBuilder := sqlbuilder.MySQL.NewSelectBuilder()
	selectBuilder.
		Select("*").
		From("resources").
		Where(selectBuilder.Equal("id", resourceId))

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var resource *entitiesv2.Resource
	if rows.Next() {
		resource, err = commondb.ResourceScan(rows)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan row")
		}
	}

	return resource, nil
}
