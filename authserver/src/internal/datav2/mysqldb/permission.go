package mysqldb

import (
	"database/sql"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/datav2/commondb"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func (d *MySQLDatabase) CreatePermission(tx *sql.Tx, permission *entitiesv2.Permission) (*entitiesv2.Permission, error) {

	insertBuilder := sqlbuilder.MySQL.NewInsertBuilder()
	insertBuilder = commondb.PermissionSetColsAndValues(insertBuilder, permission)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to insert permission")
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, errors.Wrap(err, "unable to get last insert id")
	}

	permission, err = d.GetPermissionById(tx, id)
	if err != nil {
		return nil, errors.Wrap(err, "unable to get permission by id")
	}
	return permission, nil
}

func (d *MySQLDatabase) GetPermissionById(tx *sql.Tx, permissionId int64) (*entitiesv2.Permission, error) {

	selectBuilder := sqlbuilder.MySQL.NewSelectBuilder()
	selectBuilder.
		Select("*").
		From("permissions").
		Where(selectBuilder.Equal("id", permissionId))

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var permission *entitiesv2.Permission
	if rows.Next() {
		permission, err = commondb.PermissionScan(rows)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan row")
		}
	}

	return permission, nil
}
