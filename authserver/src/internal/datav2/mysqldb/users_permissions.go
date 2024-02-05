package mysqldb

import (
	"database/sql"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/datav2/commondb"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func (d *MySQLDatabase) CreateUsersPermission(tx *sql.Tx, usersPermissions *entitiesv2.UsersPermissions) (*entitiesv2.UsersPermissions, error) {

	insertBuilder := sqlbuilder.MySQL.NewInsertBuilder()
	insertBuilder = commondb.UsersPermissionsSetColsAndValues(insertBuilder, usersPermissions)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to insert user permission")
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, errors.Wrap(err, "unable to get last insert id")
	}

	usersPermissions, err = d.GetUsersPermissionsById(tx, id)
	if err != nil {
		return nil, errors.Wrap(err, "unable to get user permission by id")
	}

	return usersPermissions, nil
}

func (d *MySQLDatabase) GetUsersPermissionsById(tx *sql.Tx, usersPermissionsId int64) (*entitiesv2.UsersPermissions, error) {

	selectBuilder := sqlbuilder.MySQL.NewSelectBuilder()
	selectBuilder.
		Select("*").
		From("users_permissions").
		Where(selectBuilder.Equal("id", usersPermissionsId))

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var usersPermissions *entitiesv2.UsersPermissions
	if rows.Next() {
		usersPermissions, err = commondb.UsersPermissionsScan(rows)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan row")
		}
	}

	return usersPermissions, nil
}
