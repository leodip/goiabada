package mysqldb

import (
	"database/sql"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/datav2/commondb"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func (d *MySQLDatabase) CreateUser(tx *sql.Tx, user *entitiesv2.User) (*entitiesv2.User, error) {

	insertBuilder := sqlbuilder.MySQL.NewInsertBuilder()
	insertBuilder = commondb.SetUserInsertColsAndValues(insertBuilder, user)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to insert user")
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, errors.Wrap(err, "unable to get last insert id")
	}

	user, err = d.GetUserById(tx, id)
	if err != nil {
		return nil, errors.Wrap(err, "unable to get user by id")
	}
	return user, nil
}

func (d *MySQLDatabase) GetUserById(tx *sql.Tx, userId int64) (*entitiesv2.User, error) {

	selectBuilder := sqlbuilder.MySQL.NewSelectBuilder()
	selectBuilder.
		Select("*").
		From("users").
		Where(selectBuilder.Equal("id", userId))

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var user *entitiesv2.User
	if rows.Next() {
		user, err = commondb.ScanUser(rows)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan row")
		}
	}

	return user, nil
}
