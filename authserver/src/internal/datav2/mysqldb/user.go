package mysqldb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func (d *MySQLDatabase) CreateUser(tx *sql.Tx, user *entitiesv2.User) error {

	now := time.Now().UTC()

	originalCreatedAt := user.CreatedAt
	originalUpdatedAt := user.UpdatedAt
	user.CreatedAt = now
	user.UpdatedAt = now

	userStruct := sqlbuilder.NewStruct(new(entitiesv2.User)).
		For(sqlbuilder.MySQL)

	insertBuilder := userStruct.WithoutTag("pk").InsertInto("users", user)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
	if err != nil {
		user.CreatedAt = originalCreatedAt
		user.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert user")
	}

	id, err := result.LastInsertId()
	if err != nil {
		user.CreatedAt = originalCreatedAt
		user.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to get last insert id")
	}

	user.Id = id
	return nil
}

func (d *MySQLDatabase) UpdateUser(tx *sql.Tx, user *entitiesv2.User) error {

	if user.Id == 0 {
		return errors.New("can't update user with id 0")
	}

	originalUpdatedAt := user.UpdatedAt
	user.UpdatedAt = time.Now().UTC()

	userStruct := sqlbuilder.NewStruct(new(entitiesv2.User)).
		For(sqlbuilder.MySQL)

	updateBuilder := userStruct.WithoutTag("pk").Update("users", user)
	updateBuilder.Where(updateBuilder.Equal("id", user.Id))

	sql, args := updateBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		user.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update user")
	}

	return nil
}

func (d *MySQLDatabase) getUserCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	userStruct *sqlbuilder.Struct) (*entitiesv2.User, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var user entitiesv2.User
	if rows.Next() {
		aaa := userStruct.Addr(&user)
		rows.Scan(aaa...)
	}

	return &user, nil
}

func (d *MySQLDatabase) GetUserById(tx *sql.Tx, userId int64) (*entitiesv2.User, error) {

	if userId <= 0 {
		return nil, errors.New("user id must be greater than 0")
	}

	userStruct := sqlbuilder.NewStruct(new(entitiesv2.User)).
		For(sqlbuilder.MySQL)

	selectBuilder := userStruct.SelectFrom("users")
	selectBuilder.Where(selectBuilder.Equal("id", userId))

	user, err := d.getUserCommon(tx, selectBuilder, userStruct)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (d *MySQLDatabase) GetUserByUsername(tx *sql.Tx, username string) (*entitiesv2.User, error) {

	userStruct := sqlbuilder.NewStruct(new(entitiesv2.User)).
		For(sqlbuilder.MySQL)

	selectBuilder := userStruct.SelectFrom("users")
	selectBuilder.Where(selectBuilder.Equal("username", username))

	user, err := d.getUserCommon(tx, selectBuilder, userStruct)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (d *MySQLDatabase) GetUserBySubject(tx *sql.Tx, subject string) (*entitiesv2.User, error) {

	userStruct := sqlbuilder.NewStruct(new(entitiesv2.User)).
		For(sqlbuilder.MySQL)

	selectBuilder := userStruct.SelectFrom("users")
	selectBuilder.Where(selectBuilder.Equal("subject", subject))

	user, err := d.getUserCommon(tx, selectBuilder, userStruct)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (d *MySQLDatabase) GetUserByEmail(tx *sql.Tx, email string) (*entitiesv2.User, error) {

	userStruct := sqlbuilder.NewStruct(new(entitiesv2.User)).
		For(sqlbuilder.MySQL)

	selectBuilder := userStruct.SelectFrom("users")
	selectBuilder.Where(selectBuilder.Equal("email", email))

	user, err := d.getUserCommon(tx, selectBuilder, userStruct)
	if err != nil {
		return nil, err
	}

	return user, nil
}
