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
	user.CreatedAt = sql.NullTime{Time: now, Valid: true}
	user.UpdatedAt = sql.NullTime{Time: now, Valid: true}

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
	user.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

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
		addr := userStruct.Addr(&user)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan user")
		}
		return &user, nil
	}
	return nil, nil
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

func (d *MySQLDatabase) SearchUsersPaginated(tx *sql.Tx, query string, page int, pageSize int) ([]entitiesv2.User, int, error) {

	if page < 1 {
		page = 1
	}

	if pageSize < 1 {
		pageSize = 10
	}

	userStruct := sqlbuilder.NewStruct(new(entitiesv2.User)).
		For(sqlbuilder.MySQL)

	selectBuilder := userStruct.SelectFrom("users")

	if query != "" {
		selectBuilder.Where(
			selectBuilder.Or(
				selectBuilder.Like("subject", "%"+query+"%"),
				selectBuilder.Like("username", "%"+query+"%"),
				selectBuilder.Like("given_name", "%"+query+"%"),
				selectBuilder.Like("middle_name", "%"+query+"%"),
				selectBuilder.Like("family_name", "%"+query+"%"),
				selectBuilder.Like("email", "%"+query+"%"),
			),
		)
	}
	selectBuilder.OrderBy("users.given_name").Asc()
	selectBuilder.Offset((page - 1) * pageSize)
	selectBuilder.Limit(pageSize)

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(nil, sql, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var users []entitiesv2.User
	for rows.Next() {
		var user entitiesv2.User
		addr := userStruct.Addr(&user)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, 0, errors.Wrap(err, "unable to scan user")
		}
		users = append(users, user)
	}

	var count int
	selectBuilder = sqlbuilder.MySQL.NewSelectBuilder()
	selectBuilder.Select("count(*)").From("users")

	if query != "" {
		selectBuilder.Where(
			selectBuilder.Or(
				selectBuilder.Like("subject", "%"+query+"%"),
				selectBuilder.Like("username", "%"+query+"%"),
				selectBuilder.Like("given_name", "%"+query+"%"),
				selectBuilder.Like("middle_name", "%"+query+"%"),
				selectBuilder.Like("family_name", "%"+query+"%"),
				selectBuilder.Like("email", "%"+query+"%"),
			),
		)
	}

	sql, args = selectBuilder.Build()
	rows, err = d.querySql(nil, sql, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	if rows.Next() {
		rows.Scan(&count)
	}

	return users, count, nil
}

func (d *MySQLDatabase) DeleteUser(tx *sql.Tx, userId int64) error {
	if userId <= 0 {
		return errors.New("userId must be greater than 0")
	}

	userStruct := sqlbuilder.NewStruct(new(entitiesv2.UserSession)).
		For(sqlbuilder.MySQL)

	deleteBuilder := userStruct.DeleteFrom("users")
	deleteBuilder.Where(deleteBuilder.Equal("id", userId))

	sql, args := deleteBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete user")
	}

	return nil
}
