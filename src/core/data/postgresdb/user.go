package postgresdb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

func (d *PostgresDatabase) CreateUser(tx *sql.Tx, user *models.User) error {
	now := time.Now().UTC()

	originalCreatedAt := user.CreatedAt
	originalUpdatedAt := user.UpdatedAt
	user.CreatedAt = sql.NullTime{Time: now, Valid: true}
	user.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	userStruct := sqlbuilder.NewStruct(new(models.User)).
		For(sqlbuilder.PostgreSQL)

	insertBuilder := userStruct.WithoutTag("pk").InsertInto("users", user)

	sql, args := insertBuilder.Build()
	sql = sql + " RETURNING id"

	rows, err := d.CommonDB.QuerySql(tx, sql, args...)
	if err != nil {
		user.CreatedAt = originalCreatedAt
		user.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert user")
	}
	defer func() { _ = rows.Close() }()

	if rows.Next() {
		err = rows.Scan(&user.Id)
		if err != nil {
			user.CreatedAt = originalCreatedAt
			user.UpdatedAt = originalUpdatedAt
			return errors.Wrap(err, "unable to scan user id")
		}
	}

	return nil
}

func (d *PostgresDatabase) UpdateUser(tx *sql.Tx, user *models.User) error {
	return d.CommonDB.UpdateUser(tx, user)
}

func (d *PostgresDatabase) GetUsersByIds(tx *sql.Tx, userIds []int64) (map[int64]models.User, error) {
	return d.CommonDB.GetUsersByIds(tx, userIds)
}

func (d *PostgresDatabase) GetUserById(tx *sql.Tx, userId int64) (*models.User, error) {
	return d.CommonDB.GetUserById(tx, userId)
}

func (d *PostgresDatabase) UsersLoadPermissions(tx *sql.Tx, users []models.User) error {
	return d.CommonDB.UsersLoadPermissions(tx, users)
}

func (d *PostgresDatabase) UserLoadAttributes(tx *sql.Tx, user *models.User) error {
	return d.CommonDB.UserLoadAttributes(tx, user)
}

func (d *PostgresDatabase) UserLoadPermissions(tx *sql.Tx, user *models.User) error {
	return d.CommonDB.UserLoadPermissions(tx, user)
}

func (d *PostgresDatabase) UsersLoadGroups(tx *sql.Tx, users []models.User) error {
	return d.CommonDB.UsersLoadGroups(tx, users)
}

func (d *PostgresDatabase) UserLoadGroups(tx *sql.Tx, user *models.User) error {
	return d.CommonDB.UserLoadGroups(tx, user)
}

func (d *PostgresDatabase) GetUserByUsername(tx *sql.Tx, username string) (*models.User, error) {
	return d.CommonDB.GetUserByUsername(tx, username)
}

func (d *PostgresDatabase) GetUserBySubject(tx *sql.Tx, subject string) (*models.User, error) {
	return d.CommonDB.GetUserBySubject(tx, subject)
}

func (d *PostgresDatabase) GetUserByEmail(tx *sql.Tx, email string) (*models.User, error) {
	return d.CommonDB.GetUserByEmail(tx, email)
}

func (d *PostgresDatabase) GetLastUserWithOTPState(tx *sql.Tx, otpEnabledState bool) (*models.User, error) {
	return d.CommonDB.GetLastUserWithOTPState(tx, otpEnabledState)
}

func (d *PostgresDatabase) SearchUsersPaginated(tx *sql.Tx, query string, page int, pageSize int) ([]models.User, int, error) {
	return d.CommonDB.SearchUsersPaginated(tx, query, page, pageSize)
}

func (d *PostgresDatabase) DeleteUser(tx *sql.Tx, userId int64) error {
	return d.CommonDB.DeleteUser(tx, userId)
}
