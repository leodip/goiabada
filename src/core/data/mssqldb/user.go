package mssqldb

import (
	"database/sql"
	"strings"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

func (d *MsSQLDatabase) CreateUser(tx *sql.Tx, user *models.User) error {
	now := time.Now().UTC()

	originalCreatedAt := user.CreatedAt
	originalUpdatedAt := user.UpdatedAt
	user.CreatedAt = sql.NullTime{Time: now, Valid: true}
	user.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	userStruct := sqlbuilder.NewStruct(new(models.User)).
		For(sqlbuilder.SQLServer)

	insertBuilder := userStruct.WithoutTag("pk").InsertInto("users", user)
	sql, args := insertBuilder.Build()

	parts := strings.SplitN(sql, "VALUES", 2)
	if len(parts) != 2 {
		return errors.New("unexpected SQL format from sqlbuilder")
	}
	sql = parts[0] + "OUTPUT INSERTED.id VALUES" + parts[1]

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

func (d *MsSQLDatabase) UpdateUser(tx *sql.Tx, user *models.User) error {
	return d.CommonDB.UpdateUser(tx, user)
}

func (d *MsSQLDatabase) GetUsersByIds(tx *sql.Tx, userIds []int64) (map[int64]models.User, error) {
	return d.CommonDB.GetUsersByIds(tx, userIds)
}

func (d *MsSQLDatabase) GetUserById(tx *sql.Tx, userId int64) (*models.User, error) {
	return d.CommonDB.GetUserById(tx, userId)
}

func (d *MsSQLDatabase) UsersLoadPermissions(tx *sql.Tx, users []models.User) error {
	return d.CommonDB.UsersLoadPermissions(tx, users)
}

func (d *MsSQLDatabase) UserLoadAttributes(tx *sql.Tx, user *models.User) error {
	return d.CommonDB.UserLoadAttributes(tx, user)
}

func (d *MsSQLDatabase) UserLoadPermissions(tx *sql.Tx, user *models.User) error {
	return d.CommonDB.UserLoadPermissions(tx, user)
}

func (d *MsSQLDatabase) UsersLoadGroups(tx *sql.Tx, users []models.User) error {
	return d.CommonDB.UsersLoadGroups(tx, users)
}

func (d *MsSQLDatabase) UserLoadGroups(tx *sql.Tx, user *models.User) error {
	return d.CommonDB.UserLoadGroups(tx, user)
}

func (d *MsSQLDatabase) GetUserByUsername(tx *sql.Tx, username string) (*models.User, error) {
	return d.CommonDB.GetUserByUsername(tx, username)
}

func (d *MsSQLDatabase) GetUserBySubject(tx *sql.Tx, subject string) (*models.User, error) {
	return d.CommonDB.GetUserBySubject(tx, subject)
}

func (d *MsSQLDatabase) GetUserByEmail(tx *sql.Tx, email string) (*models.User, error) {
	return d.CommonDB.GetUserByEmail(tx, email)
}

func (d *MsSQLDatabase) GetLastUserWithOTPState(tx *sql.Tx, otpEnabledState bool) (*models.User, error) {
	return d.CommonDB.GetLastUserWithOTPState(tx, otpEnabledState)
}

func (d *MsSQLDatabase) SearchUsersPaginated(tx *sql.Tx, query string, page int, pageSize int) ([]models.User, int, error) {
	return d.CommonDB.SearchUsersPaginated(tx, query, page, pageSize)
}

func (d *MsSQLDatabase) DeleteUser(tx *sql.Tx, userId int64) error {
	return d.CommonDB.DeleteUser(tx, userId)
}
