package mysqldb

import (
	"database/sql"

	"github.com/leodip/goiabada/internal/entities"
)

func (d *MySQLDatabase) CreateUser(tx *sql.Tx, user *entities.User) error {
	return d.CommonDB.CreateUser(tx, user)
}

func (d *MySQLDatabase) UpdateUser(tx *sql.Tx, user *entities.User) error {
	return d.CommonDB.UpdateUser(tx, user)
}

func (d *MySQLDatabase) GetUsersByIds(tx *sql.Tx, userIds []int64) (map[int64]entities.User, error) {
	return d.CommonDB.GetUsersByIds(tx, userIds)
}

func (d *MySQLDatabase) GetUserById(tx *sql.Tx, userId int64) (*entities.User, error) {
	return d.CommonDB.GetUserById(tx, userId)
}

func (d *MySQLDatabase) UsersLoadPermissions(tx *sql.Tx, users []entities.User) error {
	return d.CommonDB.UsersLoadPermissions(tx, users)
}

func (d *MySQLDatabase) UserLoadAttributes(tx *sql.Tx, user *entities.User) error {
	return d.CommonDB.UserLoadAttributes(tx, user)
}

func (d *MySQLDatabase) UserLoadPermissions(tx *sql.Tx, user *entities.User) error {
	return d.CommonDB.UserLoadPermissions(tx, user)
}

func (d *MySQLDatabase) UsersLoadGroups(tx *sql.Tx, users []entities.User) error {
	return d.CommonDB.UsersLoadGroups(tx, users)
}

func (d *MySQLDatabase) UserLoadGroups(tx *sql.Tx, user *entities.User) error {
	return d.CommonDB.UserLoadGroups(tx, user)
}

func (d *MySQLDatabase) GetUserByUsername(tx *sql.Tx, username string) (*entities.User, error) {
	return d.CommonDB.GetUserByUsername(tx, username)
}

func (d *MySQLDatabase) GetUserBySubject(tx *sql.Tx, subject string) (*entities.User, error) {
	return d.CommonDB.GetUserBySubject(tx, subject)
}

func (d *MySQLDatabase) GetUserByEmail(tx *sql.Tx, email string) (*entities.User, error) {
	return d.CommonDB.GetUserByEmail(tx, email)
}

func (d *MySQLDatabase) GetLastUserWithOTPState(tx *sql.Tx, otpEnabledState bool) (*entities.User, error) {
	return d.CommonDB.GetLastUserWithOTPState(tx, otpEnabledState)
}

func (d *MySQLDatabase) SearchUsersPaginated(tx *sql.Tx, query string, page int, pageSize int) ([]entities.User, int, error) {
	return d.CommonDB.SearchUsersPaginated(tx, query, page, pageSize)
}

func (d *MySQLDatabase) DeleteUser(tx *sql.Tx, userId int64) error {
	return d.CommonDB.DeleteUser(tx, userId)
}
