package sqlitedb

import (
	"database/sql"

	"github.com/leodip/goiabada/internal/entitiesv2"
)

func (d *SQLiteDatabase) CreateUser(tx *sql.Tx, user *entitiesv2.User) error {
	return d.CommonDB.CreateUser(tx, user)
}

func (d *SQLiteDatabase) UpdateUser(tx *sql.Tx, user *entitiesv2.User) error {
	return d.CommonDB.UpdateUser(tx, user)
}

func (d *SQLiteDatabase) GetUsersByIds(tx *sql.Tx, userIds []int64) (map[int64]entitiesv2.User, error) {
	return d.CommonDB.GetUsersByIds(tx, userIds)
}

func (d *SQLiteDatabase) GetUserById(tx *sql.Tx, userId int64) (*entitiesv2.User, error) {
	return d.CommonDB.GetUserById(tx, userId)
}

func (d *SQLiteDatabase) UsersLoadPermissions(tx *sql.Tx, users []entitiesv2.User) error {
	return d.CommonDB.UsersLoadPermissions(tx, users)
}

func (d *SQLiteDatabase) UserLoadAttributes(tx *sql.Tx, user *entitiesv2.User) error {
	return d.CommonDB.UserLoadAttributes(tx, user)
}

func (d *SQLiteDatabase) UserLoadPermissions(tx *sql.Tx, user *entitiesv2.User) error {
	return d.CommonDB.UserLoadPermissions(tx, user)
}

func (d *SQLiteDatabase) UsersLoadGroups(tx *sql.Tx, users []entitiesv2.User) error {
	return d.CommonDB.UsersLoadGroups(tx, users)
}

func (d *SQLiteDatabase) UserLoadGroups(tx *sql.Tx, user *entitiesv2.User) error {
	return d.CommonDB.UserLoadGroups(tx, user)
}

func (d *SQLiteDatabase) GetUserByUsername(tx *sql.Tx, username string) (*entitiesv2.User, error) {
	return d.CommonDB.GetUserByUsername(tx, username)
}

func (d *SQLiteDatabase) GetUserBySubject(tx *sql.Tx, subject string) (*entitiesv2.User, error) {
	return d.CommonDB.GetUserBySubject(tx, subject)
}

func (d *SQLiteDatabase) GetUserByEmail(tx *sql.Tx, email string) (*entitiesv2.User, error) {
	return d.CommonDB.GetUserByEmail(tx, email)
}

func (d *SQLiteDatabase) GetLastUserWithOTPState(tx *sql.Tx, otpEnabledState bool) (*entitiesv2.User, error) {
	return d.CommonDB.GetLastUserWithOTPState(tx, otpEnabledState)
}

func (d *SQLiteDatabase) SearchUsersPaginated(tx *sql.Tx, query string, page int, pageSize int) ([]entitiesv2.User, int, error) {
	return d.CommonDB.SearchUsersPaginated(tx, query, page, pageSize)
}

func (d *SQLiteDatabase) DeleteUser(tx *sql.Tx, userId int64) error {
	return d.CommonDB.DeleteUser(tx, userId)
}
