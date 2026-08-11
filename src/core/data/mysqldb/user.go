package mysqldb

import (
	"database/sql"

	"github.com/leodip/goiabada/core/models"
)

func (d *MySQLDatabase) CreateUser(tx *sql.Tx, user *models.User) error {
	return d.CommonDB.CreateUser(tx, user)
}

func (d *MySQLDatabase) UpdateUser(tx *sql.Tx, user *models.User) error {
	return d.CommonDB.UpdateUser(tx, user)
}

func (d *MySQLDatabase) BackfillEncryptedOTPSecrets(aesKey []byte) (int, error) {
	return d.CommonDB.BackfillEncryptedOTPSecrets(aesKey)
}

func (d *MySQLDatabase) ReencryptDataToNewKey(oldKey, newKey []byte) error {
	return d.CommonDB.ReencryptDataToNewKey(oldKey, newKey)
}

func (d *MySQLDatabase) RotateEncryptionKeyIfNeeded(currentKey, previousKey []byte) (bool, error) {
	return d.CommonDB.RotateEncryptionKeyIfNeeded(currentKey, previousKey)
}

func (d *MySQLDatabase) GetUsersByIds(tx *sql.Tx, userIds []int64) (map[int64]models.User, error) {
	return d.CommonDB.GetUsersByIds(tx, userIds)
}

func (d *MySQLDatabase) GetUserById(tx *sql.Tx, userId int64) (*models.User, error) {
	return d.CommonDB.GetUserById(tx, userId)
}

func (d *MySQLDatabase) UsersLoadPermissions(tx *sql.Tx, users []models.User) error {
	return d.CommonDB.UsersLoadPermissions(tx, users)
}

func (d *MySQLDatabase) UserLoadAttributes(tx *sql.Tx, user *models.User) error {
	return d.CommonDB.UserLoadAttributes(tx, user)
}

func (d *MySQLDatabase) UserLoadPermissions(tx *sql.Tx, user *models.User) error {
	return d.CommonDB.UserLoadPermissions(tx, user)
}

func (d *MySQLDatabase) UsersLoadGroups(tx *sql.Tx, users []models.User) error {
	return d.CommonDB.UsersLoadGroups(tx, users)
}

func (d *MySQLDatabase) UserLoadGroups(tx *sql.Tx, user *models.User) error {
	return d.CommonDB.UserLoadGroups(tx, user)
}

func (d *MySQLDatabase) GetUserByUsername(tx *sql.Tx, username string) (*models.User, error) {
	return d.CommonDB.GetUserByUsername(tx, username)
}

func (d *MySQLDatabase) GetUserBySubject(tx *sql.Tx, subject string) (*models.User, error) {
	return d.CommonDB.GetUserBySubject(tx, subject)
}

func (d *MySQLDatabase) GetUserByEmail(tx *sql.Tx, email string) (*models.User, error) {
	return d.CommonDB.GetUserByEmail(tx, email)
}

func (d *MySQLDatabase) GetUserByForgotPasswordCodeHash(tx *sql.Tx, codeHash string) (*models.User, error) {
	return d.CommonDB.GetUserByForgotPasswordCodeHash(tx, codeHash)
}

func (d *MySQLDatabase) GetLastUserWithOTPState(tx *sql.Tx, otpEnabledState bool) (*models.User, error) {
	return d.CommonDB.GetLastUserWithOTPState(tx, otpEnabledState)
}

func (d *MySQLDatabase) SearchUsersPaginated(tx *sql.Tx, query string, page int, pageSize int) ([]models.User, int, error) {
	return d.CommonDB.SearchUsersPaginated(tx, query, page, pageSize)
}

func (d *MySQLDatabase) DeleteUser(tx *sql.Tx, userId int64) error {
	return d.CommonDB.DeleteUser(tx, userId)
}

func (d *MySQLDatabase) IncrementUserAuthStateGeneration(tx *sql.Tx, userId int64) (int64, error) {
	return d.CommonDB.IncrementUserAuthStateGeneration(tx, userId)
}

func (d *MySQLDatabase) SetUserPasswordHash(tx *sql.Tx, userId int64, passwordHash string) error {
	return d.CommonDB.SetUserPasswordHash(tx, userId, passwordHash)
}

func (d *MySQLDatabase) TryConsumeForgotPasswordCode(tx *sql.Tx, userId int64, codeHash string,
	passwordHash string) (bool, error) {
	return d.CommonDB.TryConsumeForgotPasswordCode(tx, userId, codeHash, passwordHash)
}

func (d *MySQLDatabase) TrySetUserEnabled(tx *sql.Tx, userId int64, expected bool, desired bool) (bool, error) {
	return d.CommonDB.TrySetUserEnabled(tx, userId, expected, desired)
}

func (d *MySQLDatabase) TryConsumeUserOTPStep(tx *sql.Tx, userId int64, step int64, requireOTPEnabled bool) (bool, error) {
	return d.CommonDB.TryConsumeUserOTPStep(tx, userId, step, requireOTPEnabled)
}

func (d *MySQLDatabase) ResetUserOTPStep(tx *sql.Tx, userId int64) error {
	return d.CommonDB.ResetUserOTPStep(tx, userId)
}
