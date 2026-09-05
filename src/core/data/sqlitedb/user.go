package sqlitedb

import (
	"database/sql"
	"time"

	"github.com/leodip/goiabada/core/models"
)

func (d *SQLiteDatabase) AcquireUserRow(tx *sql.Tx, userId int64) error {
	return d.CommonDB.AcquireUserRow(tx, userId)
}

func (d *SQLiteDatabase) CreateUser(tx *sql.Tx, user *models.User) error {
	return d.CommonDB.CreateUser(tx, user)
}

func (d *SQLiteDatabase) UpdateUser(tx *sql.Tx, user *models.User) error {
	return d.CommonDB.UpdateUser(tx, user)
}

func (d *SQLiteDatabase) BackfillEncryptedOTPSecrets(aesKey []byte) (int, error) {
	return d.CommonDB.BackfillEncryptedOTPSecrets(aesKey)
}

func (d *SQLiteDatabase) BackfillLowercaseEmails() (int, int, error) {
	return d.CommonDB.BackfillLowercaseEmails()
}

func (d *SQLiteDatabase) ReencryptDataToNewKey(oldKey, newKey []byte) error {
	return d.CommonDB.ReencryptDataToNewKey(oldKey, newKey)
}

func (d *SQLiteDatabase) RotateEncryptionKeyIfNeeded(currentKey, previousKey []byte) (bool, error) {
	return d.CommonDB.RotateEncryptionKeyIfNeeded(currentKey, previousKey)
}

func (d *SQLiteDatabase) GetUsersByIds(tx *sql.Tx, userIds []int64) (map[int64]models.User, error) {
	return d.CommonDB.GetUsersByIds(tx, userIds)
}

func (d *SQLiteDatabase) GetUserById(tx *sql.Tx, userId int64) (*models.User, error) {
	return d.CommonDB.GetUserById(tx, userId)
}

func (d *SQLiteDatabase) UsersLoadPermissions(tx *sql.Tx, users []models.User) error {
	return d.CommonDB.UsersLoadPermissions(tx, users)
}

func (d *SQLiteDatabase) UserLoadAttributes(tx *sql.Tx, user *models.User) error {
	return d.CommonDB.UserLoadAttributes(tx, user)
}

func (d *SQLiteDatabase) UserLoadPermissions(tx *sql.Tx, user *models.User) error {
	return d.CommonDB.UserLoadPermissions(tx, user)
}

func (d *SQLiteDatabase) UsersLoadGroups(tx *sql.Tx, users []models.User) error {
	return d.CommonDB.UsersLoadGroups(tx, users)
}

func (d *SQLiteDatabase) UserLoadGroups(tx *sql.Tx, user *models.User) error {
	return d.CommonDB.UserLoadGroups(tx, user)
}

func (d *SQLiteDatabase) GetUserByUsername(tx *sql.Tx, username string) (*models.User, error) {
	return d.CommonDB.GetUserByUsername(tx, username)
}

func (d *SQLiteDatabase) GetUserBySubject(tx *sql.Tx, subject string) (*models.User, error) {
	return d.CommonDB.GetUserBySubject(tx, subject)
}

func (d *SQLiteDatabase) GetUserByEmail(tx *sql.Tx, email string) (*models.User, error) {
	return d.CommonDB.GetUserByEmail(tx, email)
}

func (d *SQLiteDatabase) GetUserByForgotPasswordCodeHash(tx *sql.Tx, codeHash string) (*models.User, error) {
	return d.CommonDB.GetUserByForgotPasswordCodeHash(tx, codeHash)
}

func (d *SQLiteDatabase) GetLastUserWithOTPState(tx *sql.Tx, otpEnabledState bool) (*models.User, error) {
	return d.CommonDB.GetLastUserWithOTPState(tx, otpEnabledState)
}

func (d *SQLiteDatabase) SearchUsersPaginated(tx *sql.Tx, query string, page int, pageSize int) ([]models.User, int, error) {
	return d.CommonDB.SearchUsersPaginated(tx, query, page, pageSize)
}

func (d *SQLiteDatabase) DeleteUser(tx *sql.Tx, userId int64) error {
	return d.CommonDB.DeleteUser(tx, userId)
}

func (d *SQLiteDatabase) IncrementUserAuthStateGeneration(tx *sql.Tx, userId int64) (int64, error) {
	return d.CommonDB.IncrementUserAuthStateGeneration(tx, userId)
}

func (d *SQLiteDatabase) IncrementUserOtpConfigGeneration(tx *sql.Tx, userId int64) (int64, error) {
	return d.CommonDB.IncrementUserOtpConfigGeneration(tx, userId)
}

func (d *SQLiteDatabase) SetUserPasswordHash(tx *sql.Tx, userId int64, passwordHash string) error {
	return d.CommonDB.SetUserPasswordHash(tx, userId, passwordHash)
}

func (d *SQLiteDatabase) TryConsumeForgotPasswordCode(tx *sql.Tx, userId int64, codeHash string,
	passwordHash string) (bool, error) {
	return d.CommonDB.TryConsumeForgotPasswordCode(tx, userId, codeHash, passwordHash)
}

func (d *SQLiteDatabase) TrySetUserEnabled(tx *sql.Tx, userId int64, expected bool, desired bool) (bool, error) {
	return d.CommonDB.TrySetUserEnabled(tx, userId, expected, desired)
}

func (d *SQLiteDatabase) TryConsumeUserOTPStep(tx *sql.Tx, userId int64, step int64, requireOTPEnabled bool) (bool, error) {
	return d.CommonDB.TryConsumeUserOTPStep(tx, userId, step, requireOTPEnabled)
}

func (d *SQLiteDatabase) ResetUserOTPStep(tx *sql.Tx, userId int64) error {
	return d.CommonDB.ResetUserOTPStep(tx, userId)
}

func (d *SQLiteDatabase) TryInstallPendingOTPEnrollment(tx *sql.Tx, userId int64,
	secretEncrypted []byte, issuedAt time.Time, staleBefore time.Time) (bool, error) {
	return d.CommonDB.TryInstallPendingOTPEnrollment(tx, userId, secretEncrypted, issuedAt, staleBefore)
}

func (d *SQLiteDatabase) ClearPendingOTPEnrollment(tx *sql.Tx, userId int64) error {
	return d.CommonDB.ClearPendingOTPEnrollment(tx, userId)
}
