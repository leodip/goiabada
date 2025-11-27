package sqlitedb

import (
	"database/sql"

	"github.com/leodip/goiabada/core/models"
)

func (d *SQLiteDatabase) CreateUserProfilePicture(tx *sql.Tx, profilePicture *models.UserProfilePicture) error {
	return d.CommonDB.CreateUserProfilePicture(tx, profilePicture)
}

func (d *SQLiteDatabase) UpdateUserProfilePicture(tx *sql.Tx, profilePicture *models.UserProfilePicture) error {
	return d.CommonDB.UpdateUserProfilePicture(tx, profilePicture)
}

func (d *SQLiteDatabase) GetUserProfilePictureByUserId(tx *sql.Tx, userId int64) (*models.UserProfilePicture, error) {
	return d.CommonDB.GetUserProfilePictureByUserId(tx, userId)
}

func (d *SQLiteDatabase) DeleteUserProfilePicture(tx *sql.Tx, userId int64) error {
	return d.CommonDB.DeleteUserProfilePicture(tx, userId)
}

func (d *SQLiteDatabase) UserHasProfilePicture(tx *sql.Tx, userId int64) (bool, error) {
	return d.CommonDB.UserHasProfilePicture(tx, userId)
}
