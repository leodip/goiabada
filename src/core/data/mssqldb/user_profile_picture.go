package mssqldb

import (
	"database/sql"
	"strings"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

func (d *MsSQLDatabase) CreateUserProfilePicture(tx *sql.Tx, profilePicture *models.UserProfilePicture) error {
	if profilePicture.UserId == 0 {
		return errors.WithStack(errors.New("can't create profile picture with user_id 0"))
	}

	now := time.Now().UTC()

	originalCreatedAt := profilePicture.CreatedAt
	originalUpdatedAt := profilePicture.UpdatedAt
	profilePicture.CreatedAt = sql.NullTime{Time: now, Valid: true}
	profilePicture.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	profilePictureStruct := sqlbuilder.NewStruct(new(models.UserProfilePicture)).
		For(sqlbuilder.SQLServer)

	insertBuilder := profilePictureStruct.WithoutTag("pk").InsertInto("user_profile_pictures", profilePicture)
	sqlStr, args := insertBuilder.Build()

	// MSSQL doesn't support LastInsertId, use OUTPUT clause instead
	parts := strings.SplitN(sqlStr, "VALUES", 2)
	if len(parts) != 2 {
		return errors.New("unexpected SQL format from sqlbuilder")
	}
	sqlStr = parts[0] + "OUTPUT INSERTED.id VALUES" + parts[1]

	rows, err := d.CommonDB.QuerySql(tx, sqlStr, args...)
	if err != nil {
		profilePicture.CreatedAt = originalCreatedAt
		profilePicture.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert profile picture")
	}
	defer func() { _ = rows.Close() }()

	if rows.Next() {
		err = rows.Scan(&profilePicture.Id)
		if err != nil {
			profilePicture.CreatedAt = originalCreatedAt
			profilePicture.UpdatedAt = originalUpdatedAt
			return errors.Wrap(err, "unable to scan profile picture id")
		}
	}

	return nil
}

func (d *MsSQLDatabase) UpdateUserProfilePicture(tx *sql.Tx, profilePicture *models.UserProfilePicture) error {
	return d.CommonDB.UpdateUserProfilePicture(tx, profilePicture)
}

func (d *MsSQLDatabase) GetUserProfilePictureByUserId(tx *sql.Tx, userId int64) (*models.UserProfilePicture, error) {
	return d.CommonDB.GetUserProfilePictureByUserId(tx, userId)
}

func (d *MsSQLDatabase) DeleteUserProfilePicture(tx *sql.Tx, userId int64) error {
	return d.CommonDB.DeleteUserProfilePicture(tx, userId)
}

func (d *MsSQLDatabase) UserHasProfilePicture(tx *sql.Tx, userId int64) (bool, error) {
	return d.CommonDB.UserHasProfilePicture(tx, userId)
}
