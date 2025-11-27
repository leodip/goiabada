package postgresdb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

func (d *PostgresDatabase) CreateUserProfilePicture(tx *sql.Tx, profilePicture *models.UserProfilePicture) error {
	if profilePicture.UserId == 0 {
		return errors.WithStack(errors.New("can't create profile picture with user_id 0"))
	}

	now := time.Now().UTC()

	originalCreatedAt := profilePicture.CreatedAt
	originalUpdatedAt := profilePicture.UpdatedAt
	profilePicture.CreatedAt = sql.NullTime{Time: now, Valid: true}
	profilePicture.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	profilePictureStruct := sqlbuilder.NewStruct(new(models.UserProfilePicture)).
		For(sqlbuilder.PostgreSQL)

	insertBuilder := profilePictureStruct.WithoutTag("pk").InsertInto("user_profile_pictures", profilePicture)
	sqlStr, args := insertBuilder.Build()
	sqlStr = sqlStr + " RETURNING id"

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

func (d *PostgresDatabase) UpdateUserProfilePicture(tx *sql.Tx, profilePicture *models.UserProfilePicture) error {
	return d.CommonDB.UpdateUserProfilePicture(tx, profilePicture)
}

func (d *PostgresDatabase) GetUserProfilePictureByUserId(tx *sql.Tx, userId int64) (*models.UserProfilePicture, error) {
	return d.CommonDB.GetUserProfilePictureByUserId(tx, userId)
}

func (d *PostgresDatabase) DeleteUserProfilePicture(tx *sql.Tx, userId int64) error {
	return d.CommonDB.DeleteUserProfilePicture(tx, userId)
}

func (d *PostgresDatabase) UserHasProfilePicture(tx *sql.Tx, userId int64) (bool, error) {
	return d.CommonDB.UserHasProfilePicture(tx, userId)
}
