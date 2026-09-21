package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/errs"
)

func (d *CommonDatabase) CreateUserProfilePicture(ctx context.Context, tx *sql.Tx, profilePicture *models.UserProfilePicture) error {

	if profilePicture.UserId == 0 {
		return errs.New("can't create profile picture with user_id 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := profilePicture.CreatedAt
	originalUpdatedAt := profilePicture.UpdatedAt
	profilePicture.CreatedAt = sql.NullTime{Time: now, Valid: true}
	profilePicture.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	profilePictureStruct := sqlbuilder.NewStruct(new(models.UserProfilePicture)).
		For(d.Flavor)

	insertBuilder := profilePictureStruct.WithoutTag("pk").InsertInto("user_profile_pictures", profilePicture)

	id, err := d.insertReturningId(ctx, tx, insertBuilder, "profile picture")
	if err != nil {
		profilePicture.CreatedAt = originalCreatedAt
		profilePicture.UpdatedAt = originalUpdatedAt
		return err
	}

	profilePicture.Id = id
	return nil
}

func (d *CommonDatabase) UpdateUserProfilePicture(ctx context.Context, tx *sql.Tx, profilePicture *models.UserProfilePicture) error {

	if profilePicture.Id == 0 {
		return errs.New("can't update profile picture with id 0")
	}

	originalUpdatedAt := profilePicture.UpdatedAt
	profilePicture.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	profilePictureStruct := sqlbuilder.NewStruct(new(models.UserProfilePicture)).
		For(d.Flavor)

	updateBuilder := profilePictureStruct.WithoutTag("pk").WithoutTag("dont-update").Update("user_profile_pictures", profilePicture)
	updateBuilder.Where(updateBuilder.Equal("id", profilePicture.Id))

	sql, args := updateBuilder.Build()
	_, err := d.ExecSql(ctx, tx, sql, args...)
	if err != nil {
		profilePicture.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to update profile picture")
	}

	return nil
}

func (d *CommonDatabase) GetUserProfilePictureByUserId(ctx context.Context, tx *sql.Tx, userId int64) (*models.UserProfilePicture, error) {

	profilePictureStruct := sqlbuilder.NewStruct(new(models.UserProfilePicture)).
		For(d.Flavor)

	selectBuilder := profilePictureStruct.SelectFrom("user_profile_pictures")
	selectBuilder.Where(selectBuilder.Equal("user_id", userId))

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(ctx, tx, sql, args...)
	if err != nil {
		return nil, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var profilePicture models.UserProfilePicture
	if rows.Next() {
		addr := profilePictureStruct.Addr(&profilePicture)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errs.Wrap(err, "unable to scan profile picture")
		}
		return &profilePicture, nil
	}
	if err := rows.Err(); err != nil {
		return nil, errs.Wrap(err, "unable to read query results")
	}

	return nil, nil
}

func (d *CommonDatabase) DeleteUserProfilePicture(ctx context.Context, tx *sql.Tx, userId int64) error {

	profilePictureStruct := sqlbuilder.NewStruct(new(models.UserProfilePicture)).
		For(d.Flavor)

	deleteBuilder := profilePictureStruct.DeleteFrom("user_profile_pictures")
	deleteBuilder.Where(deleteBuilder.Equal("user_id", userId))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSql(ctx, tx, sql, args...)
	if err != nil {
		return errs.Wrap(err, "unable to delete profile picture")
	}

	return nil
}

func (d *CommonDatabase) UserHasProfilePicture(ctx context.Context, tx *sql.Tx, userId int64) (bool, error) {

	selectBuilder := d.Flavor.NewSelectBuilder()
	selectBuilder.Select("1").From("user_profile_pictures")
	selectBuilder.Where(selectBuilder.Equal("user_id", userId))
	selectBuilder.Limit(1)

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(ctx, tx, sql, args...)
	if err != nil {
		return false, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	exists := rows.Next()
	if err := rows.Err(); err != nil {
		return false, errs.Wrap(err, "unable to read query results")
	}

	return exists, nil
}
