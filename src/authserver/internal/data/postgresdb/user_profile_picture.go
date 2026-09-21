package postgresdb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/errs"
)

func (d *PostgresDatabase) CreateUserProfilePicture(tx *sql.Tx, profilePicture *models.UserProfilePicture) error {
	if profilePicture.UserId == 0 {
		return errs.New("can't create profile picture with user_id 0")
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

	rows, err := d.QuerySql(tx, sqlStr, args...)
	if err != nil {
		profilePicture.CreatedAt = originalCreatedAt
		profilePicture.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to insert profile picture")
	}
	defer func() { _ = rows.Close() }()

	if rows.Next() {
		err = rows.Scan(&profilePicture.Id)
		if err != nil {
			profilePicture.CreatedAt = originalCreatedAt
			profilePicture.UpdatedAt = originalUpdatedAt
			return errs.Wrap(err, "unable to scan profile picture id")
		}
	}

	// The driver can defer a constraint violation to the result set rather than
	// returning it from the query, in which case Next() simply reports no row.
	// Without this the insert would look like a success with id 0.
	if err := rows.Err(); err != nil {
		profilePicture.CreatedAt = originalCreatedAt
		profilePicture.UpdatedAt = originalUpdatedAt
		return d.WrapSQLError(err, "unable to insert profile picture")
	}

	return nil
}
