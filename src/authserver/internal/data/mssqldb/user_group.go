package mssqldb

import (
	"database/sql"
	"strings"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/errs"
)

func (d *MsSQLDatabase) CreateUserGroup(tx *sql.Tx, userGroup *models.UserGroup) error {
	if userGroup.UserId == 0 {
		return errs.New("can't create userGroup with user_id 0")
	}

	if userGroup.GroupId == 0 {
		return errs.New("can't create userGroup with group_id 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := userGroup.CreatedAt
	originalUpdatedAt := userGroup.UpdatedAt
	userGroup.CreatedAt = sql.NullTime{Time: now, Valid: true}
	userGroup.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	userGroupStruct := sqlbuilder.NewStruct(new(models.UserGroup)).
		For(sqlbuilder.SQLServer)

	insertBuilder := userGroupStruct.WithoutTag("pk").InsertInto("users_groups", userGroup)
	sql, args := insertBuilder.Build()

	parts := strings.SplitN(sql, "VALUES", 2)
	if len(parts) != 2 {
		return errs.New("unexpected SQL format from sqlbuilder")
	}
	sql = parts[0] + "OUTPUT INSERTED.id VALUES" + parts[1]

	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		userGroup.CreatedAt = originalCreatedAt
		userGroup.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to insert userGroup")
	}
	defer func() { _ = rows.Close() }()

	if rows.Next() {
		err = rows.Scan(&userGroup.Id)
		if err != nil {
			userGroup.CreatedAt = originalCreatedAt
			userGroup.UpdatedAt = originalUpdatedAt
			return errs.Wrap(err, "unable to scan userGroup id")
		}
	}

	// The driver can defer a constraint violation to the result set rather than
	// returning it from the query, in which case Next() simply reports no row.
	// Without this the insert would look like a success with id 0.
	if err := rows.Err(); err != nil {
		userGroup.CreatedAt = originalCreatedAt
		userGroup.UpdatedAt = originalUpdatedAt
		return d.WrapSQLError(err, "unable to insert userGroup")
	}

	return nil
}
