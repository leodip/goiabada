package mssqldb

import (
	"database/sql"
	"strings"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

func (d *MsSQLDatabase) CreateUserAttribute(tx *sql.Tx, userAttribute *models.UserAttribute) error {
	if userAttribute.UserId == 0 {
		return errors.WithStack(errors.New("can't create userAttribute with user_id 0"))
	}

	now := time.Now().UTC()

	originalCreatedAt := userAttribute.CreatedAt
	originalUpdatedAt := userAttribute.UpdatedAt
	userAttribute.CreatedAt = sql.NullTime{Time: now, Valid: true}
	userAttribute.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	userAttributeStruct := sqlbuilder.NewStruct(new(models.UserAttribute)).
		For(sqlbuilder.SQLServer)

	insertBuilder := userAttributeStruct.WithoutTag("pk").InsertInto("user_attributes", userAttribute)
	sql, args := insertBuilder.Build()

	parts := strings.SplitN(sql, "VALUES", 2)
	if len(parts) != 2 {
		return errors.New("unexpected SQL format from sqlbuilder")
	}
	sql = parts[0] + "OUTPUT INSERTED.id VALUES" + parts[1]

	rows, err := d.CommonDB.QuerySql(tx, sql, args...)
	if err != nil {
		userAttribute.CreatedAt = originalCreatedAt
		userAttribute.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert userAttribute")
	}
	defer rows.Close()

	if rows.Next() {
		err = rows.Scan(&userAttribute.Id)
		if err != nil {
			userAttribute.CreatedAt = originalCreatedAt
			userAttribute.UpdatedAt = originalUpdatedAt
			return errors.Wrap(err, "unable to scan userAttribute id")
		}
	}

	return nil
}

func (d *MsSQLDatabase) UpdateUserAttribute(tx *sql.Tx, userAttribute *models.UserAttribute) error {
	return d.CommonDB.UpdateUserAttribute(tx, userAttribute)
}

func (d *MsSQLDatabase) GetUserAttributeById(tx *sql.Tx, userAttributeId int64) (*models.UserAttribute, error) {
	return d.CommonDB.GetUserAttributeById(tx, userAttributeId)
}

func (d *MsSQLDatabase) GetUserAttributesByUserId(tx *sql.Tx, userId int64) ([]models.UserAttribute, error) {
	return d.CommonDB.GetUserAttributesByUserId(tx, userId)
}

func (d *MsSQLDatabase) DeleteUserAttribute(tx *sql.Tx, userAttributeId int64) error {
	return d.CommonDB.DeleteUserAttribute(tx, userAttributeId)
}
