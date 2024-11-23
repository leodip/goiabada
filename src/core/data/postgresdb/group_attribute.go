package postgresdb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

func (d *PostgresDatabase) CreateGroupAttribute(tx *sql.Tx, groupAttribute *models.GroupAttribute) error {
	if groupAttribute.GroupId == 0 {
		return errors.WithStack(errors.New("can't create groupAttribute with group_id 0"))
	}

	now := time.Now().UTC()

	originalCreatedAt := groupAttribute.CreatedAt
	originalUpdatedAt := groupAttribute.UpdatedAt
	groupAttribute.CreatedAt = sql.NullTime{Time: now, Valid: true}
	groupAttribute.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	groupAttributeStruct := sqlbuilder.NewStruct(new(models.GroupAttribute)).
		For(sqlbuilder.PostgreSQL)

	insertBuilder := groupAttributeStruct.WithoutTag("pk").InsertInto("group_attributes", groupAttribute)

	sql, args := insertBuilder.Build()
	sql = sql + " RETURNING id"

	rows, err := d.CommonDB.QuerySql(tx, sql, args...)
	if err != nil {
		groupAttribute.CreatedAt = originalCreatedAt
		groupAttribute.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert groupAttribute")
	}
	defer rows.Close()

	if rows.Next() {
		err = rows.Scan(&groupAttribute.Id)
		if err != nil {
			groupAttribute.CreatedAt = originalCreatedAt
			groupAttribute.UpdatedAt = originalUpdatedAt
			return errors.Wrap(err, "unable to scan groupAttribute id")
		}
	}

	return nil
}

func (d *PostgresDatabase) UpdateGroupAttribute(tx *sql.Tx, groupAttribute *models.GroupAttribute) error {
	return d.CommonDB.UpdateGroupAttribute(tx, groupAttribute)
}

func (d *PostgresDatabase) GetGroupAttributeById(tx *sql.Tx, groupAttributeId int64) (*models.GroupAttribute, error) {
	return d.CommonDB.GetGroupAttributeById(tx, groupAttributeId)
}

func (d *PostgresDatabase) GetGroupAttributesByGroupIds(tx *sql.Tx, groupIds []int64) ([]models.GroupAttribute, error) {
	return d.CommonDB.GetGroupAttributesByGroupIds(tx, groupIds)
}

func (d *PostgresDatabase) GetGroupAttributesByGroupId(tx *sql.Tx, groupId int64) ([]models.GroupAttribute, error) {
	return d.CommonDB.GetGroupAttributesByGroupId(tx, groupId)
}

func (d *PostgresDatabase) DeleteGroupAttribute(tx *sql.Tx, groupAttributeId int64) error {
	return d.CommonDB.DeleteGroupAttribute(tx, groupAttributeId)
}
