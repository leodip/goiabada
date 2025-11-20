package postgresdb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

func (d *PostgresDatabase) CreateGroup(tx *sql.Tx, group *models.Group) error {
	now := time.Now().UTC()

	originalCreatedAt := group.CreatedAt
	originalUpdatedAt := group.UpdatedAt
	group.CreatedAt = sql.NullTime{Time: now, Valid: true}
	group.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	groupStruct := sqlbuilder.NewStruct(new(models.Group)).
		For(sqlbuilder.PostgreSQL)

	insertBuilder := groupStruct.WithoutTag("pk").InsertInto(sqlbuilder.PostgreSQL.Quote("groups"), group)

	sql, args := insertBuilder.Build()
	sql = sql + " RETURNING id"

	rows, err := d.CommonDB.QuerySql(tx, sql, args...)
	if err != nil {
		group.CreatedAt = originalCreatedAt
		group.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert group")
	}
	defer func() { _ = rows.Close() }()

	if rows.Next() {
		err = rows.Scan(&group.Id)
		if err != nil {
			group.CreatedAt = originalCreatedAt
			group.UpdatedAt = originalUpdatedAt
			return errors.Wrap(err, "unable to scan group id")
		}
	}

	return nil
}

func (d *PostgresDatabase) UpdateGroup(tx *sql.Tx, group *models.Group) error {
	return d.CommonDB.UpdateGroup(tx, group)
}

func (d *PostgresDatabase) GetGroupById(tx *sql.Tx, groupId int64) (*models.Group, error) {
	return d.CommonDB.GetGroupById(tx, groupId)
}

func (d *PostgresDatabase) GetGroupsByIds(tx *sql.Tx, groupIds []int64) ([]models.Group, error) {
	return d.CommonDB.GetGroupsByIds(tx, groupIds)
}

func (d *PostgresDatabase) GroupLoadPermissions(tx *sql.Tx, group *models.Group) error {
	return d.CommonDB.GroupLoadPermissions(tx, group)
}

func (d *PostgresDatabase) GroupsLoadPermissions(tx *sql.Tx, groups []models.Group) error {
	return d.CommonDB.GroupsLoadPermissions(tx, groups)
}

func (d *PostgresDatabase) GroupsLoadAttributes(tx *sql.Tx, groups []models.Group) error {
	return d.CommonDB.GroupsLoadAttributes(tx, groups)
}

func (d *PostgresDatabase) GetGroupByGroupIdentifier(tx *sql.Tx, groupIdentifier string) (*models.Group, error) {
	return d.CommonDB.GetGroupByGroupIdentifier(tx, groupIdentifier)
}

func (d *PostgresDatabase) GetAllGroups(tx *sql.Tx) ([]models.Group, error) {
	return d.CommonDB.GetAllGroups(tx)
}

func (d *PostgresDatabase) GetAllGroupsPaginated(tx *sql.Tx, page int, pageSize int) ([]models.Group, int, error) {
	return d.CommonDB.GetAllGroupsPaginated(tx, page, pageSize)
}

func (d *PostgresDatabase) GetGroupMembersPaginated(tx *sql.Tx, groupId int64, page int, pageSize int) ([]models.User, int, error) {
	return d.CommonDB.GetGroupMembersPaginated(tx, groupId, page, pageSize)
}

func (d *PostgresDatabase) CountGroupMembers(tx *sql.Tx, groupId int64) (int, error) {
	return d.CommonDB.CountGroupMembers(tx, groupId)
}

func (d *PostgresDatabase) DeleteGroup(tx *sql.Tx, groupId int64) error {
	return d.CommonDB.DeleteGroup(tx, groupId)
}
