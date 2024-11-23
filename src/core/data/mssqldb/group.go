package mssqldb

import (
	"database/sql"
	"strings"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

func (d *MsSQLDatabase) CreateGroup(tx *sql.Tx, group *models.Group) error {
	now := time.Now().UTC()

	originalCreatedAt := group.CreatedAt
	originalUpdatedAt := group.UpdatedAt
	group.CreatedAt = sql.NullTime{Time: now, Valid: true}
	group.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	groupStruct := sqlbuilder.NewStruct(new(models.Group)).
		For(sqlbuilder.SQLServer)

	insertBuilder := groupStruct.WithoutTag("pk").InsertInto(sqlbuilder.SQLServer.Quote("groups"), group)
	sql, args := insertBuilder.Build()

	parts := strings.SplitN(sql, "VALUES", 2)
	if len(parts) != 2 {
		return errors.New("unexpected SQL format from sqlbuilder")
	}
	sql = parts[0] + "OUTPUT INSERTED.id VALUES" + parts[1]

	rows, err := d.CommonDB.QuerySql(tx, sql, args...)
	if err != nil {
		group.CreatedAt = originalCreatedAt
		group.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert group")
	}
	defer rows.Close()

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

func (d *MsSQLDatabase) UpdateGroup(tx *sql.Tx, group *models.Group) error {
	return d.CommonDB.UpdateGroup(tx, group)
}

func (d *MsSQLDatabase) GetGroupById(tx *sql.Tx, groupId int64) (*models.Group, error) {
	return d.CommonDB.GetGroupById(tx, groupId)
}

func (d *MsSQLDatabase) GetGroupsByIds(tx *sql.Tx, groupIds []int64) ([]models.Group, error) {
	return d.CommonDB.GetGroupsByIds(tx, groupIds)
}

func (d *MsSQLDatabase) GroupLoadPermissions(tx *sql.Tx, group *models.Group) error {
	return d.CommonDB.GroupLoadPermissions(tx, group)
}

func (d *MsSQLDatabase) GroupsLoadPermissions(tx *sql.Tx, groups []models.Group) error {
	return d.CommonDB.GroupsLoadPermissions(tx, groups)
}

func (d *MsSQLDatabase) GroupsLoadAttributes(tx *sql.Tx, groups []models.Group) error {
	return d.CommonDB.GroupsLoadAttributes(tx, groups)
}

func (d *MsSQLDatabase) GetGroupByGroupIdentifier(tx *sql.Tx, groupIdentifier string) (*models.Group, error) {
	return d.CommonDB.GetGroupByGroupIdentifier(tx, groupIdentifier)
}

func (d *MsSQLDatabase) GetAllGroups(tx *sql.Tx) ([]models.Group, error) {
	return d.CommonDB.GetAllGroups(tx)
}

func (d *MsSQLDatabase) GetAllGroupsPaginated(tx *sql.Tx, page int, pageSize int) ([]models.Group, int, error) {
	return d.CommonDB.GetAllGroupsPaginated(tx, page, pageSize)
}

func (d *MsSQLDatabase) GetGroupMembersPaginated(tx *sql.Tx, groupId int64, page int, pageSize int) ([]models.User, int, error) {
	return d.CommonDB.GetGroupMembersPaginated(tx, groupId, page, pageSize)
}

func (d *MsSQLDatabase) CountGroupMembers(tx *sql.Tx, groupId int64) (int, error) {
	return d.CommonDB.CountGroupMembers(tx, groupId)
}

func (d *MsSQLDatabase) DeleteGroup(tx *sql.Tx, groupId int64) error {
	return d.CommonDB.DeleteGroup(tx, groupId)
}
