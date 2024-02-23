package sqlitedb

import (
	"database/sql"

	"github.com/leodip/goiabada/internal/entities"
)

func (d *SQLiteDatabase) CreateGroup(tx *sql.Tx, group *entities.Group) error {
	return d.CommonDB.CreateGroup(tx, group)
}

func (d *SQLiteDatabase) UpdateGroup(tx *sql.Tx, group *entities.Group) error {
	return d.CommonDB.UpdateGroup(tx, group)
}

func (d *SQLiteDatabase) GetGroupById(tx *sql.Tx, groupId int64) (*entities.Group, error) {
	return d.CommonDB.GetGroupById(tx, groupId)
}

func (d *SQLiteDatabase) GetGroupsByIds(tx *sql.Tx, groupIds []int64) ([]entities.Group, error) {
	return d.CommonDB.GetGroupsByIds(tx, groupIds)
}

func (d *SQLiteDatabase) GroupLoadPermissions(tx *sql.Tx, group *entities.Group) error {
	return d.CommonDB.GroupLoadPermissions(tx, group)
}

func (d *SQLiteDatabase) GroupsLoadPermissions(tx *sql.Tx, groups []entities.Group) error {
	return d.CommonDB.GroupsLoadPermissions(tx, groups)
}

func (d *SQLiteDatabase) GroupsLoadAttributes(tx *sql.Tx, groups []entities.Group) error {
	return d.CommonDB.GroupsLoadAttributes(tx, groups)
}

func (d *SQLiteDatabase) GetGroupByGroupIdentifier(tx *sql.Tx, groupIdentifier string) (*entities.Group, error) {
	return d.CommonDB.GetGroupByGroupIdentifier(tx, groupIdentifier)
}

func (d *SQLiteDatabase) GetAllGroups(tx *sql.Tx) ([]*entities.Group, error) {
	return d.CommonDB.GetAllGroups(tx)
}

func (d *SQLiteDatabase) GetAllGroupsPaginated(tx *sql.Tx, page int, pageSize int) ([]entities.Group, int, error) {
	return d.CommonDB.GetAllGroupsPaginated(tx, page, pageSize)
}

func (d *SQLiteDatabase) GetGroupMembersPaginated(tx *sql.Tx, groupId int64, page int, pageSize int) ([]entities.User, int, error) {
	return d.CommonDB.GetGroupMembersPaginated(tx, groupId, page, pageSize)
}

func (d *SQLiteDatabase) CountGroupMembers(tx *sql.Tx, groupId int64) (int, error) {
	return d.CommonDB.CountGroupMembers(tx, groupId)
}

func (d *SQLiteDatabase) DeleteGroup(tx *sql.Tx, groupId int64) error {
	return d.CommonDB.DeleteGroup(tx, groupId)
}
