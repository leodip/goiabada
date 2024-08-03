package models

import "database/sql"

type GroupPermission struct {
	Id           int64        `db:"id" fieldtag:"pk"`
	CreatedAt    sql.NullTime `db:"created_at"`
	UpdatedAt    sql.NullTime `db:"updated_at"`
	GroupId      int64        `db:"group_id"`
	PermissionId int64        `db:"permission_id"`
}
