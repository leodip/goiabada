package models

import "database/sql"

type UserPermission struct {
	Id           int64        `db:"id" fieldtag:"pk"`
	CreatedAt    sql.NullTime `db:"created_at"`
	UpdatedAt    sql.NullTime `db:"updated_at"`
	UserId       int64        `db:"user_id"`
	PermissionId int64        `db:"permission_id"`
}
