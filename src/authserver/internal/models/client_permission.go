package models

import "database/sql"

type ClientPermission struct {
	Id           int64        `db:"id" fieldtag:"pk"`
	CreatedAt    sql.NullTime `db:"created_at" fieldtag:"dont-update"`
	UpdatedAt    sql.NullTime `db:"updated_at"`
	ClientId     int64        `db:"client_id"`
	PermissionId int64        `db:"permission_id"`
}
