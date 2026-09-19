package models

import "database/sql"

type UserGroup struct {
	Id        int64        `db:"id" fieldtag:"pk"`
	CreatedAt sql.NullTime `db:"created_at" fieldtag:"dont-update"`
	UpdatedAt sql.NullTime `db:"updated_at"`
	UserId    int64        `db:"user_id"`
	GroupId   int64        `db:"group_id"`
}
