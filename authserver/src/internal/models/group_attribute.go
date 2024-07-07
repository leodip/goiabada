package models

import "database/sql"

type GroupAttribute struct {
	Id                   int64        `db:"id" fieldtag:"pk"`
	CreatedAt            sql.NullTime `db:"created_at"`
	UpdatedAt            sql.NullTime `db:"updated_at"`
	Key                  string       `db:"key" fieldopt:"withquote"`
	Value                string       `db:"value" fieldopt:"withquote"`
	IncludeInIdToken     bool         `db:"include_in_id_token"`
	IncludeInAccessToken bool         `db:"include_in_access_token"`
	GroupId              int64        `db:"group_id"`
}
