package models

import "database/sql"

type Permission struct {
	Id                   int64        `db:"id" fieldtag:"pk"`
	CreatedAt            sql.NullTime `db:"created_at" fieldtag:"dont-update"`
	UpdatedAt            sql.NullTime `db:"updated_at"`
	PermissionIdentifier string       `db:"permission_identifier"`
	Description          string       `db:"description"`
	ResourceId           int64        `db:"resource_id"`
	Resource             Resource     `db:"-"`
}
