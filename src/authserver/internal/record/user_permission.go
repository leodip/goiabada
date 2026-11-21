package record

import "database/sql"

type UserPermission struct {
	ID           int64        `db:"id" fieldtag:"pk"`
	CreatedAt    sql.NullTime `db:"created_at" fieldtag:"dont-update"`
	UpdatedAt    sql.NullTime `db:"updated_at"`
	UserID       int64        `db:"user_id"`
	PermissionID int64        `db:"permission_id"`
}
