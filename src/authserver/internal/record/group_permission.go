package record

import "database/sql"

type GroupPermission struct {
	ID           int64        `db:"id" fieldtag:"pk"`
	CreatedAt    sql.NullTime `db:"created_at" fieldtag:"dont-update"`
	UpdatedAt    sql.NullTime `db:"updated_at"`
	GroupID      int64        `db:"group_id"`
	PermissionID int64        `db:"permission_id"`
}
