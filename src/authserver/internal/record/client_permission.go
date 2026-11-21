package record

import "database/sql"

type ClientPermission struct {
	ID           int64        `db:"id" fieldtag:"pk"`
	CreatedAt    sql.NullTime `db:"created_at" fieldtag:"dont-update"`
	UpdatedAt    sql.NullTime `db:"updated_at"`
	ClientID     int64        `db:"client_id"`
	PermissionID int64        `db:"permission_id"`
}
