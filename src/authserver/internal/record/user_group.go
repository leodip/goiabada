package record

import "database/sql"

type UserGroup struct {
	ID        int64        `db:"id" fieldtag:"pk"`
	CreatedAt sql.NullTime `db:"created_at" fieldtag:"dont-update"`
	UpdatedAt sql.NullTime `db:"updated_at"`
	UserID    int64        `db:"user_id"`
	GroupID   int64        `db:"group_id"`
}
