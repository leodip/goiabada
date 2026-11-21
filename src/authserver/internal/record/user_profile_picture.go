package record

import "database/sql"

type UserProfilePicture struct {
	ID          int64        `db:"id" fieldtag:"pk"`
	CreatedAt   sql.NullTime `db:"created_at" fieldtag:"dont-update"`
	UpdatedAt   sql.NullTime `db:"updated_at"`
	UserID      int64        `db:"user_id"`
	Picture     []byte       `db:"picture"`
	ContentType string       `db:"content_type"`
}
