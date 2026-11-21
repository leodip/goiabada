package record

import "database/sql"

type UserAttribute struct {
	ID                   int64        `db:"id" fieldtag:"pk"`
	CreatedAt            sql.NullTime `db:"created_at" fieldtag:"dont-update"`
	UpdatedAt            sql.NullTime `db:"updated_at"`
	Key                  string       `db:"key" fieldopt:"withquote"`
	Value                string       `db:"value" fieldopt:"withquote"`
	IncludeInIDToken     bool         `db:"include_in_id_token"`
	IncludeInAccessToken bool         `db:"include_in_access_token"`
	UserID               int64        `db:"user_id"`
}
