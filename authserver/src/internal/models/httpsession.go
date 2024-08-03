package models

import "database/sql"

type HttpSession struct {
	Id        int64        `db:"id" fieldtag:"pk"`
	Data      string       `db:"data"`
	CreatedAt sql.NullTime `db:"created_at"`
	UpdatedAt sql.NullTime `db:"updated_at"`
	ExpiresOn sql.NullTime `db:"expires_on"`
}
