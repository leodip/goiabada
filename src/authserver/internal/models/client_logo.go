package models

import "database/sql"

type ClientLogo struct {
	Id          int64        `db:"id" fieldtag:"pk"`
	CreatedAt   sql.NullTime `db:"created_at" fieldtag:"dont-update"`
	UpdatedAt   sql.NullTime `db:"updated_at"`
	ClientId    int64        `db:"client_id"`
	Logo        []byte       `db:"logo"`
	ContentType string       `db:"content_type"`
}
