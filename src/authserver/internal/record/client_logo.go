package record

import "database/sql"

type ClientLogo struct {
	ID          int64        `db:"id" fieldtag:"pk"`
	CreatedAt   sql.NullTime `db:"created_at" fieldtag:"dont-update"`
	UpdatedAt   sql.NullTime `db:"updated_at"`
	ClientID    int64        `db:"client_id"`
	Logo        []byte       `db:"logo"`
	ContentType string       `db:"content_type"`
}
