package models

import "database/sql"

type RedirectURI struct {
	Id        int64        `db:"id" fieldtag:"pk"`
	CreatedAt sql.NullTime `db:"created_at" fieldtag:"dont-update"`
	URI       string       `db:"uri"`
	ClientId  int64        `db:"client_id"`
}
