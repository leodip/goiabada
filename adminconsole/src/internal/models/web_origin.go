package models

import "database/sql"

type WebOrigin struct {
	Id        int64        `db:"id" fieldtag:"pk"`
	CreatedAt sql.NullTime `db:"created_at"`
	Origin    string       `db:"origin"`
	ClientId  int64        `db:"client_id"`
}
