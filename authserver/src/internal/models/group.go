package models

import "database/sql"

type Group struct {
	Id                   int64            `db:"id" fieldtag:"pk"`
	CreatedAt            sql.NullTime     `db:"created_at" fieldtag:"dont-update"`
	UpdatedAt            sql.NullTime     `db:"updated_at"`
	GroupIdentifier      string           `db:"group_identifier"`
	Description          string           `db:"description"`
	Attributes           []GroupAttribute `db:"-"`
	Permissions          []Permission     `db:"-"`
	IncludeInIdToken     bool             `db:"include_in_id_token"`
	IncludeInAccessToken bool             `db:"include_in_access_token"`
}
