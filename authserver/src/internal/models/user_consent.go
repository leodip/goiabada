package models

import (
	"database/sql"
	"slices"
	"strings"
)

type UserConsent struct {
	Id        int64        `db:"id" fieldtag:"pk"`
	CreatedAt sql.NullTime `db:"created_at" fieldtag:"dont-update"`
	UpdatedAt sql.NullTime `db:"updated_at"`
	UserId    int64        `db:"user_id"`
	ClientId  int64        `db:"client_id"`
	Client    Client       `db:"-"`
	Scope     string       `db:"scope"`
	GrantedAt sql.NullTime `db:"granted_at"`
}

func (uc *UserConsent) HasScope(scope string) bool {
	if len(uc.Scope) == 0 {
		return false
	}
	return slices.Contains(strings.Split(uc.Scope, " "), scope)
}
