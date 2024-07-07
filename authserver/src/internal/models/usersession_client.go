package models

import (
	"database/sql"
	"time"
)

type UserSessionClient struct {
	Id            int64        `db:"id" fieldtag:"pk"`
	CreatedAt     sql.NullTime `db:"created_at"`
	UpdatedAt     sql.NullTime `db:"updated_at"`
	UserSessionId int64        `db:"user_session_id"`
	ClientId      int64        `db:"client_id"`
	Client        Client       `db:"-"`
	Started       time.Time    `db:"started"`
	LastAccessed  time.Time    `db:"last_accessed"`
}
