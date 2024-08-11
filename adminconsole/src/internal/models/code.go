package models

import (
	"database/sql"
	"time"
)

type Code struct {
	Id                  int64        `db:"id" fieldtag:"pk"`
	CreatedAt           sql.NullTime `db:"created_at"`
	UpdatedAt           sql.NullTime `db:"updated_at"`
	Code                string       `db:"-"`
	CodeHash            string       `db:"code_hash"`
	ClientId            int64        `db:"client_id"`
	Client              Client       `db:"-"`
	CodeChallenge       string       `db:"code_challenge"`
	CodeChallengeMethod string       `db:"code_challenge_method"`
	Scope               string       `db:"scope"`
	State               string       `db:"state"`
	Nonce               string       `db:"nonce"`
	RedirectURI         string       `db:"redirect_uri"`
	UserId              int64        `db:"user_id"`
	User                User         `db:"-"`
	IpAddress           string       `db:"ip_address"`
	UserAgent           string       `db:"user_agent"`
	ResponseMode        string       `db:"response_mode"`
	AuthenticatedAt     time.Time    `db:"authenticated_at"`
	SessionIdentifier   string       `db:"session_identifier"`
	AcrLevel            string       `db:"acr_level"`
	AuthMethods         string       `db:"auth_methods"`
	Used                bool         `db:"used"`
}
