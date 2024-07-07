package models

import "database/sql"

type RefreshToken struct {
	Id                      int64        `db:"id" fieldtag:"pk"`
	CreatedAt               sql.NullTime `db:"created_at"`
	UpdatedAt               sql.NullTime `db:"updated_at"`
	CodeId                  int64        `db:"code_id"`
	Code                    Code         `db:"-"`
	RefreshTokenJti         string       `db:"refresh_token_jti"`
	PreviousRefreshTokenJti string       `db:"previous_refresh_token_jti"`
	FirstRefreshTokenJti    string       `db:"first_refresh_token_jti"`
	SessionIdentifier       string       `db:"session_identifier"`
	RefreshTokenType        string       `db:"refresh_token_type"`
	Scope                   string       `db:"scope"`
	IssuedAt                sql.NullTime `db:"issued_at"`
	ExpiresAt               sql.NullTime `db:"expires_at"`
	MaxLifetime             sql.NullTime `db:"max_lifetime"`
	Revoked                 bool         `db:"revoked"`
}
