package models

import "database/sql"

type RefreshToken struct {
	Id                      int64         `db:"id" fieldtag:"pk"`
	CreatedAt               sql.NullTime  `db:"created_at" fieldtag:"dont-update"`
	UpdatedAt               sql.NullTime  `db:"updated_at"`
	CodeId                  sql.NullInt64 `db:"code_id"`   // For auth code flow (nullable for ROPC)
	Code                    Code          `db:"-"`         // Loaded via CodeId for auth code flow
	UserId                  sql.NullInt64 `db:"user_id"`   // For ROPC flow (direct user reference)
	User                    User          `db:"-"`         // Loaded via UserId for ROPC flow
	ClientId                sql.NullInt64 `db:"client_id"` // For ROPC flow (direct client reference)
	Client                  Client        `db:"-"`         // Loaded via ClientId for ROPC flow
	RefreshTokenJti         string        `db:"refresh_token_jti"`
	PreviousRefreshTokenJti string        `db:"previous_refresh_token_jti"`
	FirstRefreshTokenJti    string        `db:"first_refresh_token_jti"`
	SessionIdentifier       string        `db:"session_identifier"`
	RefreshTokenType        string        `db:"refresh_token_type"`
	Scope                   string        `db:"scope"`
	IssuedAt                sql.NullTime  `db:"issued_at"`
	ExpiresAt               sql.NullTime  `db:"expires_at"`
	MaxLifetime             sql.NullTime  `db:"max_lifetime"`
	Revoked                 bool          `db:"revoked"`
}
