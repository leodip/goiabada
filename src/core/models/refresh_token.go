package models

import "database/sql"

type RefreshToken struct {
	Id        int64        `db:"id" fieldtag:"pk"`
	CreatedAt sql.NullTime `db:"created_at" fieldtag:"dont-update"`
	UpdatedAt sql.NullTime `db:"updated_at"`
	// The three foreign keys are tagged dont-update because nothing reassigns a token's
	// code, its user or its client: rotation constructs a NEW row and copies them, which
	// is what makes the family chain a chain at all. The tag is not hygiene. SQL Server
	// re-checks a foreign key whenever its column appears in an UPDATE's SET list, even
	// with an unchanged value, taking a shared lock on the parent row. UpdateRefreshToken
	// is a full-row update and revokeRefreshTokens is what every session-side transaction
	// ends with, so without these tags a password change, a reset, a termination and the
	// auth-code replay response each took a shared clients lock at their grant sweep,
	// AFTER they already held the session and its association rows. Against DeleteClient,
	// which holds the clients row exclusively and is waiting to read those association
	// rows, that is a cycle, and it deadlocks with the credential operation as the victim.
	// Removing the lock is the fix rather than ordering it: a lock no statement names is
	// one no reader of that code can be expected to order (#139).
	CodeId                  sql.NullInt64 `db:"code_id" fieldtag:"dont-update"`   // For auth code flow (nullable for ROPC)
	Code                    Code          `db:"-"`                                // Loaded via CodeId for auth code flow
	UserId                  sql.NullInt64 `db:"user_id" fieldtag:"dont-update"`   // For ROPC flow (direct user reference)
	User                    User          `db:"-"`                                // Loaded via UserId for ROPC flow
	ClientId                sql.NullInt64 `db:"client_id" fieldtag:"dont-update"` // For ROPC flow (direct client reference)
	Client                  Client        `db:"-"`                                // Loaded via ClientId for ROPC flow
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
	// AuthStateGeneration records the generation this token's grant was authenticated
	// under. Rotation copies it from the PARENT token, never from the user's current
	// value, so an old grant cannot launder itself forward. Refresh validation reads
	// it from this row rather than from the joined Code, which is what lets a
	// preserved session's promoted tokens keep working. Tagged dont-update so an
	// ordinary full-row UpdateRefreshToken cannot regress it (#106).
	AuthStateGeneration int64 `db:"auth_state_generation" fieldtag:"dont-update"`
}
