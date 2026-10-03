package record

import "time"

// RefreshTokenFamilyRevocation is the durable record that one refresh token rotation family is
// revoked (#132, #259, #437). A family is the refresh tokens sharing a first_refresh_token_jti,
// and the record outlives every member: a rotation that claimed its parent and has not yet
// inserted its child holds no live row for a sweep to find, so the family is marked here and the
// child is refused when it arrives.
//
// There is no id: the first token's jti is the key, and a family is revoked once.
type RefreshTokenFamilyRevocation struct {
	FirstRefreshTokenJti string    `db:"first_refresh_token_jti"`
	Reason               string    `db:"reason"`
	RevokedAt            time.Time `db:"revoked_at"`
}
