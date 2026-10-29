package record

import "time"

// RevokedAccessToken is the record that one access token without a grant was revoked at
// /auth/revoke (#676 decision 1). A token of the client credentials grant or the implicit flow
// carries no grant_id, so no refresh token family stands behind it to end; its jti is stored
// instead, and the access-token liveness check refuses it while the row exists.
//
// There is no id: the jti is the key, and a token is revoked once. ExpiresAt is the token's own
// exp, past which the row has nothing left to refuse and the background worker deletes it.
type RevokedAccessToken struct {
	Jti       string    `db:"jti"`
	ExpiresAt time.Time `db:"expires_at"`
}
