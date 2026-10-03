package sessionkeys

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSessionKeys_PinTheValuesCoreWritesOut holds the one declaration core/sessionstore's cutover
// matrix names as a literal.
//
// That matrix runs both owners' session name and authenticated-session key against every state a
// browser can arrive in, and it lives in core, which may not import this module. So it writes
// JWT's value out by hand, as it already did for the auth server's pair. Renaming the constant
// without touching the matrix would leave it asserting a key this binary no longer uses, with
// nothing going red (#351, #385).
func TestSessionKeys_PinTheValuesCoreWritesOut(t *testing.T) {
	assert.Equal(t, "Jwt", JWT)
}

// TestSessionKeys_AreStoredData holds the session key spellings, which are the map keys of a
// server-side session row. A live session carries the old spelling, so changing one here signs
// every logged-in administrator out at deploy rather than failing anywhere visible. The five
// ceremony keys are the same kind of stored data: a sign-in in flight across the deploy reads them
// back at the callback (#266, #385).
func TestSessionKeys_AreStoredData(t *testing.T) {
	assert.Equal(t, "Jwt", JWT)
	assert.Equal(t, "State", State)
	assert.Equal(t, "Nonce", Nonce)
	assert.Equal(t, "RedirectURI", RedirectURI)
	assert.Equal(t, "CodeVerifier", CodeVerifier)
	assert.Equal(t, "RedirectBack", RedirectBack)
	assert.Equal(t, "JwtExpiresAt", JWTExpiresAt)
	assert.Equal(t, "RequestedScope", RequestedScope)
}
