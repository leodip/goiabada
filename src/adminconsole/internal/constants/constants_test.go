package constants

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestContextKeySettings_IsDeclaredAndNonEmpty holds the admin console's own settings key.
//
// It carries the same spelling as the auth server's deliberately, and the two are not asserted
// against each other because they are not the same key: a context key never leaves the process
// that set it, and the two processes store different types under this one (#351).
func TestContextKeySettings_IsDeclaredAndNonEmpty(t *testing.T) {
	assert.Equal(t, "Settings", string(ContextKeySettings))
}

// TestConstants_PinTheValuesCoreWritesOut holds the one declaration core/sessionstore's cutover
// matrix names as a literal.
//
// That matrix runs both owners' session name and authenticated-session key against every state a
// browser can arrive in, and it lives in core, which may not import this module. So it writes
// SessionKeyJwt out by hand, as it already did for the auth server's pair. Renaming the constant
// without touching the matrix would leave it asserting a key this binary no longer uses, with
// nothing going red (#351, #385).
func TestConstants_PinTheValuesCoreWritesOut(t *testing.T) {
	assert.Equal(t, "Jwt", SessionKeyJwt)
}

// TestConstants_SessionKeysAreStoredData holds the session key spellings, which are the map keys of
// a server-side session row. A live session carries the old spelling, so changing one here signs
// every logged-in administrator out at deploy rather than failing anywhere visible. The five
// ceremony keys are the same kind of stored data: a sign-in in flight across the deploy reads them
// back at the callback (#266, #385).
func TestConstants_SessionKeysAreStoredData(t *testing.T) {
	assert.Equal(t, "Jwt", SessionKeyJwt)
	assert.Equal(t, "State", SessionKeyState)
	assert.Equal(t, "Nonce", SessionKeyNonce)
	assert.Equal(t, "RedirectURI", SessionKeyRedirectURI)
	assert.Equal(t, "CodeVerifier", SessionKeyCodeVerifier)
	assert.Equal(t, "RedirectBack", SessionKeyRedirectBack)
	assert.Equal(t, "JwtExpiresAt", SessionKeyJwtExpiresAt)
	assert.Equal(t, "RequestedScope", SessionKeyRequestedScope)
}
