package sessionkeys

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSessionKeys_PinTheValuesCoreWritesOut holds the two declarations that core/sessionstore's
// cutover matrix names as literals.
//
// That matrix runs both owners' session name and authenticated-session key against every state
// a browser can arrive in, and it lives in core, which may not import this module. So it writes
// the auth server's pair out by hand. Renaming either constant without touching the matrix would
// leave it asserting a session name this binary no longer uses, with nothing going red (#351).
func TestSessionKeys_PinTheValuesCoreWritesOut(t *testing.T) {
	assert.Equal(t, "authserver", AuthServerSessionName)
	assert.Equal(t, "SessionIdentifier", SessionKeySessionIdentifier)
}

// TestSessionKeys_AreStoredData holds the session key spellings, which are the map keys of a
// server-side session row. A live session carries the old spelling, so changing one here signs
// every logged-in user out at deploy rather than failing anywhere visible (#266).
func TestSessionKeys_AreStoredData(t *testing.T) {
	assert.Equal(t, "SessionIdentifier", SessionKeySessionIdentifier)
	assert.Equal(t, "AuthContext", SessionKeyAuthContext)
	assert.Equal(t, "LinkMarker", SessionKeyLinkMarker)
}
