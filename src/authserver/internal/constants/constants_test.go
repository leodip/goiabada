package constants

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestConstants_PinTheValuesCoreWritesOut holds the two declarations that core/sessionstore's
// cutover matrix names as literals.
//
// That matrix runs both owners' session name and authenticated-session key against every state
// a browser can arrive in, and it lives in core, which may not import this module. So it writes
// the auth server's pair out by hand. Renaming either constant without touching the matrix would
// leave it asserting a session name this binary no longer uses, with nothing going red (#351).
func TestConstants_PinTheValuesCoreWritesOut(t *testing.T) {
	assert.Equal(t, "authserver", AuthServerSessionName)
	assert.Equal(t, "SessionIdentifier", SessionKeySessionIdentifier)
}

// TestConstants_SessionKeysAreStoredData holds the session key spellings, which are the map keys
// of a server-side session row. A live session carries the old spelling, so changing one here
// signs every logged-in user out at deploy rather than failing anywhere visible (#266).
func TestConstants_SessionKeysAreStoredData(t *testing.T) {
	assert.Equal(t, "SessionIdentifier", SessionKeySessionIdentifier)
	assert.Equal(t, "AuthContext", SessionKeyAuthContext)
	assert.Equal(t, "LinkMarker", SessionKeyLinkMarker)
}

// TestConstants_ErrorCodesAreWireValues holds the three OIDC authorization error codes, which a
// client matches on. They are fixed by OpenID Connect Core 1.0 section 3.1.2.6 rather than by
// this repository, so they are not ours to spell differently.
func TestConstants_ErrorCodesAreWireValues(t *testing.T) {
	assert.Equal(t, "login_required", ErrorLoginRequired)
	assert.Equal(t, "consent_required", ErrorConsentRequired)
	assert.Equal(t, "interaction_required", ErrorInteractionRequired)
}

// TestConstants_ContextKeysAreDistinct holds the three context keys apart. They are process-local
// and their values reach nothing outside this binary, but two keys sharing a value are one key,
// and a middleware writing settings under the validated token's key would be found only at the
// panic in whichever handler read it back.
func TestConstants_ContextKeysAreDistinct(t *testing.T) {
	keys := []ctxKey{ContextKeySettings, ContextKeySessionIdentifier, ContextKeyValidatedToken}

	seen := map[ctxKey]bool{}
	for _, k := range keys {
		assert.NotEmpty(t, string(k))
		assert.False(t, seen[k], "two context keys share the value %q", string(k))
		seen[k] = true
	}
}
