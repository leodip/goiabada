package ceremony

import (
	"errors"

	"github.com/leodip/goiabada/core/oauth"
)

// ErrNoAuthContext is returned by GetAuthContext when the request's session holds no
// authorization ceremony. It is returned by identity, so errors.Is matches it by pointer as well
// as through ErrorDetail.Is.
//
// It declares the auth server's own failure: the admin console has no authorization ceremony and
// never reads one, which is why #385 moved it out of core/customerrors, and #435 moved it with the
// Store that returns it.
var ErrNoAuthContext = oauth.NewErrorDetail("no_auth_context", "no auth context in session")

// ErrCeremonyReplaced is SaveAuthContext's answer when the browser session no longer holds the
// ceremony the request loaded: another /auth/authorize replaced it, it ended, or the session is
// gone. Nothing was written, so the newer sign-in carries on (#579).
//
// A sentinel on stdlib errors.New, for the reason pattern 7 gives.
var ErrCeremonyReplaced = errors.New("the browser session no longer holds this ceremony")
