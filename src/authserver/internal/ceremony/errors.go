package ceremony

import (
	"errors"

	"github.com/leodip/goiabada/core/oauth"
)

// ErrNoAuthContext is returned by GetAuthContext and LatestAuthContext when the request's session
// holds no authorization ceremony at all. It is returned by identity, so errors.Is matches it by pointer as well
// as through ErrorDetail.Is.
//
// It declares the auth server's own failure: the admin console has no authorization ceremony and
// never reads one, which is why #385 moved it out of core/customerrors, and #435 moved it with the
// Store that returns it.
var ErrNoAuthContext = oauth.NewErrorDetail("no_auth_context", "no auth context in session")

// ErrCeremonyReplaced is a step's write's answer when the browser session no longer holds the
// ceremony the request loaded: another request of it ended it, newer sign-ins pushed it out
// (MaxHeldCeremonies), or the session is gone. Nothing was written, so the sign-ins the browser holds
// carry on (#579, #246).
//
// A sentinel on stdlib errors.New, for the reason pattern 7 gives.
var ErrCeremonyReplaced = errors.New("the browser session no longer holds this ceremony")

// ErrCeremonyNotHeld is GetAuthContext's answer when the browser session holds a ceremony but not the
// one the request names (RequestedId), or the request names none. The step boundary answers it with
// the "no longer active" page and the ceremony mismatch audit event, apart from a session holding no
// ceremony at all, ErrNoAuthContext, which is sent to the account page.
//
// A sentinel on stdlib errors.New, for the reason pattern 7 gives.
var ErrCeremonyNotHeld = errors.New("the browser session does not hold the ceremony the request names")
