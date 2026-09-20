package handlerhelpers

import "github.com/leodip/goiabada/core/customerrors"

// ErrNoAuthContext is returned by GetAuthContext when the request's session holds no
// authorization ceremony. It is returned by identity, so errors.Is matches it by pointer as well
// as through ErrorDetail.Is.
//
// It declares the auth server's own failure: the admin console has no authorization ceremony and
// never reads one, which is why #385 moved it out of core/customerrors and beside the helper that
// returns it.
var ErrNoAuthContext = customerrors.NewErrorDetail("no_auth_context", "no auth context in session")
