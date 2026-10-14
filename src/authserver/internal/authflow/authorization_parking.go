package authflow

import (
	"context"
	"net/url"
	"slices"

	"github.com/leodip/goiabada/authserver/internal/authorizerequest"
)

// authorizeParkedParameters are the parameters a POST parks for its GET: every one Authorization.Run
// reads a value of, and request and request_uri, which it reads only to refuse. Everything else the
// browser sent is dropped rather than stored: nothing reads it, a login_hint is an address for
// whoever reads the table, and a row's size is then the size of what the endpoint uses. Not
// request_handle either, so a parked request can never name another (#246).
//
// TestAuthorizeParkedParameters_CoverEveryRead holds the list to authorization.go's reads, so a
// parameter read later cannot be left out and silently vanish between a POST and its GET.
var authorizeParkedParameters = append(slices.Clone(authorizeRequestParameters), "request", "request_uri")

// AuthorizeParkedParameters answers a copy of the parameters a POST parks for its GET.
func AuthorizeParkedParameters() []string {
	return slices.Clone(authorizeParkedParameters)
}

// parkedAuthorizeForm is what a POST parks: the parameters the endpoint reads, every copy of each,
// in the order they arrived.
func parkedAuthorizeForm(params url.Values) url.Values {
	form := make(url.Values, len(authorizeParkedParameters))
	for _, name := range authorizeParkedParameters {
		if values, ok := params[name]; ok {
			form[name] = slices.Clone(values)
		}
	}
	return form
}

// AuthorizationParking is POST /auth/authorize: it parks the request under a one-time handle for the
// GET the handler redirects to, where Authorization runs the ceremony from it (OIDC Core 1.0 section
// 3.1.2.1 requires the endpoint to accept a POST).
//
// The ceremony does not begin here, and nothing of the browser's own session is read or written. A
// POST from another site arrives without the SameSite=Lax session cookie, so a ceremony begun here
// would set a new cookie over the one the browser holds and lose the session it is signed in with,
// and a cross-site iframe could never see the session at all. The GET is a top-level safe
// navigation, which does carry the cookie, so SSO and prompt=none work over POST as over GET (#246).
// The route table builds one.
type AuthorizationParking struct {
	validator authorizeAddressValidator
	database  authorizerequest.Parking
}

// NewAuthorizationParking builds the operation over the request's address check and the database it
// parks requests in.
func NewAuthorizationParking(validator authorizeAddressValidator, database authorizerequest.Parking) *AuthorizationParking {
	return &AuthorizationParking{validator: validator, database: database}
}

// AuthorizationParkingResult is what AuthorizationParking.Run did: exactly one of PageRefusal and
// Handle is set.
type AuthorizationParkingResult struct {
	// PageRefusal is the refusal page the handler answers with. Nothing was parked.
	PageRefusal *AuthorizePageRefusal
	// Handle names the parked request, for the handler's redirect to the GET.
	Handle string
}

// Run, in order:
//
//  1. Answers the refusal page the GET would answer a request it cannot address
//     (refuseUnaddressableAuthorizeRequest), so a POST that could never begin a ceremony costs no
//     row. Whatever else the GET would refuse, it refuses when it runs the parked request.
//  2. Parks what the endpoint reads of params (parkedAuthorizeForm) and returns its handle.
//
// A failure of the address check that is no refusal, or of the insert, is returned as an error.
func (o *AuthorizationParking) Run(ctx context.Context, params url.Values, requestId string) (AuthorizationParkingResult, error) {
	pageRefusal, err := refuseUnaddressableAuthorizeRequest(ctx, o.validator, requestId, params)
	if err != nil {
		return AuthorizationParkingResult{}, err
	}
	if pageRefusal != nil {
		return AuthorizationParkingResult{PageRefusal: pageRefusal}, nil
	}

	handle, err := authorizerequest.Park(ctx, o.database, parkedAuthorizeForm(params))
	if err != nil {
		return AuthorizationParkingResult{}, err
	}
	return AuthorizationParkingResult{Handle: handle}, nil
}
