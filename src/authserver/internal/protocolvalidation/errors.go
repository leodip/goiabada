package protocolvalidation

import "github.com/leodip/goiabada/core/oauth"

// The comparison target the token validator constructs at the point of failure. Only this server
// issues or redeems a grant, so #385 moved it out of core/customerrors and beside the validator
// that produces it; the admin console never names it. ErrUserDisabled stood beside it until #437
// answered a disabled user's code or refresh token with the grant's generic wording, which no
// value can tell apart from the other refusals sharing it, and UserDisabledError replaced it.
var (
	// ErrCodeRedirectURIDeregistered is a comparison target: the token
	// validator constructs this same value when redeeming an authorization code whose own
	// redirect URI is no longer registered on the client, and errors.Is matches it by value
	// through oauth.ErrorDetail.Is.
	// That is what makes the audit decision and the wire message one fact rather than two
	// that can drift (#241 decision 10).
	//
	// The message is legible where every refusal around it is a flat "Code is invalid." Two
	// things pay for that. The check runs below client authentication and PKCE, so whoever
	// reads this has either authenticated as the client or proved possession of the verifier,
	// and it already submitted both the redirect URI and the client identifier, so nothing
	// here is news to them. And the person who needs to read it is an administrator who
	// rotated a callback while a code was outstanding: the generic "Invalid redirect_uri."
	// that a submitted-value mismatch returns also means "you sent one that differs from the
	// code's", so reusing it would leave them unable to tell which of the two happened.
	ErrCodeRedirectURIDeregistered = oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
		"The redirect URI recorded on this authorization code is no longer registered on the client, so the code can no longer be redeemed.", 400)
)
