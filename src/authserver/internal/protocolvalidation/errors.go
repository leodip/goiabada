package protocolvalidation

import "github.com/leodip/goiabada/core/customerrors"

// The three comparison targets the token validator constructs at the point of failure. Only this
// server issues or redeems a grant, so #385 moved them out of core/customerrors and beside the
// validator that produces each; the admin console names none of them.
var (
	ErrUserDisabled = customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
		"The user account is disabled.", 400)
	// ErrClientDisabled is a comparison target, like ErrUserDisabled: the token validator
	// constructs this same value and errors.Is matches it by value through
	// customerrors.ErrorDetail.Is.
	//
	// It exists because it is the one invalid_grant a password grant can produce without any
	// credential having been read. The check runs before the grant-type switch, so treating
	// every invalid_grant on a password grant as a guess against the account would charge an
	// account's failure budget, and write a ropc_auth_failed audit row naming a username
	// nothing ever compared, for a request that merely named a disabled client (#219).
	ErrClientDisabled = customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
		"Client is disabled.", 400)
	// ErrCodeRedirectURIDeregistered is a comparison target, like the two above: the token
	// validator constructs this same value when redeeming an authorization code whose own
	// redirect URI is no longer registered on the client, and errors.Is matches it by value
	// through customerrors.ErrorDetail.Is.
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
	ErrCodeRedirectURIDeregistered = customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
		"The redirect URI recorded on this authorization code is no longer registered on the client, so the code can no longer be redeemed.", 400)
)
