package customerrors

import "github.com/leodip/goiabada/core/models"

// AuthCodeReusedError is the sentinel returned by the token validator when an
// authorization-code grant is replayed AND the request authenticated against
// the previously-used code (correct client_id, redirect_uri, client_secret if
// confidential, and matching code_verifier if PKCE was used).
//
// The validator does NOT itself revoke anything; the handler is responsible
// for reading Code and revoking the linked refresh tokens and user session.
//
// Detail is the *ErrorDetail to render to the client (invalid_grant,
// "Code is invalid.", 400), and Unwrap exposes it, so HttpHelper.JsonError answers 400 with that
// description whether it is handed this wrapper or the Detail inside it. The handler still passes
// Detail, because it reads Code first and revoking is what it is here to do; the difference is that
// passing the wrapper is no longer a silent 500 (#279).
type AuthCodeReusedError struct {
	Detail *ErrorDetail
	Code   *models.Code
}

func (e *AuthCodeReusedError) Error() string {
	return e.Detail.Error()
}

// Unwrap puts Detail on the chain, so errors.As reaches the *ErrorDetail and errors.Is reaches the
// sentinels it equals. Every writer and every classifier in this tree matches with those two
// (#279), and a wrapper that does not unwrap is invisible to both.
func (e *AuthCodeReusedError) Unwrap() error {
	return e.Detail
}
