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
// "Code is invalid.", 400). Callers should pass Detail to JsonError, not the
// wrapper itself: HttpHelper.JsonError only special-cases *ErrorDetail.
type AuthCodeReusedError struct {
	Detail *ErrorDetail
	Code   *models.Code
}

func (e *AuthCodeReusedError) Error() string {
	return e.Detail.Error()
}
