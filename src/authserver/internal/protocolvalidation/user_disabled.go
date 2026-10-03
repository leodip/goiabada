package protocolvalidation

import (
	"net/http"

	"github.com/leodip/goiabada/core/oauth"
)

// UserDisabledError is the token validator's refusal of a grant whose user is disabled. Detail is
// what the client is answered with, and Unwrap puts it on the chain, so the writer answers it as it
// answers any ErrorDetail; the type is what tells the token handler to write EventUserDisabled.
//
// A type rather than a sentinel matched by value, because a code or refresh grant's answer no
// longer names the condition (#137): it is that grant's generic refusal, which other failures
// return too, so its value cannot say which of them happened. oauth.ErrorDetail.Is compares
// the code, description and status, so a by-value match on "Code is invalid." would write the
// audit row for a superseded generation or a revoked code as well.
type UserDisabledError struct {
	Detail *oauth.ErrorDetail
}

func (e *UserDisabledError) Error() string {
	return e.Detail.Error()
}

// Unwrap puts Detail on the chain, as AuthCodeReusedError's does, so errors.As reaches the
// *oauth.ErrorDetail every writer and classifier in this tree matches with (#279).
func (e *UserDisabledError) Unwrap() error {
	return e.Detail
}

// userDisabled refuses a grant whose user is disabled, answering the client with description as
// invalid_grant (RFC 6749 section 5.2: the grant is no longer valid).
func userDisabled(description string) *UserDisabledError {
	return &UserDisabledError{
		Detail: oauth.NewErrorDetailWithHTTPStatus("invalid_grant", description, http.StatusBadRequest),
	}
}
