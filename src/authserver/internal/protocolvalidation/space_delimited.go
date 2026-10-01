package protocolvalidation

import (
	"fmt"
	"net/http"

	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/oauth"
)

// ValidateSpaceDelimited refuses a space-delimited parameter whose value is not well formed
// (oauth.IsWellFormedSpaceDelimited): a run of spaces between two values, or a space before the
// first or after the last. errorCode is the code the parameter's other refusals use, invalid_scope
// for scope, which RFC 6749 4.1.2.1 and 5.2 name for a scope that is "malformed", and
// invalid_request for response_type and prompt. The description names the parameter and never its
// value. An empty value is accepted: it is an omitted parameter, which the caller answers itself.
//
// One refusal for the three parameters a malformed value is refused for, at both endpoints, so the
// rule has one wording wherever a client meets it. acr_values and ui_locales are not among them:
// OIDC Core 1.0 makes both a request the server may decline to honour, and each reader treats a
// malformed one as absent (#244).
func ValidateSpaceDelimited(parameter, errorCode, value string) error {
	if oauth.IsWellFormedSpaceDelimited(value) {
		return nil
	}
	return customerrors.NewErrorDetailWithHttpStatusCode(errorCode,
		fmt.Sprintf("The '%v' parameter is malformed. Separate its values with a single space, with no space before the first value or after the last.", parameter),
		http.StatusBadRequest)
}
