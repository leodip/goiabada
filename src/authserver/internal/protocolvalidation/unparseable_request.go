package protocolvalidation

import (
	"net/http"

	"github.com/leodip/goiabada/core/oauth"
)

// UnparseableRequest is the token endpoint's answer to a request whose form does not parse: a
// url-encoding broken by the client, or a body cut at the request-body limit. That is the client's
// malformed request, RFC 6749 section 5.2's invalid_request, and never a server fault (#426).
//
// Two places answer it, because whichever parses the form first is the one that sees the failure:
// LimitROPC when the rate limiter is on, HandleTokenPost when it is off. net/http keeps the pairs
// that did parse and answers a second ParseForm with nil, so the second reader can never see it. Both
// call this, so the two answers cannot drift apart (#228, #437).
func UnparseableRequest() *oauth.ErrorDetail {
	return oauth.NewErrorDetailWithHTTPStatus("invalid_request",
		"The request body could not be parsed.", http.StatusBadRequest)
}
