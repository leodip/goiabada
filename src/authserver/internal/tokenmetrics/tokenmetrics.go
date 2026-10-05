// Package tokenmetrics counts, on the metrics listener, the tokens this server issues and the token
// requests it refuses (#400 decision 5): the issued by grant type, every grant the server issues
// included, and the refused by the grant the request named and the RFC 6749 section 5.2 error code
// it was answered with.
//
// Both labels are closed sets (#400 decision 4). A grant_type is the request's own parameter, so
// anything outside the grants this server redeems is recorded as other, and an error code outside
// section 5.2's and server_error is too; no client identifier or description reaches a label.
package tokenmetrics

import (
	"errors"

	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/core/metrics"
	"github.com/leodip/goiabada/core/oauth"
)

// serverError is the code the token endpoint answers any error that is not an *oauth.ErrorDetail
// with, which is what render's JSONError writes for one.
const serverError = "server_error"

// refusalCodes are the error codes RFC 6749 section 5.2 lists for a token request, and the
// server_error a fault is answered with.
var refusalCodes = []string{
	"invalid_request",
	"invalid_client",
	"invalid_grant",
	"unauthorized_client",
	"unsupported_grant_type",
	"invalid_scope",
	serverError,
}

// Recorder counts the token endpoint's answers and the implicit grant's issuance.
type Recorder struct {
	issued  *metrics.Counter
	refused *metrics.Counter
}

// Register registers the two token families on reg and returns the recorder that counts in them.
func Register(reg *metrics.Registry) *Recorder {
	var redeemed []string
	for _, grantType := range oidc.GrantTypesSupported() {
		if oidc.GrantType(grantType).AcceptedAtTokenEndpoint() {
			redeemed = append(redeemed, grantType)
		}
	}

	return &Recorder{
		issued: reg.Counter("goiabada_tokens_issued_total",
			"Token responses this server answered with, by the grant that issued them.",
			metrics.Enum("grant_type", oidc.GrantTypesSupported()...)),
		refused: reg.Counter("goiabada_token_requests_refused_total",
			"Token requests the token endpoint refused, by the grant they asked for and the error code they were answered with.",
			metrics.Enum("grant_type", redeemed...),
			metrics.Enum("error", refusalCodes...)),
	}
}

// Issued counts one token response issued under grantType.
func (r *Recorder) Issued(grantType oidc.GrantType) {
	r.issued.Inc(grantType.String())
}

// Refused counts one token request refused with err, under the grant it asked for and the error
// code err is answered with: its own when it is an *oauth.ErrorDetail, however wrapped, and
// server_error otherwise.
func (r *Recorder) Refused(grantType oidc.GrantType, err error) {
	code := serverError
	var detail *oauth.ErrorDetail
	if errors.As(err, &detail) {
		code = detail.Code()
	}
	r.refused.Inc(grantType.String(), code)
}
