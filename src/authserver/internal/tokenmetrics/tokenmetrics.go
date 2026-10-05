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
	"net/http"

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

// ErrorWriter writes RFC 6749 section 5.2's error response for err: the JSON writer the token
// endpoint answers through.
type ErrorWriter interface {
	JSONError(w http.ResponseWriter, r *http.Request, err error)
}

// RefusalWriter is the token endpoint's error writer for the refusals written before its handler
// runs: the faults of the branch it is registered on, a settings or session read that failed or a
// panic, and LimitROPC's own, a body that does not parse or a credential count that could not be
// read. Each is counted as Refused counts the handler's, so the client's 400 or 500 is counted
// whichever of the two answered it, and once, since a request either stops before the handler or
// reaches it. A 429 is not written through it: it is the rate limiter's refusal, counted under its
// limiter.
type RefusalWriter struct {
	recorder *Recorder
	next     ErrorWriter
}

// Refusals returns next counting every refusal written through it.
func (r *Recorder) Refusals(next ErrorWriter) RefusalWriter {
	return RefusalWriter{recorder: r, next: next}
}

// JSONError counts the refusal under the grant the request's body names, then writes it.
//
// A fault met before anything parsed the body, the settings or the session failing, parses it here,
// so it too is counted under the grant it asked for. Nothing reads the body after a refusal, and it
// was bounded at the root by BodyLimit. A body that does not parse keeps the pairs that parsed
// before the malformed one, as the handler reads them.
func (w RefusalWriter) JSONError(rw http.ResponseWriter, r *http.Request, err error) {
	if r.PostForm == nil {
		_ = r.ParseForm()
	}
	w.recorder.Refused(oidc.GrantType(r.PostForm.Get("grant_type")), err)
	w.next.JSONError(rw, r, err)
}
