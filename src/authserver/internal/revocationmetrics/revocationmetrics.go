// Package revocationmetrics counts, on the metrics listener, the requests the revocation endpoint
// answers, by their outcome (#676 decision 11). The outcome is a closed set, so no client identifier
// or token reaches a label.
package revocationmetrics

import "github.com/leodip/goiabada/core/metrics"

// Outcome is how the revocation endpoint answered one request.
type Outcome string

const (
	// Revoked is a grant, or an access token without one, the client ended, answered 200.
	Revoked Outcome = "revoked"
	// InvalidToken is a token that was not live, answered 200 with nothing revoked (RFC 7009
	// section 2.2).
	InvalidToken Outcome = "invalid_token"
	// Refused is a request answered with an error the client caused: its authentication failed, the
	// request was malformed, or the token was another client's.
	Refused Outcome = "refused"
	// Error is a fault, answered 503, on which the client assumes the token still exists and retries
	// (RFC 7009 section 2.2.1).
	Error Outcome = "error"
)

// Recorder counts the revocation endpoint's answers.
type Recorder struct {
	requests *metrics.Counter
}

// Register registers the revocation family on reg and returns the recorder that counts in it.
func Register(reg *metrics.Registry) *Recorder {
	return &Recorder{
		requests: reg.Counter("goiabada_revocation_requests_total",
			"Requests the token revocation endpoint answered, by their outcome.",
			metrics.Enum("outcome", string(Revoked), string(InvalidToken), string(Refused), string(Error))),
	}
}

// Count counts one request answered with outcome.
func (r *Recorder) Count(outcome Outcome) {
	r.requests.Inc(string(outcome))
}
