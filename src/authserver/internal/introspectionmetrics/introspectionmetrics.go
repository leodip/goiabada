// Package introspectionmetrics counts, on the metrics listener, the requests the introspection
// endpoint answers, by their outcome (#676 decision 11). The outcome is a closed set, so no client
// identifier or token reaches a label.
package introspectionmetrics

import "github.com/leodip/goiabada/core/metrics"

// Outcome is how the introspection endpoint answered one request.
type Outcome string

const (
	// Active is a token answered active to its caller.
	Active Outcome = "active"
	// Inactive is a token answered {"active": false}: not live, or not one the caller may
	// introspect (RFC 7662 section 2.2).
	Inactive Outcome = "inactive"
	// Refused is a request answered with an error the client caused: its authentication failed, it
	// is a public client, or the request was malformed.
	Refused Outcome = "refused"
	// Error is a fault, answered 500, never as an inactive token (#676 decision 13).
	Error Outcome = "error"
)

// Recorder counts the introspection endpoint's answers.
type Recorder struct {
	requests *metrics.Counter
}

// Register registers the introspection family on reg and returns the recorder that counts in it.
func Register(reg *metrics.Registry) *Recorder {
	return &Recorder{
		requests: reg.Counter("goiabada_introspection_requests_total",
			"Requests the token introspection endpoint answered, by their outcome.",
			metrics.Enum("outcome", string(Active), string(Inactive), string(Refused), string(Error))),
	}
}

// Count counts one request answered with outcome.
func (r *Recorder) Count(outcome Outcome) {
	r.requests.Inc(string(outcome))
}
