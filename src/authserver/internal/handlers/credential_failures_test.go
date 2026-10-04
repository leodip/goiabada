package handlers

import (
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/middleware"
)

// noCredentialFailures stands in for the rate limiter in every case that is not about it.
//
// Hand-written rather than generated, and deliberately not a spy: asserting that a handler
// called RecordCredentialFailure would prove a call happened, not that the failure landed
// in the bucket the middleware reads, and those two are what the per-account tiers came
// apart on (#219). The cases that do care drive the handler through a real limiter instead.
type noCredentialFailures struct{}

func (noCredentialFailures) RecordCredentialFailure(r *http.Request) {}

// rateLimitTestRenderer is the ErrorRenderer a live limiter rejects browser routes through.
// It writes the status the bind map carries, which is the half of the real render.Renderer the
// cases below need: the status is what tells a refusal apart from a handler that ran.
type rateLimitTestRenderer struct{}

func (rateLimitTestRenderer) RenderTemplate(w http.ResponseWriter, r *http.Request, layoutName string,
	templateName string, data map[string]interface{}) error {

	if code, ok := data["_httpStatus"].(int); ok {
		w.WriteHeader(code)
	}
	return nil
}

// InternalServerError writes the 500 a credential tier whose shared count could not be read answers
// with. The limiter here counts in memory, which cannot fail, so no case reaches it.
func (rateLimitTestRenderer) InternalServerError(w http.ResponseWriter, r *http.Request, err error) {
	w.WriteHeader(http.StatusInternalServerError)
}

// newTestRateLimiter builds a live, enabled limiter for the cases that exercise a handler
// through it. A nil audit logger is the supported shape: the limiter skips the audit write
// and still emits its warning line and its rejection. It has no JSON writer, which LimitROPC
// writes through only for a form that does not parse, and no case here sends one.
func newTestRateLimiter(ceremonyStore CeremonyStore) *middleware.RateLimiter {
	return middleware.NewRateLimiter(ceremonyStore, rateLimitTestRenderer{}, nil, nil, true, nil)
}
