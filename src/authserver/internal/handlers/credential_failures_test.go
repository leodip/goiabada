package handlers

import (
	"net/http"

	core_middleware "github.com/leodip/goiabada/core/middleware"
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
// It writes the status the bind map carries, which is the half of the real HttpHelper the
// cases below need: the status is what tells a refusal apart from a handler that ran.
type rateLimitTestRenderer struct{}

func (rateLimitTestRenderer) RenderTemplate(w http.ResponseWriter, r *http.Request, layoutName string,
	templateName string, data map[string]interface{}) error {

	if code, ok := data["_httpStatus"].(int); ok {
		w.WriteHeader(code)
	}
	return nil
}

// newTestRateLimiter builds a live, enabled limiter for the cases that exercise a handler
// through it. A nil audit logger is the supported shape: the limiter skips the audit write
// and still emits its warning line and its rejection.
func newTestRateLimiter(authHelper core_middleware.AuthHelper) *core_middleware.RateLimiterMiddleware {
	return core_middleware.NewRateLimiterMiddleware(authHelper, rateLimitTestRenderer{}, nil, true)
}
