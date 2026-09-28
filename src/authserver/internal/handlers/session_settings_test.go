package handlers

import (
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/models"
)

// The two session lifetimes the ceremony handlers read from the request's settings and pass to
// HasValidUserSession, idle first. Distinct, so a stub pinning both fails a call site that
// swapped them (#433 decision 9).
const (
	testIdleTimeoutInSeconds = 1800
	testMaxLifetimeInSeconds = 43200
)

// withSessionSettings puts settings carrying the two lifetimes above on the request, where
// MiddlewareSettings puts them in production.
func withSessionSettings(r *http.Request) *http.Request {
	return withSettings(r, &models.Settings{
		UserSessionIdleTimeoutInSeconds: testIdleTimeoutInSeconds,
		UserSessionMaxLifetimeInSeconds: testMaxLifetimeInSeconds,
	})
}
