package handlers

import (
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/usersession"
)

// The two session lifetimes the ceremony handlers read from the request's settings and pass to
// HasValidUserSession, idle first. Distinct, so a stub pinning both fails a call site that
// swapped them (#433 decision 9). The per-user session cap beside them is distinct from both too,
// for the create arm, which passes all three to StartNewUserSession (#564 decision 5).
const (
	testIdleTimeoutInSeconds   = 1800
	testMaxLifetimeInSeconds   = 43200
	testMaxUserSessionsPerUser = 17
)

// testSessionLimits is the three values above as the create arm hands them to StartNewUserSession.
var testSessionLimits = usersession.SessionLimits{
	IdleTimeoutInSeconds: testIdleTimeoutInSeconds,
	MaxLifetimeInSeconds: testMaxLifetimeInSeconds,
	MaxSessionsPerUser:   testMaxUserSessionsPerUser,
}

// withSessionSettings puts settings carrying the three values above on the request, where
// middleware.Settings puts them in production, with testResponseIssuer as the issuer every
// authorization response carries.
func withSessionSettings(r *http.Request) *http.Request {
	return withSettings(r, &record.Settings{
		Issuer:                          testResponseIssuer,
		UserSessionIdleTimeoutInSeconds: testIdleTimeoutInSeconds,
		UserSessionMaxLifetimeInSeconds: testMaxLifetimeInSeconds,
		MaxUserSessionsPerUser:          testMaxUserSessionsPerUser,
	})
}
