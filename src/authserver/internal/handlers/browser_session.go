package handlers

import (
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/usersession"
)

// browserSession is the per-request adapter an authflow operation writes the browser session
// through. It holds the response writer and the request of the one request it was built for, and
// passes both, unchanged, to every call it delegates, so a write lands on that request's response
// and runs under that request's context.
//
// A handler builds one for each request, at the point it calls its operation, and never stores it:
// an adapter on a shared struct would write one request's Set-Cookie onto another's response.
type browserSession struct {
	w             http.ResponseWriter
	r             *http.Request
	ceremonyStore CeremonyStore
	// userSessionManager is set only for /auth/completed, whose session start rotates the browser
	// session's identifier and writes the device cookie (newSessionStartingBrowserSession).
	userSessionManager UserSessionManager
}

func newBrowserSession(w http.ResponseWriter, r *http.Request, ceremonyStore CeremonyStore) *browserSession {
	return &browserSession{w: w, r: r, ceremonyStore: ceremonyStore}
}

// newSessionStartingBrowserSession is newBrowserSession for a step that also starts a user session.
func newSessionStartingBrowserSession(w http.ResponseWriter, r *http.Request, ceremonyStore CeremonyStore,
	userSessionManager UserSessionManager) *browserSession {

	return &browserSession{w: w, r: r, ceremonyStore: ceremonyStore, userSessionManager: userSessionManager}
}

// SaveAuthContext is CeremonyStore.SaveAuthContext, a step's conditional save.
func (b *browserSession) SaveAuthContext(authContext *ceremony.AuthContext) error {
	return b.ceremonyStore.SaveAuthContext(b.w, b.r, authContext)
}

// ClearAuthContext is CeremonyStore.ClearAuthContext, a step's conditional clear.
func (b *browserSession) ClearAuthContext(ceremonyId string) error {
	return b.ceremonyStore.ClearAuthContext(b.w, b.r, ceremonyId)
}

// RegenerateSession is CeremonyStore.RegenerateSession, a step's conditional rotation of the browser
// session's identifier.
func (b *browserSession) RegenerateSession(ceremonyId string) error {
	return b.ceremonyStore.RegenerateSession(b.w, b.r, ceremonyId)
}

// ConfirmCeremony is CeremonyStore.ConfirmCeremony, which writes nothing.
func (b *browserSession) ConfirmCeremony(ceremonyId string) error {
	return b.ceremonyStore.ConfirmCeremony(b.w, b.r, ceremonyId)
}

// StartNewUserSession is UserSessionManager.StartNewUserSession, the create arm's session start,
// which rotates the browser session's identifier onto the new session and writes the device cookie.
func (b *browserSession) StartNewUserSession(clientId int64, authentication usersession.Authentication,
	authStateGeneration int64, otpConfigGeneration *int64, ipAddress string, replacing *record.UserSession,
	limits usersession.SessionLimits) (*record.UserSession, []usersession.Removal, error) {

	return b.userSessionManager.StartNewUserSession(b.w, b.r, clientId, authentication, authStateGeneration,
		otpConfigGeneration, ipAddress, replacing, limits)
}
