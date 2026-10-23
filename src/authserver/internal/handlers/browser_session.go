package handlers

import (
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
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
	// deviceCookie is set only for /auth/completed, whose create arm records the browser's device on
	// the session it starts and writes the device cookie (newSessionStartingBrowserSession).
	deviceCookie *DeviceCookie
	// credentialFailures is set only for a step that checks a credential
	// (newCredentialCheckingBrowserSession).
	credentialFailures CredentialFailureRecorder
}

func newBrowserSession(w http.ResponseWriter, r *http.Request, ceremonyStore CeremonyStore) *browserSession {
	return &browserSession{w: w, r: r, ceremonyStore: ceremonyStore}
}

// newSessionStartingBrowserSession is newBrowserSession for a step that also starts a user session.
func newSessionStartingBrowserSession(w http.ResponseWriter, r *http.Request, ceremonyStore CeremonyStore,
	deviceCookie *DeviceCookie) *browserSession {

	return &browserSession{w: w, r: r, ceremonyStore: ceremonyStore, deviceCookie: deviceCookie}
}

// newCredentialCheckingBrowserSession is newBrowserSession for a step that checks a credential, whose
// refusals are charged to the rate limiter.
func newCredentialCheckingBrowserSession(w http.ResponseWriter, r *http.Request, ceremonyStore CeremonyStore,
	credentialFailures CredentialFailureRecorder) *browserSession {

	return &browserSession{w: w, r: r, ceremonyStore: ceremonyStore, credentialFailures: credentialFailures}
}

// SaveAuthContext is CeremonyStore.SaveAuthContext, a step's conditional save.
func (b *browserSession) SaveAuthContext(authContext *ceremony.AuthContext) error {
	return b.ceremonyStore.SaveAuthContext(b.w, b.r, authContext)
}

// ClearAuthContext is CeremonyStore.ClearAuthContext, a step's conditional clear.
func (b *browserSession) ClearAuthContext(ceremonyId string) error {
	return b.ceremonyStore.ClearAuthContext(b.w, b.r, ceremonyId)
}

// ReplaceAuthContext is CeremonyStore.ReplaceAuthContext, /auth/authorize's save, which replaces
// whatever ceremony the browser session held.
func (b *browserSession) ReplaceAuthContext(authContext *ceremony.AuthContext) error {
	return b.ceremonyStore.ReplaceAuthContext(b.w, b.r, authContext)
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

// RegenerateSessionAndBind is CeremonyStore.RegenerateSessionAndBind, the create arm's conditional
// rotation, which binds the user session it started to the browser session.
func (b *browserSession) RegenerateSessionAndBind(ceremonyId string, userSessionIdentifier string) error {
	return b.ceremonyStore.RegenerateSessionAndBind(b.w, b.r, ceremonyId, userSessionIdentifier)
}

// Device is the browser this request comes from, as its device cookie and headers say.
func (b *browserSession) Device() usersession.Device {
	return b.deviceCookie.read(b.r)
}

// WriteDeviceCookie gives the browser its device identifier, on this request's response.
func (b *browserSession) WriteDeviceCookie(identifier string) {
	b.deviceCookie.write(b.w, identifier)
}

// RecordCredentialFailure is CredentialFailureRecorder.RecordCredentialFailure on this request, whose
// context carries the reservation the rate limiter placed before the handler ran.
func (b *browserSession) RecordCredentialFailure() {
	b.credentialFailures.RecordCredentialFailure(b.r)
}
