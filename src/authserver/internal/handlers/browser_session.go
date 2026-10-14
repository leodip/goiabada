package handlers

import (
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
)

// browserSession is the per-request adapter an authflow operation writes the browser session
// through. It holds the response writer and the request of the one request it was built for, and
// passes both, unchanged, to every call it delegates to the ceremony store, so a write lands on that
// request's response and runs under that request's context.
//
// A handler builds one for each request, at the point it calls its operation, and never stores it:
// an adapter on a shared struct would write one request's Set-Cookie onto another's response.
type browserSession struct {
	w             http.ResponseWriter
	r             *http.Request
	ceremonyStore CeremonyStore
}

func newBrowserSession(w http.ResponseWriter, r *http.Request, ceremonyStore CeremonyStore) *browserSession {
	return &browserSession{w: w, r: r, ceremonyStore: ceremonyStore}
}

// SaveAuthContext is CeremonyStore.SaveAuthContext, a step's conditional save.
func (b *browserSession) SaveAuthContext(authContext *ceremony.AuthContext) error {
	return b.ceremonyStore.SaveAuthContext(b.w, b.r, authContext)
}

// ClearAuthContext is CeremonyStore.ClearAuthContext, a step's conditional clear.
func (b *browserSession) ClearAuthContext(ceremonyId string) error {
	return b.ceremonyStore.ClearAuthContext(b.w, b.r, ceremonyId)
}
