package accounthandlers

import (
	"context"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/legaldocuments"
)

// heldCeremonies is the sign-ins a test's browser holds, by ceremony id.
type heldCeremonies map[string]*ceremony.AuthContext

func (h heldCeremonies) HeldAuthContext(_ *http.Request, ceremonyId string) (*ceremony.AuthContext, error) {
	if len(h) == 0 {
		return nil, ceremony.ErrNoAuthContext
	}
	authContext, ok := h[ceremonyId]
	if !ok {
		return nil, ceremony.ErrCeremonyNotHeld
	}
	return authContext, nil
}

// legalDocumentsInEffect answers the documents in effect a test sets: allApps for every client, and
// each client's own besides.
type legalDocumentsInEffect struct {
	allApps  []legaldocuments.InEffect
	byClient map[string][]legaldocuments.InEffect
	err      error
	// asked records the client identifier each read was for.
	asked *[]string
}

func (l legalDocumentsInEffect) ForClient(_ context.Context, clientIdentifier string) ([]legaldocuments.InEffect, error) {
	if l.asked != nil {
		*l.asked = append(*l.asked, clientIdentifier)
	}
	if l.err != nil {
		return nil, l.err
	}
	return append(append([]legaldocuments.InEffect{}, l.allApps...), l.byClient[clientIdentifier]...), nil
}
