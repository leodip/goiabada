package sessionstore

import (
	"net/http"

	"github.com/leodip/goiabada/core/errs"
)

// Regenerate writes the session's current contents under a fresh identifier, removes the
// row the old identifier named, and only then tells the browser about the new one.
//
// Rotation at every privilege change is what a server-side store must add to match a
// cookie store's structural immunity to session fixation. A cookie store is immune
// because the cookie IS the state: an attacker's planted copy stays the attacker's own
// stale state and never becomes the victim's session. A row is not immune, because a
// planted identifier names a row that the victim's sign-in then fills in. Rotating at
// sign-in is what puts that immunity back, and rotating again at a step-up means an
// identifier stolen at one authentication level stops working the moment the session
// reaches a higher one (#266).
//
// It is not on Store. Each consumer that rotates declares a port naming it, so a store
// that cannot rotate does not compile there; an optional interface asserted at run time
// let a missing rotation fall back to a plain save without anything noticing (#431).
//
// The order is the whole point, and it is not the obvious one. A Set-Cookie already
// written is not retracted by a later failure: a handler that sets a cookie and then
// answers 500 still ships the cookie. So writing the new cookie before deleting the old
// row would mean a failed deletion leaves the old identifier live AND the browser
// already moved on, which is precisely the state rotation exists to prevent. New row,
// old row gone, then the cookie. Every failure before that last step returns an error
// and emits no header at all, so the failing direction is a user who loses a session
// rather than an attacker who keeps one.
func (s *ServerSideStore) Regenerate(w http.ResponseWriter, r *http.Request, session *Session) error {
	encoded, err := s.sealSessionData(session)
	if err != nil {
		return err
	}

	newId, err := s.newSessionId()
	if err != nil {
		return err
	}

	ctx := requestContext(r)
	authenticated := s.isAuthenticated(session)

	expiresAt, err := s.backend.Create(ctx, newId, []byte(encoded), authenticated)
	if err != nil {
		return errs.Wrap(err, "unable to create the rotated browser session")
	}

	if oldId := session.ID; oldId != "" {
		if err := s.backend.Delete(ctx, oldId); err != nil {
			return errs.Wrap(err, "unable to delete the browser session being rotated away")
		}
	}

	session.ID = newId
	session.IsNew = false
	return s.setCookie(w, session, newId, expiresAt)
}
