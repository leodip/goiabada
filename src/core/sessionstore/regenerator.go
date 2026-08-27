package sessionstore

import (
	"net/http"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
)

// Regenerator is implemented by a store whose identifier can be replaced without losing
// the session's contents.
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
// sessions.Store has no such method, so callers reach it by asserting to this interface
// rather than by widening the interface every handler already takes.
type Regenerator interface {
	Regenerate(w http.ResponseWriter, r *http.Request, session *sessions.Session) error
}

// Regenerate writes the session's current contents under a fresh identifier, removes the
// row the old identifier named, and only then tells the browser about the new one.
//
// The order is the whole point, and it is not the obvious one. A Set-Cookie already
// written is not retracted by a later failure: a handler that sets a cookie and then
// answers 500 still ships the cookie. So writing the new cookie before deleting the old
// row would mean a failed deletion leaves the old identifier live AND the browser
// already moved on, which is precisely the state rotation exists to prevent. New row,
// old row gone, then the cookie. Every failure before that last step returns an error
// and emits no header at all, so the failing direction is a user who loses a session
// rather than an attacker who keeps one.
func (s *ServerSideStore) Regenerate(w http.ResponseWriter, r *http.Request, session *sessions.Session) error {
	encoded, err := securecookie.EncodeMulti(session.Name(), session.Values, s.Codecs...)
	if err != nil {
		return errors.Wrap(err, "unable to encode the browser session")
	}

	newId, err := newSessionId()
	if err != nil {
		return err
	}

	ctx := requestContext(r)
	authenticated := s.isAuthenticated(session)

	expiresAt, err := s.Backend.Create(ctx, newId, []byte(encoded), authenticated)
	if err != nil {
		return errors.Wrap(err, "unable to create the rotated browser session")
	}

	if oldId := session.ID; oldId != "" {
		if err := s.Backend.Delete(ctx, oldId); err != nil {
			return errors.Wrap(err, "unable to delete the browser session being rotated away")
		}
	}

	session.ID = newId
	session.IsNew = false
	return s.setCookie(w, session, newId, expiresAt)
}
