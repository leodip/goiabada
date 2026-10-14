package ceremony

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/sessionkeys"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/sessionstore"
)

// authSessionStore is what Store calls on the browser session store. Regenerate is in
// it, so a store that cannot rotate does not compile here, where it used to make
// RegenerateSession a silent no-op (#431). So is ChangeAndSave, the conditional write every
// step's save is made with, which only sessionstore.ConditionalStore has (#579).
type authSessionStore interface {
	Get(r *http.Request, name string) (*sessionstore.Session, error)
	Save(r *http.Request, w http.ResponseWriter, session *sessionstore.Session) error
	Regenerate(w http.ResponseWriter, r *http.Request, session *sessionstore.Session) error
	ChangeAndSave(r *http.Request, w http.ResponseWriter, session *sessionstore.Session,
		change func(values map[string]any) error) error
}

// Store keeps a browser's AuthContext in the server-side session, under
// sessionkeys.AuthContext, between the hops of one authorization ceremony. It was
// handlerhelpers.AuthHelper until #435 moved it beside the type it persists; the handlers reach it
// through their CeremonyStore port, and server.go's locale middleware through UILocales.
type Store struct {
	sessionStore authSessionStore
	sessionName  string
}

func NewStore(sessionStore authSessionStore, sessionName string) *Store {
	return &Store{
		sessionStore: sessionStore,
		sessionName:  sessionName,
	}
}

func (s *Store) GetAuthContext(r *http.Request) (*AuthContext, error) {
	sess, err := s.sessionStore.Get(r, s.sessionName)
	if err != nil {
		return nil, err
	}
	jsonData, ok := sess.Values[sessionkeys.AuthContext].(string)
	if !ok {
		return nil, ErrNoAuthContext
	}

	var authContext AuthContext
	err = json.Unmarshal([]byte(jsonData), &authContext)
	if err != nil {
		return nil, err
	}
	return &authContext, nil
}

// SaveAuthContext is every step's save after /auth/authorize, and it writes only while the
// browser session still holds the ceremony authContext names (#579). The step loaded its context
// when its request began, and another tab's /auth/authorize may have replaced it since, so the
// session is read afresh, its ceremony compared with this one, and the context written on
// condition nothing wrote the session in between, through ChangeAndSave. Anything else the session
// holds is kept as the fresh read found it, rather than put back as the request read it.
//
// It answers ErrCeremonyReplaced, writing nothing, when the session holds another ceremony, none,
// or is gone: the browser has moved on from this ceremony, and the newer one carries on. Ownership
// is the ceremony id, not the state, so two requests of one ceremony stay last-writer-wins between
// themselves, as a double-submitted consent form needs. An empty stored id is never owned, as
// ceremonyMatches refuses it.
func (s *Store) SaveAuthContext(w http.ResponseWriter, r *http.Request, authContext *AuthContext) error {
	jsonData, err := json.Marshal(authContext)
	if err != nil {
		return err
	}

	return s.changeOwnCeremony(w, r, authContext.CeremonyId, func(values map[string]any) {
		values[sessionkeys.AuthContext] = string(jsonData)
	})
}

// changeOwnCeremony applies change to the browser session as it is stored now, only while it holds
// the ceremony named, through ChangeAndSave: the one write SaveAuthContext and ClearAuthContext are
// made with. It answers ErrCeremonyReplaced, having written nothing, when the session holds another
// ceremony, none, or is gone.
func (s *Store) changeOwnCeremony(w http.ResponseWriter, r *http.Request, ceremonyId string,
	change func(values map[string]any)) error {

	sess, err := s.sessionStore.Get(r, s.sessionName)
	if err != nil {
		return err
	}

	err = s.sessionStore.ChangeAndSave(r, w, sess, func(values map[string]any) error {
		owned, ownedErr := holdsCeremony(values, ceremonyId)
		if ownedErr != nil {
			return ownedErr
		}
		if !owned {
			return errs.WithStack(ErrCeremonyReplaced)
		}
		change(values)
		return nil
	})
	if errors.Is(err, sessionstore.ErrNotFound) {
		// The session this step loaded is gone: signed out in another tab, rotated away by another
		// request of this browser, or expired. Its ceremony is not in the browser's session any
		// more, which is a replaced ceremony too, and ChangeAndSave has not put it back.
		return errs.Wrap(ErrCeremonyReplaced, "the browser session is gone")
	}
	return err
}

// holdsCeremony reports whether the session values a fresh read found hold the ceremony named.
func holdsCeremony(values map[string]any, ceremonyId string) (bool, error) {
	jsonData, ok := values[sessionkeys.AuthContext].(string)
	if !ok || ceremonyId == "" {
		return false, nil
	}
	var stored AuthContext
	if err := json.Unmarshal([]byte(jsonData), &stored); err != nil {
		return false, errs.Wrap(err, "unable to read the auth context the browser session holds")
	}
	return stored.CeremonyId == ceremonyId, nil
}

// ReplaceAuthContext is /auth/authorize's save. It starts a ceremony, so it replaces whatever the
// browser session held, the session's other values included, as every save did before #579.
func (s *Store) ReplaceAuthContext(w http.ResponseWriter, r *http.Request, authContext *AuthContext) error {
	sess, err := s.sessionStore.Get(r, s.sessionName)
	if err != nil {
		return err
	}

	jsonData, err := json.Marshal(authContext)
	if err != nil {
		return err
	}
	sess.Values[sessionkeys.AuthContext] = string(jsonData)
	return s.sessionStore.Save(r, w, sess)
}

// ClearAuthContext is a step's clear, which ends the ceremony only while the browser session still
// holds it, for SaveAuthContext's reason (#579). It answers ErrCeremonyReplaced, writing nothing, when
// the session holds another ceremony, none, or is gone, and a session never stored is one holding
// none, so the clear of a ceremony the browser does not hold creates no row and no cookie. Anything
// else the session holds is kept as the fresh read found it.
func (s *Store) ClearAuthContext(w http.ResponseWriter, r *http.Request, ceremonyId string) error {
	return s.changeOwnCeremony(w, r, ceremonyId, func(values map[string]any) {
		delete(values, sessionkeys.AuthContext)
	})
}

// DiscardAuthContext is /auth/authorize's clear, before it answers a request it refused at once. It
// ends whatever ceremony the browser session held, without a condition, as /auth/authorize's saves
// replace it. A browser with no stored session holds nothing to end, so nothing is written for it:
// no row holding nothing for the session's lifetime, and no cookie naming one (#579 decision 6).
func (s *Store) DiscardAuthContext(w http.ResponseWriter, r *http.Request) error {
	sess, err := s.sessionStore.Get(r, s.sessionName)
	if err != nil {
		return err
	}
	if sess.ID == "" {
		return nil
	}
	delete(sess.Values, sessionkeys.AuthContext)
	return s.sessionStore.Save(r, w, sess)
}

// RegenerateSession replaces the browser session's identifier, keeping its contents.
//
// Handlers reach rotation through here rather than through the store, so the one port that
// names Regenerate is this type's and sessionstore.Store stays Get and Save for the
// hundred places that take it (#266, #431).
func (s *Store) RegenerateSession(w http.ResponseWriter, r *http.Request) error {
	sess, err := s.sessionStore.Get(r, s.sessionName)
	if err != nil {
		return err
	}

	return s.sessionStore.Regenerate(w, r, sess)
}

func (s *Store) UILocales(r *http.Request) []string {
	authContext, err := s.GetAuthContext(r)
	if err != nil || authContext == nil || len(authContext.UILocales) == 0 {
		return nil
	}
	return authContext.UILocales
}
