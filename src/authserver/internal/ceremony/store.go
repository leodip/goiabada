package ceremony

import (
	"encoding/json"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/sessionkeys"
	"github.com/leodip/goiabada/core/sessionstore"
)

// authSessionStore is what Store calls on the browser session store. Regenerate is in
// it, so a store that cannot rotate does not compile here, where it used to make
// RegenerateSession a silent no-op (#431).
type authSessionStore interface {
	Get(r *http.Request, name string) (*sessionstore.Session, error)
	Save(r *http.Request, w http.ResponseWriter, session *sessionstore.Session) error
	Regenerate(w http.ResponseWriter, r *http.Request, session *sessionstore.Session) error
}

// Store keeps a browser's AuthContext in the server-side session, under
// sessionkeys.SessionKeyAuthContext, between the hops of one authorization ceremony. It was
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
	jsonData, ok := sess.Values[sessionkeys.SessionKeyAuthContext].(string)
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

func (s *Store) SaveAuthContext(w http.ResponseWriter, r *http.Request, authContext *AuthContext) error {

	sess, err := s.sessionStore.Get(r, s.sessionName)
	if err != nil {
		return err
	}

	jsonData, err := json.Marshal(authContext)
	if err != nil {
		return err
	}
	sess.Values[sessionkeys.SessionKeyAuthContext] = string(jsonData)
	err = s.sessionStore.Save(r, w, sess)
	if err != nil {
		return err
	}

	return nil
}

func (s *Store) ClearAuthContext(w http.ResponseWriter, r *http.Request) error {

	sess, err := s.sessionStore.Get(r, s.sessionName)
	if err != nil {
		return err
	}
	delete(sess.Values, sessionkeys.SessionKeyAuthContext)
	err = s.sessionStore.Save(r, w, sess)
	if err != nil {
		return err
	}

	return nil
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
