package handlerhelpers

import (
	"encoding/json"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/core/sessionstore"
)

// authSessionStore is what AuthHelper calls on the browser session store. Regenerate is in
// it, so a store that cannot rotate does not compile here, where it used to make
// RegenerateSession a silent no-op (#431).
type authSessionStore interface {
	Get(r *http.Request, name string) (*sessionstore.Session, error)
	Save(r *http.Request, w http.ResponseWriter, session *sessionstore.Session) error
	Regenerate(w http.ResponseWriter, r *http.Request, session *sessionstore.Session) error
}

type AuthHelper struct {
	sessionStore authSessionStore
	sessionName  string
}

func NewAuthHelper(sessionStore authSessionStore, sessionName string) *AuthHelper {
	return &AuthHelper{
		sessionStore: sessionStore,
		sessionName:  sessionName,
	}
}

func (s *AuthHelper) GetAuthContext(r *http.Request) (*ceremony.AuthContext, error) {
	sess, err := s.sessionStore.Get(r, s.sessionName)
	if err != nil {
		return nil, err
	}
	jsonData, ok := sess.Values[constants.SessionKeyAuthContext].(string)
	if !ok {
		return nil, ErrNoAuthContext
	}

	var authContext ceremony.AuthContext
	err = json.Unmarshal([]byte(jsonData), &authContext)
	if err != nil {
		return nil, err
	}
	return &authContext, nil
}

func (s *AuthHelper) SaveAuthContext(w http.ResponseWriter, r *http.Request, authContext *ceremony.AuthContext) error {

	sess, err := s.sessionStore.Get(r, s.sessionName)
	if err != nil {
		return err
	}

	jsonData, err := json.Marshal(authContext)
	if err != nil {
		return err
	}
	sess.Values[constants.SessionKeyAuthContext] = string(jsonData)
	err = s.sessionStore.Save(r, w, sess)
	if err != nil {
		return err
	}

	return nil
}

func (s *AuthHelper) ClearAuthContext(w http.ResponseWriter, r *http.Request) error {

	sess, err := s.sessionStore.Get(r, s.sessionName)
	if err != nil {
		return err
	}
	delete(sess.Values, constants.SessionKeyAuthContext)
	err = s.sessionStore.Save(r, w, sess)
	if err != nil {
		return err
	}

	return nil
}

// RegenerateSession replaces the browser session's identifier, keeping its contents.
//
// Handlers reach rotation through here rather than through the store, so the one port that
// names Regenerate is this helper's and sessionstore.Store stays Get and Save for the
// hundred places that take it (#266, #431).
func (s *AuthHelper) RegenerateSession(w http.ResponseWriter, r *http.Request) error {
	sess, err := s.sessionStore.Get(r, s.sessionName)
	if err != nil {
		return err
	}

	return s.sessionStore.Regenerate(w, r, sess)
}

func (s *AuthHelper) UILocales(r *http.Request) []string {
	authContext, err := s.GetAuthContext(r)
	if err != nil || authContext == nil || len(authContext.UILocales) == 0 {
		return nil
	}
	return authContext.UILocales
}
