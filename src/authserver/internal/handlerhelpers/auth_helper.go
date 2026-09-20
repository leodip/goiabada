package handlerhelpers

import (
	"encoding/json"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/sessionstore"
)

type AuthHelper struct {
	sessionStore sessionstore.Store
	sessionName  string
}

func NewAuthHelper(sessionStore sessionstore.Store, sessionName string) *AuthHelper {
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
		return nil, customerrors.ErrNoAuthContext
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
// Callers reach rotation through here rather than through the store because sessionstore.Store
// has no such method and widening it would touch the hundred places that already take the
// interface. A store that cannot rotate is a no-op, which is what the cookie store in the
// unit tier is; the property is observed against the real store at the integration tier,
// where the cookie is watched changing across a privilege change (#266).
func (s *AuthHelper) RegenerateSession(w http.ResponseWriter, r *http.Request) error {
	regenerator, ok := s.sessionStore.(sessionstore.Regenerator)
	if !ok {
		return nil
	}

	sess, err := s.sessionStore.Get(r, s.sessionName)
	if err != nil {
		return err
	}

	return regenerator.Regenerate(w, r, sess)
}

func (s *AuthHelper) UILocales(r *http.Request) []string {
	authContext, err := s.GetAuthContext(r)
	if err != nil || authContext == nil || len(authContext.UILocales) == 0 {
		return nil
	}
	return authContext.UILocales
}
