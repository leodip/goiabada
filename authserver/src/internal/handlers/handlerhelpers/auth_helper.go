package handlerhelpers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/authserver/internal/customerrors"
	"github.com/leodip/goiabada/authserver/internal/oauth"
)

type AuthHelper struct {
	sessionStore sessions.Store
}

func NewAuthHelper(sessionStore sessions.Store) *AuthHelper {
	return &AuthHelper{
		sessionStore: sessionStore,
	}
}

func (s *AuthHelper) GetAuthContext(r *http.Request) (*oauth.AuthContext, error) {
	sess, err := s.sessionStore.Get(r, constants.SessionName)
	if err != nil {
		return nil, err
	}
	jsonData, ok := sess.Values[constants.SessionKeyAuthContext].(string)
	if !ok {
		return nil, customerrors.ErrNoAuthContext
	}

	var authContext oauth.AuthContext
	err = json.Unmarshal([]byte(jsonData), &authContext)
	if err != nil {
		return nil, err
	}
	return &authContext, nil
}

func (s *AuthHelper) GetLoggedInSubject(r *http.Request) string {
	var jwtInfo oauth.JwtInfo
	if r.Context().Value(constants.ContextKeyJwtInfo) != nil {
		var ok bool
		jwtInfo, ok = r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			stackBytes := debug.Stack()
			slog.Error("unable to cast jwtInfo\n" + string(stackBytes))
			return ""
		}
		if jwtInfo.IdToken != nil {
			sub := jwtInfo.IdToken.GetStringClaim("sub")
			return sub
		}
	}
	return ""
}

func (s *AuthHelper) SaveAuthContext(w http.ResponseWriter, r *http.Request, authContext *oauth.AuthContext) error {

	sess, err := s.sessionStore.Get(r, constants.SessionName)
	if err != nil {
		return err
	}

	jsonData, err := json.Marshal(authContext)
	if err != nil {
		return err
	}
	sess.Values[constants.SessionKeyAuthContext] = string(jsonData)
	err = sess.Save(r, w)
	if err != nil {
		return err
	}

	return nil
}

func (s *AuthHelper) ClearAuthContext(w http.ResponseWriter, r *http.Request) error {

	sess, err := s.sessionStore.Get(r, constants.SessionName)
	if err != nil {
		return err
	}
	delete(sess.Values, constants.SessionKeyAuthContext)
	err = sess.Save(r, w)
	if err != nil {
		return err
	}

	return nil
}
