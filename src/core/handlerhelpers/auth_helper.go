package handlerhelpers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"runtime/debug"

	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/stringutil"
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
	err = s.sessionStore.Save(r, w, sess)
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
	err = s.sessionStore.Save(r, w, sess)
	if err != nil {
		return err
	}

	return nil
}

func (s *AuthHelper) RedirToAuthorize(
	w http.ResponseWriter,
	r *http.Request,
	clientIdentifier string,
	scope string,
	redirectBack string,
) error {
	sess, err := s.sessionStore.Get(r, constants.SessionName)
	if err != nil {
		return err
	}

	redirectURI := config.Get().BaseURL + "/auth/callback"
	codeVerifier := stringutil.GenerateSecureRandomString(120)
	codeChallenge := oauth.GeneratePKCECodeChallenge(codeVerifier)
	state := stringutil.GenerateSecureRandomString(16)
	nonce := stringutil.GenerateSecureRandomString(16)

	sess.Values[constants.SessionKeyState] = state
	sess.Values[constants.SessionKeyNonce] = nonce
	sess.Values[constants.SessionKeyCodeVerifier] = codeVerifier
	sess.Values[constants.SessionKeyRedirectURI] = redirectURI
	sess.Values[constants.SessionKeyRedirectBack] = redirectBack
	err = sess.Save(r, w)
	if err != nil {
		return err
	}

	values := url.Values{}
	values.Add("client_id", clientIdentifier)
	values.Add("redirect_uri", redirectURI)
	values.Add("response_mode", "form_post")
	values.Add("response_type", "code")
	values.Add("code_challenge_method", "S256")
	values.Add("code_challenge", codeChallenge)
	values.Add("state", state)
	nonceHash, err := hashutil.HashString(nonce)
	if err != nil {
		return err
	}
	values.Add("nonce", nonceHash)
	values.Add("scope", scope)
	values.Add("acr_values", "2") // pwd + optional otp (if enabled)

	destUrl := fmt.Sprintf("%v/auth/authorize?%v", config.GetAuthServer().BaseURL, values.Encode())

	http.Redirect(w, r, destUrl, http.StatusFound)

	return nil
}

func (s *AuthHelper) IsAuthorizedToAccessResource(jwtInfo oauth.JwtInfo, scopesAnyOf []string) bool {
	if jwtInfo.AccessToken != nil {
		for _, scope := range scopesAnyOf {
			if jwtInfo.AccessToken.HasScope(scope) {
				return true
			}
		}
	}
	return false
}

func (s *AuthHelper) IsAuthenticated(jwtInfo oauth.JwtInfo) bool {
	return jwtInfo.IdToken != nil
}
