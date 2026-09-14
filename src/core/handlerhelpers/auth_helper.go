package handlerhelpers

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/stringutil"
)

type AuthHelper struct {
	sessionStore      sessionstore.Store
	sessionName       string
	baseURL           string
	authServerBaseURL string
}

func NewAuthHelper(sessionStore sessionstore.Store, sessionName, baseURL, authServerBaseURL string) *AuthHelper {
	return &AuthHelper{
		sessionStore:      sessionStore,
		sessionName:       sessionName,
		baseURL:           baseURL,
		authServerBaseURL: authServerBaseURL,
	}
}

func (s *AuthHelper) RedirToAuthorize(
	w http.ResponseWriter,
	r *http.Request,
	clientIdentifier string,
	scope string,
	redirectBack string,
) error {
	sess, err := s.sessionStore.Get(r, s.sessionName)
	if err != nil {
		return err
	}

	redirectURI := s.baseURL + "/auth/callback"
	codeVerifier := stringutil.GenerateSecurityRandomString(120)
	codeChallenge := oauth.GeneratePKCECodeChallenge(codeVerifier)
	state := stringutil.GenerateSecurityRandomString(16)
	nonce := stringutil.GenerateSecurityRandomString(16)

	sess.Values[constants.SessionKeyState] = state
	sess.Values[constants.SessionKeyNonce] = nonce
	sess.Values[constants.SessionKeyCodeVerifier] = codeVerifier
	sess.Values[constants.SessionKeyRedirectURI] = redirectURI
	sess.Values[constants.SessionKeyRedirectBack] = redirectBack
	err = s.sessionStore.Save(r, w, sess)
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

	destUrl := fmt.Sprintf("%v/auth/authorize?%v", s.authServerBaseURL, values.Encode())

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
