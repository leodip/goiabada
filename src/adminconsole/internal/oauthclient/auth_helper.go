package oauthclient

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/leodip/goiabada/adminconsole/internal/constants"
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
	sess.Values[constants.SessionKeyRequestedScope] = scope
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
	sentNonce, err := nonceHash(nonce)
	if err != nil {
		return err
	}
	values.Add("nonce", sentNonce)
	values.Add("scope", scope)

	destUrl := fmt.Sprintf("%v/auth/authorize?%v", s.authServerBaseURL, values.Encode())

	http.Redirect(w, r, destUrl, http.StatusFound)

	return nil
}

// nonceHash is the nonce an authorize request sends and the sign-in's ID token must carry back:
// the SHA-256 of the raw value the session keeps, the scheme OIDC Core 15.5.2 describes ("use a
// cryptographic hash of the value as the nonce parameter"). RedirToAuthorize sends it and
// DecodeAndValidateSignInResponse compares against it, so the scheme is written once (#427).
func nonceHash(nonce string) (string, error) {
	return hashutil.HashString(nonce)
}

// IsAuthorizedToAccessResource reports whether the grant the token response records includes any
// of scopesAnyOf. It reads the response's scope through JwtInfo.HasScope, never the access token,
// which the console carries without decoding (#427). A visitor with no token response has an empty
// grant and is authorized for nothing.
func (s *AuthHelper) IsAuthorizedToAccessResource(jwtInfo JwtInfo, scopesAnyOf []string) bool {
	for _, scope := range scopesAnyOf {
		if jwtInfo.HasScope(scope) {
			return true
		}
	}
	return false
}

func (s *AuthHelper) IsAuthenticated(jwtInfo JwtInfo) bool {
	return jwtInfo.IdToken != nil
}
