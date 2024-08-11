package handlerhelpers

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"runtime/debug"

	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/adminconsole/internal/config"
	"github.com/leodip/goiabada/adminconsole/internal/constants"
	"github.com/leodip/goiabada/adminconsole/internal/enums"
	"github.com/leodip/goiabada/adminconsole/internal/hashutil"
	"github.com/leodip/goiabada/adminconsole/internal/oauth"
	"github.com/leodip/goiabada/adminconsole/internal/stringutil"
)

type AuthHelper struct {
	sessionStore sessions.Store
}

func NewAuthHelper(sessionStore sessions.Store) *AuthHelper {
	return &AuthHelper{
		sessionStore: sessionStore,
	}
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

	redirectURI := config.AdminConsoleBaseUrl + "/auth/callback"
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

	destUrl := fmt.Sprintf("%v/auth/authorize?%v", config.AuthServerBaseUrl, values.Encode())

	http.Redirect(w, r, destUrl, http.StatusFound)

	return nil
}

func (s *AuthHelper) IsAuthorizedToAccessResource(jwtInfo oauth.JwtInfo, scopesAnyOf []string) bool {
	if jwtInfo.AccessToken != nil && jwtInfo.AccessToken.SignatureIsValid {
		acrLevel := jwtInfo.AccessToken.GetAcrLevel()
		if acrLevel != nil &&
			(*acrLevel == enums.AcrLevel2 || *acrLevel == enums.AcrLevel3) {
			for _, scope := range scopesAnyOf {
				if jwtInfo.AccessToken.HasScope(scope) {
					return true
				}
			}
		}
	}
	return false
}
