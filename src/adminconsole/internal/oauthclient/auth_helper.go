package oauthclient

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/leodip/goiabada/adminconsole/internal/sessionkeys"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/securerandom"
)

// SignInHandshakeCookie is the logical name of the cookie the sign-in's handshake rides in from
// the authorize redirect to the callback: the six values RedirToAuthorize mints, sealed by the
// session store under keys of their own. The handshake used to be parked in a fresh browser
// session, which cost the auth server a row for every anonymous request to /admin or /account,
// at no limit; it is a kilobyte or so sealed, written once and read once, and its safety rests on the posted state
// matching it and the code being bound to its verifier, not on where it is kept. So the console
// writes no row until the callback has a signed-in administrator to store (#620).
const SignInHandshakeCookie = "adminconsole-signin"

// handshakeSealer is what RedirToAuthorize calls on the session store: seal the handshake and
// build the cookie that carries it.
type handshakeSealer interface {
	SealCookieValues(name string, values map[string]string) (string, error)
	ValuesCookie(name, value string) *http.Cookie
}

type AuthHelper struct {
	sealer            handshakeSealer
	baseURL           string
	authServerBaseURL string
}

func NewAuthHelper(sealer handshakeSealer, baseURL, authServerBaseURL string) *AuthHelper {
	return &AuthHelper{
		sealer:            sealer,
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
	redirectURI := s.baseURL + "/auth/callback"
	codeVerifier := securerandom.String(120)
	codeChallenge := oauth.GeneratePKCECodeChallenge(codeVerifier)
	state := securerandom.String(16)
	nonce := securerandom.String(16)

	sealed, err := s.sealer.SealCookieValues(SignInHandshakeCookie, map[string]string{
		sessionkeys.State:          state,
		sessionkeys.Nonce:          nonce,
		sessionkeys.CodeVerifier:   codeVerifier,
		sessionkeys.RedirectURI:    redirectURI,
		sessionkeys.RedirectBack:   redirectBack,
		sessionkeys.RequestedScope: scope,
	})
	if err != nil {
		return err
	}
	http.SetCookie(w, s.sealer.ValuesCookie(SignInHandshakeCookie, sealed))

	values := url.Values{}
	values.Add("client_id", clientIdentifier)
	values.Add("redirect_uri", redirectURI)
	values.Add("response_mode", "form_post")
	values.Add("response_type", "code")
	values.Add("code_challenge_method", "S256")
	values.Add("code_challenge", codeChallenge)
	values.Add("state", state)
	values.Add("nonce", nonceHash(nonce))
	values.Add("scope", scope)

	destUrl := fmt.Sprintf("%v/auth/authorize?%v", s.authServerBaseURL, values.Encode())

	http.Redirect(w, r, destUrl, http.StatusFound)

	return nil
}

// nonceHash is the nonce an authorize request sends and the sign-in's ID token must carry back:
// the SHA-256 of the raw value the handshake keeps, the scheme OIDC Core 15.5.2 describes ("use a
// cryptographic hash of the value as the nonce parameter"). RedirToAuthorize sends it and
// DecodeAndValidateSignInResponse compares against it, so the scheme is written once (#427).
func nonceHash(nonce string) string {
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
