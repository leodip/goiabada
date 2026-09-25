package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/leodip/goiabada/adminconsole/internal/boundedread"
	"github.com/leodip/goiabada/adminconsole/internal/constants"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	coreconstants "github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/sessionstore"
)

// tokenParser is the part of oauthclient.JWKSTokenParser this middleware calls: the per-request
// check of the stored ID token and the acceptance of a refresh response. Both decide iss and aud
// themselves and mark a foreign token with oauthclient.ErrForeignToken, so the middleware compares
// no issuer of its own (#427).
type tokenParser interface {
	DecodeAndValidateStoredIDToken(ctx context.Context, raw string) (*oauth.JwtToken, error)
	DecodeAndValidateRefreshResponse(ctx context.Context, tokenResponse *oauth.TokenResponse, previous *oauth.JwtToken) (*oauthclient.JwtInfo, error)
}

type AuthHelper interface {
	RedirToAuthorize(w http.ResponseWriter, r *http.Request, clientIdentifier string, scope string, redirectBack string) error
	IsAuthorizedToAccessResource(jwtInfo oauthclient.JwtInfo, scopesAnyOf []string) bool
	IsAuthenticated(jwtInfo oauthclient.JwtInfo) bool
}

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// ServerErrorRenderer answers a request this middleware cannot complete with the
// localized server-error page, logging the cause against the request id. The middleware
// declares only the shape it needs rather than depending on the handler helper that satisfies it.
//
// Every site below used to answer with http.Error and the Go error text, which put
// an internal detail in front of the administrator in English while the log, which
// is where that detail belongs and where an operator would look for it, got
// nothing. The page these sites now render is localized and carries the request id
// that ties it to the logged cause.
//
// The page reads the settings off the request context for its layout and the
// localizer for its text, so this middleware belongs below whatever puts those
// there, which is where initRoutes mounts it. Mounted above them, a failure here
// renders nothing and panics into Recoverer instead.
type ServerErrorRenderer interface {
	InternalServerError(w http.ResponseWriter, r *http.Request, err error)
}

type MiddlewareJwt struct {
	sessionStore      sessionstore.Store
	sessionName       string
	tokenParser       tokenParser
	authHelper        AuthHelper
	errorRenderer     ServerErrorRenderer
	httpClient        HTTPClient
	authServerBaseURL string
	baseURL           string
	clientID          string
	clientSecret      string
}

// NewMiddlewareJwt constructs a DB-free JWT middleware. It uses provided client
// credentials for refresh operations. If credentials are empty, refresh is disabled.
func NewMiddlewareJwt(
	sessionStore sessionstore.Store,
	sessionName string,
	tokenParser tokenParser,
	authHelper AuthHelper,
	errorRenderer ServerErrorRenderer,
	httpClient HTTPClient,
	authServerBaseURL string,
	baseURL string,
	clientID string,
	clientSecret string,
) *MiddlewareJwt {
	return &MiddlewareJwt{
		sessionStore:      sessionStore,
		sessionName:       sessionName,
		tokenParser:       tokenParser,
		authHelper:        authHelper,
		errorRenderer:     errorRenderer,
		httpClient:        httpClient,
		authServerBaseURL: authServerBaseURL,
		baseURL:           baseURL,
		clientID:          clientID,
		clientSecret:      clientSecret,
	}
}

// JwtSessionHandler puts the signed-in administrator's verified ID token and token response on the
// request context, refreshing the access token when its recorded expiry is near. The console trusts
// one token, the ID token, and only once oauthclient has verified it; the access and refresh tokens
// are carried as strings and never decoded (#427). Per request, in order:
//
//  1. No token response in the session: continue unauthenticated.
//  2. A token response with no recorded expiry, which is every session signed in before #427, or
//     with no ID token: sign it out and continue unauthenticated. One sign-in more for everyone
//     signed in at the upgrade, rather than a transitional path.
//  3. Re-verify the stored ID token, everything but its expiry. A foreign one (another issuer or
//     audience) ends the session with a redirect to the root, which is how every other signed-in
//     administrator leaves when the issuer setting changes (f7c79538). Any other failure, a
//     signing key that has left the JWKS for one, signs the session out with no refresh sent: a
//     refresh would need a verified token to compare the new one with and to keep, and there is
//     none (#427 decision 19).
//  4. Refresh when the recorded expiry is due. An unknown expiry never is: the access token is
//     used until the auth server refuses it.
//  5. The refresh's answer is validated before anything is stored.
//  6. Put the verified ID token and the token response on the context.
func (m *MiddlewareJwt) JwtSessionHandler() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			sess, err := m.sessionStore.Get(r, m.sessionName)
			if err != nil {
				m.errorRenderer.InternalServerError(w, r, errs.Wrap(err, "unable to get the session"))
				return
			}

			if sess.Values[constants.SessionKeyJwt] == nil {
				next.ServeHTTP(w, r)
				return
			}
			tokenResponse, ok := sess.Values[constants.SessionKeyJwt].(oauth.TokenResponse)
			if !ok {
				m.errorRenderer.InternalServerError(w, r,
					errs.New("unable to cast the session value to TokenResponse"))
				return
			}

			// Step 2. The expiry is a plain int64 beside the token response rather than a field of
			// a new persisted type, so a session written before it existed still decodes and is
			// recognised here by the value's absence (#427 decision 15).
			expiresAt, hasExpiry := sess.Values[constants.SessionKeyJwtExpiresAt].(int64)
			if !hasExpiry {
				slog.WarnContext(ctx, "the session holds a token response with no recorded expiry, signing it out")
				m.signOut(w, r, sess, next)
				return
			}
			if tokenResponse.IdToken == "" {
				slog.WarnContext(ctx, "the session holds a token response with no id token, signing it out")
				m.signOut(w, r, sess, next)
				return
			}

			// Step 3.
			idToken, err := m.tokenParser.DecodeAndValidateStoredIDToken(ctx, tokenResponse.IdToken)
			if err != nil {
				if errors.Is(err, oauthclient.ErrForeignToken) {
					m.endForeignSession(w, r, sess, err)
					return
				}
				slog.WarnContext(ctx, "the stored id token no longer verifies, signing the session out", "error", err)
				m.signOut(w, r, sess, next)
				return
			}

			// Steps 4 and 5.
			if oauthclient.RefreshDue(expiresAt, time.Now()) {
				refreshed, refused, err := m.refreshToken(w, r, tokenResponse, idToken)
				if refused != nil {
					if errors.Is(refused, oauthclient.ErrForeignToken) {
						m.endForeignSession(w, r, sess, refused)
						return
					}
					// Error, not Warn: an answer the parser refuses for anything but a foreign
					// issuer, a refreshed ID token naming another user or another sign-in than the
					// stored one above all, is not a changed setting, and someone must look at it
					// (#427 decision 14).
					slog.ErrorContext(ctx, "the refresh response was refused, clearing the session and redirecting to root",
						"error", refused)
					m.endSession(w, r, sess)
					return
				}
				if err != nil {
					slog.WarnContext(ctx, "unable to refresh the access token, signing the session out", "error", err)
				}
				if refreshed == nil {
					m.signOut(w, r, sess, next)
					return
				}
				tokenResponse = refreshed.TokenResponse
				idToken = refreshed.IdToken
			}

			// Step 6.
			ctx = context.WithValue(ctx, constants.ContextKeyJwtInfo,
				oauthclient.JwtInfo{TokenResponse: tokenResponse, IdToken: idToken})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// clearTokens deletes the token values from the session and saves it, answering the error page
// when the save fails. It reports whether the session was saved.
func (m *MiddlewareJwt) clearTokens(w http.ResponseWriter, r *http.Request, sess *sessionstore.Session) bool {
	delete(sess.Values, constants.SessionKeyJwt)
	delete(sess.Values, constants.SessionKeyJwtExpiresAt)
	if err := m.sessionStore.Save(r, w, sess); err != nil {
		m.errorRenderer.InternalServerError(w, r, errs.Wrap(err, "unable to save the session"))
		return false
	}
	return true
}

// signOut clears the token values and continues the chain unauthenticated, so a page that requires
// a scope sends the browser to sign in again.
func (m *MiddlewareJwt) signOut(w http.ResponseWriter, r *http.Request, sess *sessionstore.Session, next http.Handler) {
	if m.clearTokens(w, r, sess) {
		next.ServeHTTP(w, r)
	}
}

// endSession clears the token values and sends the browser to the root rather than on to the page
// it asked for.
func (m *MiddlewareJwt) endSession(w http.ResponseWriter, r *http.Request, sess *sessionstore.Session) {
	if m.clearTokens(w, r, sess) {
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

// endForeignSession ends a session whose ID token names another issuer or audience.
//
// Warn, not Error: a token from another issuer is a condition this middleware is here to meet, and
// it meets it by clearing the session and sending the browser to the root. Nobody has to act, and
// an error log that fills with handled conditions has no error log left (#320 decision 5).
func (m *MiddlewareJwt) endForeignSession(w http.ResponseWriter, r *http.Request, sess *sessionstore.Session, cause error) {
	slog.WarnContext(r.Context(),
		"the id token names another issuer or audience, clearing the session and redirecting to root",
		"error", cause)
	m.endSession(w, r, sess)
}

// refreshToken sends the refresh grant for stored and, when the auth server answers, accepts its
// answer through the parser against previous, the stored ID token that verified on this request,
// before anything reaches the session. It returns the refreshed JwtInfo once it is stored. refused
// is the parser's refusal of the answer, which ends the session; err is a grant that could not be
// completed, which signs it out. With no refresh token all three are nil.
func (m *MiddlewareJwt) refreshToken(
	w http.ResponseWriter,
	r *http.Request,
	stored oauth.TokenResponse,
	previous *oauth.JwtToken,
) (refreshed *oauthclient.JwtInfo, refused error, err error) {
	if stored.RefreshToken == "" {
		return nil, nil, nil
	}

	// Require configured confidential client
	clientID := m.clientID
	clientSecret := m.clientSecret
	if strings.TrimSpace(clientID) == "" || strings.TrimSpace(clientSecret) == "" {
		slog.ErrorContext(r.Context(), "missing client credentials, so the token refresh is skipped")
		return nil, nil, errs.Errorf("missing client credentials for refresh")
	}

	// Prepare the refresh token request
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", stored.RefreshToken)
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)

	// The browser may be gone; the auth server is not. refresh_token is single use, so the
	// server revokes the old token as part of issuing the new one, and abandoning the read
	// loses the only copy of what it issued -- the administrator would then hold a revoked
	// token and be signed out on their next page load. WithoutCancel keeps the request's
	// values, so request_id still reaches every record below, and drops only its
	// cancellation; context.Background() would drop the request id with it. The deadline is
	// what bounds this instead (#338).
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), oauthclient.TokenExchangeTimeout)
	defer cancel()

	// Create the HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.authServerBaseURL+"/auth/token",
		strings.NewReader(data.Encode()))
	if err != nil {
		return nil, nil, errs.Errorf("error creating refresh token request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send the request
	if m.httpClient == nil {
		// Returning rather than logging and carrying on: the next line dereferences
		// m.httpClient, so this record was the last thing written before the process panicked.
		// The caller already treats a refresh error as "clear the session and continue", which
		// is the behaviour a nil client should have had all along (#320).
		return nil, nil, errs.New("no http client is configured, so the token cannot be refreshed")
	}
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, nil, errs.Errorf("error sending refresh token request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Read the response, bounded: a peer answering with an endless body would otherwise be
	// read into memory until the process dies. An answer over the ceiling is refused rather
	// than cut, so it is reported as boundedread.ErrResponseTooLarge rather than as a parse
	// failure indistinguishable from a malformed body; either way the caller clears the
	// session and carries on, and nothing below this line runs (#386 decision 4).
	body, err := boundedread.Read(resp.Body, oauthclient.MaxTokenResponseBytes)
	if err != nil {
		// %w rather than %v, which is what the line said before: the message is byte for
		// byte the same and the sentinel stays reachable through errors.Is, which is the
		// whole point of classifying the overrun.
		return nil, nil, errs.Errorf("error reading refresh token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, nil, errs.Errorf("error response from server: %s", body)
	}

	// Parse the new token response
	var newTokenResponse oauth.TokenResponse
	err = json.Unmarshal(body, &newTokenResponse)
	if err != nil {
		return nil, nil, errs.Errorf("error parsing refresh token response: %v", err)
	}

	// RFC 6749 section 6: "The authorization server MAY issue a new refresh token, in which case
	// the client MUST discard the old refresh token". One that issues none leaves the old one the
	// client's, and storing the answer as it came would drop it and sign the administrator out at
	// the next refresh. golang.org/x/oauth2 keeps it the same way (#427).
	if newTokenResponse.RefreshToken == "" {
		newTokenResponse.RefreshToken = stored.RefreshToken
	}

	// Validated before anything is stored, on the detached context: the old refresh token is
	// already spent, so the parser's JWKS fetch must not be abandoned with the browser either.
	// A response with no ID token keeps previous (OIDC Core 12.2) (#427 decision 14).
	accepted, err := m.tokenParser.DecodeAndValidateRefreshResponse(ctx, &newTokenResponse, previous)
	if err != nil {
		return nil, err, nil
	}
	// RFC 6749 section 6: a refresh whose scope is omitted is "treated as equal to the scope
	// originally granted", which is the stored response's own, set to the effective grant when it
	// arrived.
	accepted.TokenResponse.Scope = oauthclient.EffectiveScope(accepted.TokenResponse.Scope, stored.Scope)

	// The refresh is not done when the call returns; it is done when the new token is written
	// down. The auth server has already revoked the old one, so a read or a write refused
	// because the browser went away leaves the administrator holding a dead token -- the very
	// outcome the detached context above exists to prevent, arriving two lines later instead.
	// ServerSideStore hands the request's own context to its backend, so the store has to be
	// given a request carrying the detached context rather than the browser's. The deadline
	// set above covers the call, its validation and these two writes together.
	//
	// The sign-in callback deliberately does not do this: there the session being built is the
	// one the browser will never receive a cookie for, so persisting it past the browser's
	// departure leaves an authenticated row nobody can reach (#338).
	detachedReq := r.WithContext(ctx)

	sess, err := m.sessionStore.Get(detachedReq, m.sessionName)
	if err != nil {
		return nil, nil, errs.Errorf("unable to get session: %v", err)
	}

	sess.Values[constants.SessionKeyJwt] = accepted.TokenResponse
	sess.Values[constants.SessionKeyJwtExpiresAt] = oauthclient.ExpiresAt(&accepted.TokenResponse, time.Now())
	err = m.sessionStore.Save(detachedReq, w, sess)
	if err != nil {
		return nil, nil, errs.Errorf("unable to save the session: %v", err)
	}

	return accepted, nil, nil
}

// RequiresScope is a middleware that checks if the user has the required scope to access the resource.
func (m *MiddlewareJwt) RequiresScope(
	scopesAnyOf []string,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			var jwtInfo oauthclient.JwtInfo
			var ok bool
			if r.Context().Value(constants.ContextKeyJwtInfo) != nil {
				jwtInfo, ok = r.Context().Value(constants.ContextKeyJwtInfo).(oauthclient.JwtInfo)
				if !ok {
					m.errorRenderer.InternalServerError(w, r,
						errs.New("unable to cast the context value to JwtInfo in RequiresScope middleware"))
					return
				}
			}

			isAuthorized := m.authHelper.IsAuthorizedToAccessResource(jwtInfo, scopesAnyOf)
			if !isAuthorized {
				if m.authHelper.IsAuthenticated(jwtInfo) {
					// User is authenticated but not authorized
					// Show the unauthorized page
					http.Redirect(w, r, "/unauthorized", http.StatusFound)
				} else {
					// User is not authenticated
					// Redirect to the authorize endpoint
					// The caller supplies the client id; this package names no
					// module's identity. initRoutes passes the constant the admin
					// console is seeded as, so a default here could only ever hide a
					// caller that forgot (#285).
					//
					// The return URL is the path and query alone. r.RequestURI is the
					// request line as sent, and an absolute-form line
					// (GET http://elsewhere/x HTTP/1.1) put a whole second URL after the
					// base URL (#426).
					err := m.authHelper.RedirToAuthorize(w, r, m.clientID,
						m.buildScopeString(scopesAnyOf),
						m.baseURL+r.URL.RequestURI())
					if err != nil {
						m.errorRenderer.InternalServerError(w, r,
							errs.Wrap(err, "unable to redirect to authorize in RequiresScope middleware"))
					}
				}
				return
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (m *MiddlewareJwt) buildScopeString(customScopes []string) string {

	// Default required scopes.
	// "profile" is required for the locale claim to be emitted in tokens
	// (see userclaims.Mapper.AddOpenIdConnectClaims, which the auth server's token
	// issuer calls), which adminconsole's
	// JWT-locale refinement middleware reads to resolve the user's stored
	// locale.
	defaultScopes := []string{
		"openid",
		"email",
		"profile",
		coreconstants.AuthServerResourceIdentifier + ":" + coreconstants.ManageAccountPermissionIdentifier,
		coreconstants.AuthServerResourceIdentifier + ":" + coreconstants.ManagePermissionIdentifier,
	}

	scopeMap := make(map[string]bool)

	// Add default scopes first
	for _, scope := range defaultScopes {
		scopeMap[strings.ToLower(scope)] = true
	}

	// Add custom scopes
	for _, scope := range customScopes {
		scope = strings.ToLower(strings.TrimSpace(scope))
		if scope != "" {
			scopeMap[scope] = true
		}
	}

	var allScopes []string
	for scope := range scopeMap {
		allScopes = append(allScopes, scope)
	}
	sort.Strings(allScopes)

	return strings.Join(allScopes, " ")
}
