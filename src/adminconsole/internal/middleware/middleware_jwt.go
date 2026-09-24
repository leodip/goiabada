package middleware

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/leodip/goiabada/adminconsole/internal/boundedread"
	"github.com/leodip/goiabada/adminconsole/internal/constants"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	coreconstants "github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/sessionstore"
)

type tokenParser interface {
	DecodeAndValidateTokenResponse(ctx context.Context, tokenResponse *oauth.TokenResponse) (*oauthclient.JwtInfo, error)
	DecodeAndValidateTokenString(ctx context.Context, token string, pubKey *rsa.PublicKey, withExpirationCheck bool) (*oauth.JwtToken, error)
}

type issuerReader interface {
	Issuer(ctx context.Context) string
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
	issuerReader      issuerReader
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
	issuerReader issuerReader,
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
		issuerReader:      issuerReader,
		authHelper:        authHelper,
		errorRenderer:     errorRenderer,
		httpClient:        httpClient,
		authServerBaseURL: authServerBaseURL,
		baseURL:           baseURL,
		clientID:          clientID,
		clientSecret:      clientSecret,
	}
}

// JwtSessionHandler is a middleware that checks if the user has a valid JWT session.
// It will also refresh the token if needed.
func (m *MiddlewareJwt) JwtSessionHandler() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			sess, err := m.sessionStore.Get(r, m.sessionName)
			if err != nil {
				m.errorRenderer.InternalServerError(w, r, errs.Wrap(err, "unable to get the session"))
				return
			}

			if sess.Values[constants.SessionKeyJwt] != nil {
				tokenResponse, ok := sess.Values[constants.SessionKeyJwt].(oauth.TokenResponse)
				if !ok {
					m.errorRenderer.InternalServerError(w, r,
						errs.New("unable to cast the session value to TokenResponse"))
					return
				}

				// Check if token needs refresh
				_, err := m.tokenParser.DecodeAndValidateTokenString(r.Context(), tokenResponse.AccessToken, nil, true)
				if err != nil {
					refreshed, refreshErr := m.refreshToken(w, r, &tokenResponse)
					if refreshErr != nil || !refreshed {
						// If refresh failed, clear the session and continue
						delete(sess.Values, constants.SessionKeyJwt)
						saveErr := m.sessionStore.Save(r, w, sess)
						if saveErr != nil {
							m.errorRenderer.InternalServerError(w, r, errs.Wrap(saveErr, "unable to save the session"))
							return
						}
						next.ServeHTTP(w, r)
						return
					}
				}

				// Get the latest token response from the session
				tokenResponse = sess.Values[constants.SessionKeyJwt].(oauth.TokenResponse)
				jwtInfo, err := m.tokenParser.DecodeAndValidateTokenResponse(r.Context(), &tokenResponse)
				if err == nil {
					issuer := m.issuerReader.Issuer(r.Context())

					// Check if any token has an invalid issuer
					hasInvalidIssuer := (jwtInfo.IdToken != nil && !jwtInfo.IdToken.IsIssuerValid(issuer)) ||
						(jwtInfo.AccessToken != nil && !jwtInfo.AccessToken.IsIssuerValid(issuer)) ||
						(jwtInfo.RefreshToken != nil && !jwtInfo.RefreshToken.IsIssuerValid(issuer))

					if hasInvalidIssuer {

						// Warn, not Error: a token from another issuer is a condition this
						// middleware is here to meet, and it meets it by clearing the session
						// and sending the browser to the root. Nobody has to act, and an error
						// log that fills with handled conditions has no error log left
						// (#320 decision 5).
						slog.WarnContext(r.Context(),
							"jwt token has an invalid issuer, clearing the session and redirecting to root")

						// Clear the session
						delete(sess.Values, constants.SessionKeyJwt)
						err := m.sessionStore.Save(r, w, sess)
						if err != nil {
							m.errorRenderer.InternalServerError(w, r, errs.Wrap(err, "unable to save the session"))
							return
						}

						// Redirect to root
						http.Redirect(w, r, "/", http.StatusFound)
						return
					}

					ctx = context.WithValue(ctx, constants.ContextKeyJwtInfo, *jwtInfo)
				}
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (m *MiddlewareJwt) refreshToken(
	w http.ResponseWriter,
	r *http.Request,
	tokenResponse *oauth.TokenResponse,
) (bool, error) {
	if tokenResponse.RefreshToken == "" {
		return false, nil
	}

	// Require configured confidential client
	clientID := m.clientID
	clientSecret := m.clientSecret
	if strings.TrimSpace(clientID) == "" || strings.TrimSpace(clientSecret) == "" {
		slog.ErrorContext(r.Context(), "missing client credentials, so the token refresh is skipped")
		return false, errs.Errorf("missing client credentials for refresh")
	}

	// Prepare the refresh token request
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", tokenResponse.RefreshToken)
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
		return false, errs.Errorf("error creating refresh token request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send the request
	if m.httpClient == nil {
		// Returning rather than logging and carrying on: the next line dereferences
		// m.httpClient, so this record was the last thing written before the process panicked.
		// The caller already treats a refresh error as "clear the session and continue", which
		// is the behaviour a nil client should have had all along (#320).
		return false, errs.New("no http client is configured, so the token cannot be refreshed")
	}
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return false, errs.Errorf("error sending refresh token request: %v", err)
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
		return false, errs.Errorf("error reading refresh token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return false, errs.Errorf("error response from server: %s", body)
	}

	// Parse the new token response
	var newTokenResponse oauth.TokenResponse
	err = json.Unmarshal(body, &newTokenResponse)
	if err != nil {
		return false, errs.Errorf("error parsing refresh token response: %v", err)
	}

	// The refresh is not done when the call returns; it is done when the new token is written
	// down. The auth server has already revoked the old one, so a read or a write refused
	// because the browser went away leaves the administrator holding a dead token -- the very
	// outcome the detached context above exists to prevent, arriving two lines later instead.
	// ServerSideStore hands the request's own context to its backend, so the store has to be
	// given a request carrying the detached context rather than the browser's. The deadline
	// set above covers the call and these two writes together.
	//
	// The sign-in callback deliberately does not do this: there the session being built is the
	// one the browser will never receive a cookie for, so persisting it past the browser's
	// departure leaves an authenticated row nobody can reach (#338).
	detachedReq := r.WithContext(ctx)

	sess, err := m.sessionStore.Get(detachedReq, m.sessionName)
	if err != nil {
		return false, errs.Errorf("unable to get session: %v", err)
	}

	// Update the session with the new token response
	sess.Values[constants.SessionKeyJwt] = newTokenResponse
	err = m.sessionStore.Save(detachedReq, w, sess)
	if err != nil {
		return false, errs.Errorf("unable to save the session: %v", err)
	}

	return true, nil
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
