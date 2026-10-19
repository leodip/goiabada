package middleware

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	chimiddleware "github.com/go-chi/chi/v5/middleware"

	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/adminconsole/internal/sessionkeys"
	"github.com/leodip/goiabada/core/builtin"
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

// tokenRefresher is the part of oauthclient.TokenClient this middleware calls: the refresh grant,
// transport only. It detaches the grant from the browser's cancellation and keeps the old refresh
// token when the answer carries none; the check of the answer and the session write are this
// middleware's (#441 decision 2).
type tokenRefresher interface {
	Refresh(ctx context.Context, refreshToken string) (*oauth.TokenResponse, error)
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

type JWT struct {
	sessionStore   sessionstore.Store
	sessionName    string
	tokenParser    tokenParser
	tokenRefresher tokenRefresher
	authHelper     AuthHelper
	errorRenderer  ServerErrorRenderer
	baseURL        string
	clientID       string
	// refreshLocks serializes the refresh grant per browser session (#621).
	refreshLocks *sessionRefreshLocks
}

// NewJWT constructs a DB-free JWT middleware. tokenRefresher sends the refresh grant;
// clientID is the client the sign-in redirect names.
func NewJWT(
	sessionStore sessionstore.Store,
	sessionName string,
	tokenParser tokenParser,
	tokenRefresher tokenRefresher,
	authHelper AuthHelper,
	errorRenderer ServerErrorRenderer,
	baseURL string,
	clientID string,
) *JWT {
	return &JWT{
		sessionStore:   sessionStore,
		sessionName:    sessionName,
		tokenParser:    tokenParser,
		tokenRefresher: tokenRefresher,
		authHelper:     authHelper,
		errorRenderer:  errorRenderer,
		baseURL:        baseURL,
		clientID:       clientID,
		refreshLocks:   newSessionRefreshLocks(),
	}
}

// SessionHandler puts the signed-in administrator's verified ID token and token response on the
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
//     used until the auth server refuses it. One refresh runs per session at a time, and the
//     request that waited for it carries the answer another request stored rather than sending
//     a grant of its own (#621).
//  5. The refresh's answer is validated before anything is stored.
//  6. Put the verified ID token and the token response on the context.
func (m *JWT) SessionHandler() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			sess, err := m.sessionStore.Get(r, m.sessionName)
			if err != nil {
				m.errorRenderer.InternalServerError(w, r, errs.Wrap(err, "unable to get the session"))
				return
			}

			if sess.Values[sessionkeys.JWT] == nil {
				next.ServeHTTP(w, r)
				return
			}
			tokenResponse, ok := sess.Values[sessionkeys.JWT].(oauth.TokenResponse)
			if !ok {
				m.errorRenderer.InternalServerError(w, r,
					errs.New("unable to cast the session value to TokenResponse"))
				return
			}

			// Step 2. The expiry is a plain int64 beside the token response rather than a field of
			// a new persisted type, so a session written before it existed still decodes and is
			// recognised here by the value's absence (#427 decision 15).
			expiresAt, hasExpiry := sess.Values[sessionkeys.JWTExpiresAt].(int64)
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
				refreshed, refused, err := m.refreshToken(w, r, sess.ID)
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
			ctx = reqctx.WithJwtInfo(ctx, oauthclient.JwtInfo{TokenResponse: tokenResponse, IdToken: idToken})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// clearTokens deletes the token values from the session and saves it, answering the error page
// when the save fails. It reports whether the session was saved.
func (m *JWT) clearTokens(w http.ResponseWriter, r *http.Request, sess *sessionstore.Session) bool {
	delete(sess.Values, sessionkeys.JWT)
	delete(sess.Values, sessionkeys.JWTExpiresAt)
	if err := m.sessionStore.Save(r, w, sess); err != nil {
		m.errorRenderer.InternalServerError(w, r, errs.Wrap(err, "unable to save the session"))
		return false
	}
	return true
}

// signOut clears the token values and continues the chain unauthenticated, so a page that requires
// a scope sends the browser to sign in again.
func (m *JWT) signOut(w http.ResponseWriter, r *http.Request, sess *sessionstore.Session, next http.Handler) {
	if m.clearTokens(w, r, sess) {
		next.ServeHTTP(w, r)
	}
}

// endSession clears the token values and sends the browser to the root rather than on to the page
// it asked for.
func (m *JWT) endSession(w http.ResponseWriter, r *http.Request, sess *sessionstore.Session) {
	if m.clearTokens(w, r, sess) {
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

// endForeignSession ends a session whose ID token names another issuer or audience.
//
// Warn, not Error: a token from another issuer is a condition this middleware is here to meet, and
// it meets it by clearing the session and sending the browser to the root. Nobody has to act, and
// an error log that fills with handled conditions has no error log left (#320 decision 5).
func (m *JWT) endForeignSession(w http.ResponseWriter, r *http.Request, sess *sessionstore.Session, cause error) {
	slog.WarnContext(r.Context(),
		"the id token names another issuer or audience, clearing the session and redirecting to root",
		"error", cause)
	m.endSession(w, r, sess)
}

// refreshToken sends the refresh grant for the session's current token set and, when the auth
// server answers, accepts its answer through the parser against the ID token it re-read and
// verified, before anything reaches the session. It returns the refreshed JwtInfo once it is
// stored; refused is a token set the parser will not trust, which ends the session; err is a
// grant that could not be completed, which signs it out. With no refresh token all three are
// nil.
//
// The whole of it runs under the session's lock (#621). The auth server rotates refresh tokens
// strictly, so two grants for one session would present the same refresh token twice and the
// loser would be signed out over the winner's tokens. The request that waited for the lock
// therefore re-reads the session first and carries a token set another request stored as is;
// the grant, when there is one, presents the re-read set's refresh token. A grant the auth
// server refuses is answered the same way (supersedingTokens): a set newer than the one
// presented means another console won the rotation while this one was asking, and the newer
// set is carried rather than cleared.
func (m *JWT) refreshToken(
	w http.ResponseWriter,
	r *http.Request,
	sessionID string,
) (refreshed *oauthclient.JwtInfo, refused error, err error) {
	release := m.refreshLocks.Lock(sessionID)
	defer release()

	// The lock makes this request the only refresher of this session in this console, but not
	// the first: another request may have refreshed while this one waited for it. The session
	// is re-read before anything is sent, so a token set another request stored is carried as
	// is, and a set that is still due is the one the grant presents.
	current, err := m.reReadSession(r)
	if err != nil {
		return nil, nil, err
	}
	stored, hasStored := current.Values[sessionkeys.JWT].(oauth.TokenResponse)
	expiresAt, hasExpiry := current.Values[sessionkeys.JWTExpiresAt].(int64)
	if !hasStored || !hasExpiry || stored.IdToken == "" {
		// Another request ended this session while this one waited for the lock; this
		// request ends it the same way, and the sign-out's clear finds nothing newer to
		// save over.
		return nil, nil, nil
	}
	// Step 3's check, restated under the lock for the set this request may not have read
	// itself: carried or refreshed, the ID token that reaches the context is verified. Its
	// failure is refused rather than err, so the session ends whatever request stored the
	// set, and the classification — foreign or otherwise — stays the parser's.
	previous, err := m.tokenParser.DecodeAndValidateStoredIDToken(r.Context(), stored.IdToken)
	if err != nil {
		return nil, err, nil
	}
	if !oauthclient.RefreshDue(expiresAt, time.Now()) {
		return &oauthclient.JwtInfo{TokenResponse: stored, IdToken: previous}, nil, nil
	}

	if stored.RefreshToken == "" {
		return nil, nil, nil
	}

	// The token client detaches the grant itself and bounds it at its own deadline.
	newTokenResponse, err := m.tokenRefresher.Refresh(r.Context(), stored.RefreshToken)
	if err != nil {
		// A strictly rotating auth server refuses the second presentation of a refresh
		// token, and another replica of this console — beyond this process's lock — may
		// have presented the first and stored its answer while this grant was in flight.
		// Clearing here would sign the administrator out over a token set that is live,
		// so the session is re-read once more, and only a session still holding the set
		// this request presented is signed out (#621).
		if newer, ok := m.supersedingTokens(r, stored, err); ok {
			return newer, nil, nil
		}
		return nil, nil, err
	}

	// The refresh is not done when the grant returns; it is done when the new token is written
	// down. The auth server has already revoked the old one, so a check or a write refused because
	// the browser went away leaves the administrator holding a dead token -- the very outcome the
	// grant's detachment exists to prevent, arriving two lines later instead. So what follows runs
	// on a context of its own, detached the same way: WithoutCancel keeps the request's values, so
	// request_id still reaches every record, and TokenExchangeTimeout bounds the check and the
	// write together. That is a second budget after the grant's, so against a hung auth server
	// the worst case is twice the timeout, still under the listener's write timeout (#338, #441
	// decision 2).
	//
	// The sign-in callback deliberately does not do this: there the session being built is the
	// one the browser will never receive a cookie for, so persisting it past the browser's
	// departure leaves an authenticated row nobody can reach (#338).
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), oauthclient.TokenExchangeTimeout)
	defer cancel()

	// Validated before anything is stored: the parser may fetch the JWKS, which must not be
	// abandoned with the browser either. A response with no ID token keeps previous (OIDC Core
	// 12.2) (#427 decision 14).
	accepted, err := m.tokenParser.DecodeAndValidateRefreshResponse(ctx, newTokenResponse, previous)
	if err != nil {
		return nil, err, nil
	}
	// RFC 6749 section 6: a refresh whose scope is omitted is "treated as equal to the scope
	// originally granted", which is the stored response's own, set to the effective grant when it
	// arrived.
	accepted.TokenResponse.Scope = oauthclient.EffectiveScope(accepted.TokenResponse.Scope, stored.Scope)

	// ServerSideStore hands the request's own context to its backend, so the store has to be
	// given a request carrying the detached context rather than the browser's.
	detachedReq := r.WithContext(ctx)

	sess, err := m.sessionStore.Get(detachedReq, m.sessionName)
	if err != nil {
		return nil, nil, errs.Errorf("unable to get session: %v", err)
	}

	sess.Values[sessionkeys.JWT] = accepted.TokenResponse
	sess.Values[sessionkeys.JWTExpiresAt] = oauthclient.ExpiresAt(&accepted.TokenResponse, time.Now())
	err = m.sessionStore.Save(detachedReq, w, sess)
	if err != nil {
		return nil, nil, errs.Errorf("unable to save the session: %v", err)
	}

	return accepted, nil, nil
}

// reReadSession loads the session as the backend holds it now, around the store's per-request
// memoisation: Get answers later callers on a request from the session it already loaded (#269),
// which is the copy this request read at its start and not the row another request — on this
// console or another — may have written since. The clone carries a fresh context, because that
// memo lives in the request's context, with the request's own id kept on it through reqctx, the
// way the write's detached context keeps it, so the load's records still name the request. What
// it returns is read, never saved: the request's own session object, the one the write below
// reaches through, is untouched.
func (m *JWT) reReadSession(r *http.Request) (*sessionstore.Session, error) {
	ctx := context.Background()
	if id := chimiddleware.GetReqID(r.Context()); id != "" {
		ctx = reqctx.WithRequestID(ctx, id)
	}
	return m.sessionStore.Get(r.Clone(ctx), m.sessionName)
}

// supersedingTokens re-reads the session after a grant the auth server refused, asking whether
// another request — on another replica of this console, since this one holds the session's
// refresh lock — has stored a token set newer than the one this request presented: a strictly
// rotating auth server refuses the second presentation of a refresh token (#128), so the
// refusal usually means the rotation was won elsewhere while this grant was in flight. The
// newer set is returned once its ID token verifies. ok is false when the session still holds
// the one presented — the token set is genuinely dead, and the sign-out stands — and when
// nothing newer verifies, which is the sign-out's answer too.
func (m *JWT) supersedingTokens(r *http.Request, presented oauth.TokenResponse, refusedGrant error) (newer *oauthclient.JwtInfo, ok bool) {
	current, err := m.reReadSession(r)
	if err != nil {
		return nil, false
	}
	stored, hasStored := current.Values[sessionkeys.JWT].(oauth.TokenResponse)
	if !hasStored || stored == presented {
		return nil, false
	}
	idToken, err := m.tokenParser.DecodeAndValidateStoredIDToken(r.Context(), stored.IdToken)
	if err != nil {
		return nil, false
	}
	slog.WarnContext(r.Context(),
		"the refresh grant was refused, but a token set newer than the one it presented had been stored meanwhile, so the session keeps it",
		"error", refusedGrant)
	return &oauthclient.JwtInfo{TokenResponse: stored, IdToken: idToken}, true
}

// RequiresScope is a middleware that checks if the user has the required scope to access the resource.
func (m *JWT) RequiresScope(
	scopesAnyOf []string,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// An absent token set is the anonymous request, and the zero value the accessor answers
			// with authorizes nothing and authenticates no one, so it takes the sign-in arm below.
			jwtInfo, _ := reqctx.JwtInfoFrom(r.Context())

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

			next.ServeHTTP(w, r)
		})
	}
}

func (m *JWT) buildScopeString(customScopes []string) string {

	// Default required scopes.
	// "profile" is required for the locale claim to be emitted in tokens
	// (see userclaims.Mapper.AddOpenIDConnectClaims, which the auth server's token
	// issuer calls), which adminconsole's
	// JWT-locale refinement middleware reads to resolve the user's stored
	// locale.
	defaultScopes := []string{
		"openid",
		"email",
		"profile",
		builtin.AuthServerResourceIdentifier + ":" + builtin.ManageAccountPermissionIdentifier,
		builtin.AuthServerResourceIdentifier + ":" + builtin.ManagePermissionIdentifier,
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
