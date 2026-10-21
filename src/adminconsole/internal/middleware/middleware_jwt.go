package middleware

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

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

// refreshWaitTimeout bounds how long a request waits for another request's refresh of its
// session before it gives up and answers the error page: see refreshUnderLock.
const refreshWaitTimeout = 5 * time.Second

// errSessionEndedMeanwhile is refreshToken's answer when the re-read under the lock finds the
// token set gone: another request ended the session while this one waited for the lock.
var errSessionEndedMeanwhile = errors.New("the session was signed out while the request waited for its refresh lock")

// freshSessionReader is the part of sessionstore.ServerSideStore the refresh re-reads through:
// the session as stored now, past the request's memo of it (#269), without writing that memo
// or the row (#621).
type freshSessionReader interface {
	GetFresh(r *http.Request, name string) (*sessionstore.Session, error)
}

type JWT struct {
	sessionStore   sessionstore.Store
	freshSessions  freshSessionReader
	sessionName    string
	tokenParser    tokenParser
	tokenRefresher tokenRefresher
	authHelper     AuthHelper
	errorRenderer  ServerErrorRenderer
	baseURL        string
	clientID       string
	// refreshLocks serializes the refresh grant per browser session (#621).
	refreshLocks *sessionRefreshLocks
	// refreshWait bounds how long a request waits for another request's refresh of its session.
	refreshWait time.Duration
}

// redirectBackMaxLen bounds the path and query the sign-in arm hands RedirToAuthorize as its
// return target. The request line is bounded only by the console's 64 KiB header limit and the
// handshake cookie the target is sealed into far below that, so a target past this is not sealed
// at all; no return target a page of this console produces approaches the bound. Within it, every
// byte a request target can carry costs at most three in the sealed encoding, so the target fits
// the cookie; a seal refused for its length all the same, as under a long enough base URL, falls
// back to the home page too (#620).
const redirectBackMaxLen = 512

// NewJWT constructs a DB-free JWT middleware. freshSessions re-reads the session under the
// refresh lock, and is the store sessionStore is; tokenRefresher sends the refresh grant;
// clientID is the client the sign-in redirect names.
func NewJWT(
	sessionStore sessionstore.Store,
	freshSessions freshSessionReader,
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
		freshSessions:  freshSessions,
		sessionName:    sessionName,
		tokenParser:    tokenParser,
		tokenRefresher: tokenRefresher,
		authHelper:     authHelper,
		errorRenderer:  errorRenderer,
		baseURL:        baseURL,
		clientID:       clientID,
		refreshLocks:   newSessionRefreshLocks(),
		refreshWait:    refreshWaitTimeout,
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
//     a grant of its own (#621). See refreshUnderLock.
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
			if oauthclient.RefreshDue(&tokenResponse, expiresAt, time.Now()) {
				refreshed, answered := m.refreshUnderLock(w, r, sess)
				if answered {
					return
				}
				if refreshed == nil {
					next.ServeHTTP(w, r)
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
	forget(sess)
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

// refreshUnderLock is steps 4 and 5: it takes the session's refresh lock, refreshes, and
// answers whatever the refresh came to, all before it releases the lock (#621). The clear a
// failed refresh saves is part of that: a request waiting for the lock must find the session
// cleared when it re-reads, not still holding the set this request just failed with, which it
// would present again, and the clear must not land over a set the waiter stored after it.
//
// It returns the token set the request carries on, or nil for a session signed out, the chain
// continuing unauthenticated; answered is a response already written, the error page or the
// redirect to the root, and the chain stops.
//
// The wait for the lock is bounded at refreshWaitTimeout and ends with the browser's departure. A
// request whose wait ends without the lock answers the error page, whatever its access token,
// sending no grant and writing nothing: the request holding the lock still owns the stored set.
// It runs no page either, even on an access token that has not expired: its session holds the set
// the holder is rotating, and a page that saved it, for a flash, would write that set back over
// the holder's answer once stored, since the console's store is last-writer-wins (#579), and the
// next request would present the refresh token the auth server had rotated away.
//
// That bound is what keeps the time budget. Against a hung auth server the request holding the
// lock spends at most the re-read, the grant, and then either the check and the write or the
// second re-read and the clear, each bounded at TokenExchangeTimeout or the session backend's
// own 10 seconds an attempt: 40 seconds. A request that waited and then took the lock spends
// up to refreshWaitTimeout more, 45 in all, which leaves the listener's 60 second write timeout
// room for the request's first load of the session and its page; one that gave up answers at
// refreshWaitTimeout. An unbounded wait added a holder's 40 to every request queued behind it.
func (m *JWT) refreshUnderLock(
	w http.ResponseWriter,
	r *http.Request,
	sess *sessionstore.Session,
) (refreshed *oauthclient.JwtInfo, answered bool) {
	ctx := r.Context()

	waitCtx, cancel := context.WithTimeout(ctx, m.refreshWait)
	release, err := m.refreshLocks.Lock(waitCtx, sess.ID)
	cancel()
	if err != nil {
		m.errorRenderer.InternalServerError(w, r,
			errs.Wrap(err, "unable to wait for another request's refresh of the session"))
		return nil, true
	}
	defer release()

	refreshed, refused, lookupErr, err := m.refreshToken(w, r, sess)
	if lookupErr != nil {
		// A re-read that could not be performed says nothing about the tokens, and nothing was
		// presented on its strength, so the session is neither cleared nor saved: the request
		// is refused as step 1 refuses a load that failed (#266).
		m.errorRenderer.InternalServerError(w, r, lookupErr)
		return nil, true
	}
	if refused != nil {
		if errors.Is(refused, oauthclient.ErrForeignToken) {
			m.endForeignSession(w, r, sess, refused)
			return nil, true
		}
		// Error, not Warn: an answer the parser refuses for anything but a foreign
		// issuer, a refreshed ID token naming another user or another sign-in than the
		// stored one above all, is not a changed setting, and someone must look at it
		// (#427 decision 14).
		slog.ErrorContext(ctx, "the refresh response was refused, clearing the session and redirecting to root",
			"error", refused)
		m.endSession(w, r, sess)
		return nil, true
	}
	if errors.Is(err, errSessionEndedMeanwhile) {
		// The stored session holds no tokens already, so nothing is saved: a save would write the
		// copy this request began with over whatever the ending request stored beside the clear,
		// the notice /auth/session-ended sets among them. The tokens leave the request's own
		// session, so a page that saves it later writes it signed out too.
		forget(sess)
		return nil, false
	}
	if err != nil {
		slog.WarnContext(ctx, "unable to refresh the access token, signing the session out", "error", err)
	}
	if refreshed == nil {
		if !m.clearTokens(w, r, sess) {
			return nil, true
		}
		return nil, false
	}
	return refreshed, false
}

// refreshToken sends the refresh grant for the session's current token set and, when the auth
// server answers, accepts its answer through the parser against the ID token it re-read and
// verified, before anything reaches the session. It returns the refreshed JwtInfo once it is
// stored; refused is a token set the parser will not trust, which ends the session; lookupErr
// is a re-read of the session that could not be performed, which refuses the request and
// clears nothing; err is a grant that could not be completed, which signs it out, or
// errSessionEndedMeanwhile, a session another request signed out while this one waited, which
// signs it out with nothing saved. With no refresh token all four are nil.
//
// The whole of it runs under the session's lock (#621). The auth server rotates refresh tokens
// strictly, so two grants for one session would present the same refresh token twice and the
// loser would be signed out over the winner's tokens. The request that waited for the lock
// therefore re-reads the session first and carries a token set another request stored as is;
// the grant, when there is one, presents the re-read set's refresh token. A grant the auth
// server refuses is answered the same way (supersedingTokens): a set newer than the one
// presented means another console won the rotation while this one was asking, and the newer
// set is carried rather than cleared.
//
// A set carried either way is written into sess, the request's own session, which every later
// Get on the request answers with (#269), and is not saved: the set is stored already, and a
// handler further down that saves the session, for a flash say, must write that set and not
// the one the request began with, whose refresh token the auth server has rotated away (RFC
// 6749 section 6).
func (m *JWT) refreshToken(
	w http.ResponseWriter,
	r *http.Request,
	sess *sessionstore.Session,
) (refreshed *oauthclient.JwtInfo, refused error, lookupErr error, err error) {
	// The lock makes this request the only refresher of this session in this console, but not
	// the first: another request may have refreshed while this one waited for it. The session
	// is re-read before anything is sent, so a token set another request stored is carried as
	// is, and a set that is still due is the one the grant presents.
	current, err := m.reReadSession(r)
	if err != nil {
		return nil, nil, err, nil
	}
	stored, hasStored := current.Values[sessionkeys.JWT].(oauth.TokenResponse)
	expiresAt, hasExpiry := current.Values[sessionkeys.JWTExpiresAt].(int64)
	if !hasStored || !hasExpiry || stored.IdToken == "" {
		// Another request ended this session while this one waited for the lock; this
		// request ends it the same way, presenting nothing.
		return nil, nil, nil, errSessionEndedMeanwhile
	}
	// Step 3's check, restated under the lock for the set this request may not have read
	// itself: carried or refreshed, the ID token that reaches the context is verified. Its
	// failure is refused rather than err, so the session ends whatever request stored the
	// set, and the classification — foreign or otherwise — stays the parser's.
	previous, err := m.tokenParser.DecodeAndValidateStoredIDToken(r.Context(), stored.IdToken)
	if err != nil {
		return nil, err, nil, nil
	}
	if !oauthclient.RefreshDue(&stored, expiresAt, time.Now()) {
		carry(sess, stored, expiresAt)
		return &oauthclient.JwtInfo{TokenResponse: stored, IdToken: previous}, nil, nil, nil
	}

	if stored.RefreshToken == "" {
		return nil, nil, nil, nil
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
		newer, newerExpiresAt, rereadErr := m.supersedingTokens(r, stored, err)
		if rereadErr != nil {
			return nil, nil, rereadErr, nil
		}
		if newer != nil {
			carry(sess, newer.TokenResponse, newerExpiresAt)
			return newer, nil, nil, nil
		}
		return nil, nil, nil, err
	}

	// The refresh is not done when the grant returns; it is done when the new token is written
	// down. The auth server has already revoked the old one, so a check or a write refused because
	// the browser went away leaves the administrator holding a dead token -- the very outcome the
	// grant's detachment exists to prevent, arriving two lines later instead. So what follows runs
	// on a context of its own, detached the same way: WithoutCancel keeps the request's values, so
	// request_id still reaches every record, and TokenExchangeTimeout bounds the check and the
	// write together. That is a budget of its own after the grant's, one of those refreshUnderLock
	// counts against the listener's write timeout (#338, #441 decision 2, #621).
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
		return nil, err, nil, nil
	}
	// RFC 6749 section 6: a refresh whose scope is omitted is "treated as equal to the scope
	// originally granted", which is the stored response's own, set to the effective grant when it
	// arrived.
	accepted.TokenResponse.Scope = oauthclient.EffectiveScope(accepted.TokenResponse.Scope, stored.Scope)

	// ServerSideStore hands the request's own context to its backend, so the store has to be
	// given a request carrying the detached context rather than the browser's. sess is the
	// request's own session, the one every Get on it answers with (#269), so what is written
	// here is what the rest of the request reads and any later save writes.
	detachedReq := r.WithContext(ctx)

	sess.Values[sessionkeys.JWT] = accepted.TokenResponse
	sess.Values[sessionkeys.JWTExpiresAt] = oauthclient.ExpiresAt(&accepted.TokenResponse, time.Now())
	err = m.sessionStore.Save(detachedReq, w, sess)
	if err != nil {
		return nil, nil, nil, errs.Errorf("unable to save the session: %v", err)
	}

	return accepted, nil, nil, nil
}

// carry writes a token set another request stored, and its expiry, into the request's own
// session, without saving it: see refreshToken.
func carry(sess *sessionstore.Session, stored oauth.TokenResponse, expiresAt int64) {
	sess.Values[sessionkeys.JWT] = stored
	sess.Values[sessionkeys.JWTExpiresAt] = expiresAt
}

// forget deletes the token values from the request's own session without saving it: see
// refreshUnderLock.
func forget(sess *sessionstore.Session) {
	delete(sess.Values, sessionkeys.JWT)
	delete(sess.Values, sessionkeys.JWTExpiresAt)
}

// reReadSession loads the session as the backend holds it now, past the store's per-request
// memo: Get answers later callers on a request from the session it already loaded (#269), which
// is the copy this request read at its start and not the row another request — on this console
// or another — may have written since. GetFresh neither reads nor writes that memo, so the
// request's own session, the one the write below and any later save reach through, is untouched.
// The load runs detached from the browser's cancellation and bounded at TokenExchangeTimeout,
// as the check and the write after the grant do, keeping the request's values, request_id among
// them, so its records still name the request (#441 decision 2).
func (m *JWT) reReadSession(r *http.Request) (*sessionstore.Session, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), oauthclient.TokenExchangeTimeout)
	defer cancel()
	current, err := m.freshSessions.GetFresh(r.WithContext(ctx), m.sessionName)
	if err != nil {
		return nil, errs.Wrap(err, "unable to re-read the session under the refresh lock")
	}
	return current, nil
}

// supersedingTokens re-reads the session after a grant the auth server refused, asking whether
// another request — on another replica of this console, since this one holds the session's
// refresh lock — has stored a token set newer than the one this request presented: a strictly
// rotating auth server refuses the second presentation of a refresh token (#128), so the
// refusal usually means the rotation was won elsewhere while this grant was in flight. The
// newer set is returned, with its expiry, once its ID token verifies. newer is nil when the
// session still holds the one presented — the token set is genuinely dead, and the sign-out
// stands — and when nothing newer verifies, which is the sign-out's answer too. lookupErr is a
// re-read that could not be performed, which is neither: nothing is known of what the session
// holds, so nothing may be cleared on its strength.
func (m *JWT) supersedingTokens(r *http.Request, presented oauth.TokenResponse, refusedGrant error) (newer *oauthclient.JwtInfo, expiresAt int64, lookupErr error) {
	current, err := m.reReadSession(r)
	if err != nil {
		return nil, 0, err
	}
	stored, hasStored := current.Values[sessionkeys.JWT].(oauth.TokenResponse)
	storedExpiresAt, hasExpiry := current.Values[sessionkeys.JWTExpiresAt].(int64)
	if !hasStored || !hasExpiry || stored == presented {
		return nil, 0, nil
	}
	idToken, err := m.tokenParser.DecodeAndValidateStoredIDToken(r.Context(), stored.IdToken)
	if err != nil {
		return nil, 0, nil
	}
	slog.WarnContext(r.Context(),
		"the refresh grant was refused, but a token set newer than the one it presented had been stored meanwhile, so the session keeps it",
		"error", refusedGrant)
	return &oauthclient.JwtInfo{TokenResponse: stored, IdToken: idToken}, storedExpiresAt, nil
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
					//
					// RedirToAuthorize seals the handshake into a cookie of its own and
					// writes no session row, so an anonymous request costs the auth server
					// nothing here (#620). The return URL is bounded so the cookie it is
					// sealed into no longer tracks the request line's length.
					home := m.baseURL + "/"
					redirectBack := m.baseURL + r.URL.RequestURI()
					if len(r.URL.RequestURI()) > redirectBackMaxLen {
						// No page this console renders approaches the bound in path and
						// query, so a line past it is not a return target, and the home
						// page — the one destination that requires no sign-in — takes the
						// browser instead (#620).
						redirectBack = home
					}
					scope := m.buildScopeString(scopesAnyOf)
					err := m.authHelper.RedirToAuthorize(w, r, m.clientID, scope, redirectBack)
					if errors.Is(err, sessionstore.ErrCookieValuesTooLong) && redirectBack != home {
						// A target within the bound that still did not fit the cookie is not a
						// page's either, so the home page again. A refused seal has written
						// neither the cookie nor the redirect (#620).
						err = m.authHelper.RedirToAuthorize(w, r, m.clientID, scope, home)
					}
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
