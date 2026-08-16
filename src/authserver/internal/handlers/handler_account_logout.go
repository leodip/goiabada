package handlers

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/urlutil"
	"github.com/pkg/errors"
)

func HandleAccountLogoutGet(
	httpHelper HttpHelper,
	httpSession sessions.Store,
	authHelper AuthHelper,
	database data.Database,
	tokenParser TokenParser,
	auditLogger AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		r = refineLogoutLocale(r)
		doLogout(w, r, httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)
	}
}

// logoutFormPath is where the logout consent form posts. It duplicates the route registered in
// internal/server/routes.go on purpose: the form needs the path WITHOUT the query string that
// served it, so it cannot use action="" (see the comment in logout_consent.html), and taking it
// from r.URL.Path would silently start posting somewhere else the day anything rewrites the path.
const logoutFormPath = "/auth/logout"

// refineLogoutLocale honours a ui_locales the RP sent, which the global locale middleware cannot
// see for itself. resolveLocale in core/i18n reads r.URL.Query() only, above a comment explaining
// that it must not call ParseForm because that would consume the request body, so it works for a
// GET and for nothing else. r.FormValue reads the query and the body, so this one call covers all
// three shapes /auth/logout has: a GET carrying ?ui_locales, the consent form posting it back as a
// hidden field, and an RP posting it directly in a body.
//
// Without this, a consent page rendered in the locale the RP asked for would be followed by a
// signed-out page in a different one, because the confirming POST carries the parameter in its body
// (#109). Same pattern as HandleAuthorizeGet, and the return value must be assigned.
func refineLogoutLocale(r *http.Request) *http.Request {
	if uiLocales := i18n.SanitizeUILocales(r.FormValue("ui_locales")); len(uiLocales) > 0 {
		return i18n.RefineLocalizerWithUILocales(r, uiLocales)
	}
	return r
}

// renderLogoutConsent renders the logout consent page, carrying forward the parameters the
// confirming POST needs and NOT the id_token_hint. See logout_consent.html for why the hint is
// dropped and why state is treated differently from the other three.
//
// hint says how the request's id_token_hint was classified, and it decides one thing: whether
// client_id survives the hop. It does when no hint was supplied, because client_id is then the only
// thing that can authorize a post-logout redirect and doing so is its documented primary purpose. It
// must NOT when a hint was supplied and rejected: the confirming POST is hintless by design, so a
// surviving client_id would authorize the redirect that the rejected hint was specifically denied,
// and the detected error would become a redirect after all. RP-Initiated Logout 1.0 section 4 forbids
// that twice, once as "any operations requiring the information that failed to correctly validate
// MUST be aborted", and once as "the OP MUST not perform post-logout redirection to an RP" upon
// detecting errors (#109).
func renderLogoutConsent(w http.ResponseWriter, r *http.Request, httpHelper HttpHelper, hint hintState) {
	state, statePresent := httpHelper.LookupFromUrlQueryOrFormPost(r, "state")

	clientId := ""
	if hint == hintAbsent {
		clientId = httpHelper.GetFromUrlQueryOrFormPost(r, "client_id")
	}

	bind := map[string]interface{}{
		"formAction":            logoutFormPath,
		"postLogoutRedirectUri": httpHelper.GetFromUrlQueryOrFormPost(r, "post_logout_redirect_uri"),
		"clientId":              clientId,
		"state":                 state,
		"statePresent":          statePresent,
		"uiLocales":             httpHelper.GetFromUrlQueryOrFormPost(r, "ui_locales"),
	}

	err := httpHelper.RenderTemplate(w, r, "/layouts/auth_layout.html", "/logout_consent.html", bind)
	if err != nil {
		httpHelper.InternalServerError(w, r, err)
	}
}

// renderLoggedOut renders the terminal page for a logout that completed without redirecting the
// End-User anywhere. Every shape that tears down but has no redirect target ends here: a hinted
// request that sent no post_logout_redirect_uri, a hintless confirmation, and a target the spec
// forbids redirecting to.
//
// redirectDeclined adds one sentence, and only when a target was supplied and refused. It names no
// failed check, so it tells the End-User why they are looking at Goiabada instead of their
// application without disclosing which URIs are registered (#109).
func renderLoggedOut(w http.ResponseWriter, r *http.Request, httpHelper HttpHelper, redirectDeclined bool) {
	bind := map[string]interface{}{
		"redirectDeclined": redirectDeclined,
	}

	err := httpHelper.RenderTemplate(w, r, "/layouts/auth_layout.html", "/logged_out.html", bind)
	if err != nil {
		httpHelper.InternalServerError(w, r, err)
	}
}

// isEncryptedIDTokenHint reports whether the hint is a compact JWE (5
// dot-separated segments) rather than a compact JWS (3 segments). An encrypted
// hint must be decrypted with the client's key before validation; a plain
// signed hint is validated as-is. See OpenID Connect Core 1.0 §2 (an encrypted
// ID Token is a Nested JWT).
func isEncryptedIDTokenHint(hint string) bool {
	return strings.Count(hint, ".") == 4
}

// decryptIDTokenHint decrypts a JWE-encrypted id_token_hint. The token is a JWE
// (dir + A256GCM) whose key is derived from the client secret, per the scheme
// documented in integration/endpoints.mdx and implemented in
// encryption.DecryptIDTokenHintJWE. client_id selects which client's secret to
// use, as required by RP-Initiated Logout for symmetrically-encrypted hints.
//
// The returned error is for the server log and never for the End-User. Every failure here means the
// hint cannot be confirmed, and the spec's answer to a hint the OP cannot confirm is to ask the
// End-User rather than to show them a diagnostic about a request their relying party built (#109).
func decryptIDTokenHint(idTokenHint, clientID string, database data.Database) (string, error) {
	client, err := database.GetClientByClientIdentifier(nil, clientID)
	if err != nil {
		slog.Error("logout: client lookup failed", "clientId", clientID, "err", err)
		return "", errors.Wrap(err, "unable to look up the client named by client_id")
	}
	if client == nil {
		slog.Error("logout: client_id names no client", "clientId", clientID)
		return "", errors.New("client_id names no client")
	}

	clientSecret, err := encryption.DecryptData(client.ClientSecretEncrypted)
	if err != nil {
		slog.Error("logout: client secret decrypt failed", "err", err)
		return "", errors.Wrap(err, "unable to decrypt the client secret")
	}

	decryptedToken, err := encryption.DecryptIDTokenHintJWE(idTokenHint, clientSecret)
	if err != nil {
		slog.Error("logout: id_token_hint decrypt failed", "err", err)
		return "", errors.Wrap(err, "unable to decrypt the id_token_hint")
	}

	return decryptedToken, nil
}

// hintState is what classifyIdTokenHint decided about a request's id_token_hint, and it has three
// values rather than two on purpose. Collapsing "supplied and rejected" into "absent" is what let a
// detected client_id/aud mismatch go on to authorize a post-logout redirect: the rejected hint
// vanished, the unauthenticated client_id beside it survived, and client_id then chose the target.
// OpenID Connect RP-Initiated Logout 1.0 section 4 forbids that twice over, once as "any operations
// requiring the information that failed to correctly validate MUST be aborted and the information
// that failed to validate MUST NOT be used", and once as "the OP MUST not perform post-logout
// redirection to an RP" upon detecting errors (#109).
type hintState int

const (
	// hintRejected is the zero value deliberately. A classification nobody filled in then asks the
	// End-User and earns no redirect, which is the fail-safe direction of the three: the worst it can
	// do is show a consent page to somebody who need not have seen one.
	hintRejected hintState = iota
	hintAbsent
	hintConfirmed
)

func (h hintState) String() string {
	switch h {
	case hintAbsent:
		return "absent"
	case hintConfirmed:
		return "confirmed"
	default:
		return "rejected"
	}
}

// hintClassification is classifyIdTokenHint's answer. client and sessionIdentifier are populated for
// hintConfirmed and left empty otherwise, so a caller that forgets to check the state still cannot
// scope a teardown or authorize a redirect from a hint that failed to validate.
type hintClassification struct {
	state             hintState
	client            *models.Client
	sessionIdentifier string
}

// nonIdTokenTypValues are the "typ" claim values Goiabada stamps on tokens that are NOT ID Tokens:
// enums.TokenTypeBearer on access tokens, and the two refresh-token markers "Offline" and "Refresh",
// which are unexported constants in src/core/oauth/token_issuer.go. generateIdTokenCore emits no typ
// at all, and neither does the short-lived hint HandleAPIAccountLogoutRequestPost mints, so this
// rejects nothing an RP can legitimately present.
//
// It is a denylist rather than a requirement that typ be "ID" for exactly that reason: no ID Token
// this server issues carries the claim, so requiring it would reject every real hint.
var nonIdTokenTypValues = map[string]bool{
	enums.TokenTypeBearer.String():  true, // "Bearer", access tokens
	enums.TokenTypeRefresh.String(): true, // "Refresh", session-bound refresh tokens
	"Offline":                       true, // offline refresh tokens; the constant is unexported
}

// classifyIdTokenHint decides whether a request's id_token_hint can be trusted, and returns which of
// the three states it is in along with the client and session a confirmed hint names.
//
// The error return is reserved for the two lookups that decide whether the hint's session may be
// trusted: the session the hint's sid names, and the user its sub names. Every other failure is a
// rejection, because a hint the OP cannot confirm is not an error to report, it is a reason to ask
// the End-User. RP-Initiated Logout 1.0 section 2: "the OP MUST ask the End-User this question if an
// id_token_hint was not provided or if the supplied ID Token does not belong to the current OP
// session with the RP and/or currently logged in End-User".
//
// Three properties are worth stating because losing any of them turns this into a hole rather than a
// bug.
//
// The hint is read for PRESENCE, not for a value. An id_token_hint supplied empty is Rejected rather
// than Absent, because the CSRF middleware exempts a cross-site POST on presence and cannot judge
// validity. If this helper read "id_token_hint=" as no hint at all, an exempted POST would take the
// no-hint branch, which tears the whole session down without consent (#109 decision 13).
//
// The claims are checked BY HAND, all of them, because the parse deliberately runs with the
// library's claims validation off. That flag is jwt.WithoutClaimsValidation() rather than an exp
// switch, so it disables every claim check the library performs; the signature survives it, since a
// signature is not a claim. Turning it off is what lets an expired hint reach the tolerance gate
// below instead of being refused before the OP has looked at the session, per RP-Initiated Logout
// 1.0 section 2: "The OP SHOULD accept ID Tokens when the RP identified by the ID Token's aud claim
// and/or sid claim has a current session or had a recent session at the OP, even when the exp time
// has passed."
//
// A confirmed hint's sub OWNS the session its sid names. Confirming one that does not lets a hint
// signed for one user tear down another user's session, silently, because the confirmed branch is the
// one that skips the consent page. That is the ownership gate at the bottom, and it is the reason the
// session is now looked up whether or not the hint has expired (#133).
func classifyIdTokenHint(
	r *http.Request,
	httpHelper HttpHelper,
	database data.Database,
	tokenParser TokenParser,
) (hintClassification, error) {

	reject := func(gate string, args ...interface{}) (hintClassification, error) {
		slog.Error("logout: id_token_hint rejected at the "+gate+" gate", args...)
		return hintClassification{state: hintRejected}, nil
	}

	hint, present := httpHelper.LookupFromUrlQueryOrFormPost(r, "id_token_hint")
	if !present {
		return hintClassification{state: hintAbsent}, nil
	}
	if len(hint) == 0 {
		return reject("presence", "reason", "id_token_hint was supplied with an empty value")
	}

	// Presence-aware, like the hint above and for the same reason: the client_id gate further down
	// fires when the parameter is PRESENT, and a value-only read cannot tell "client_id=" from no
	// client_id at all. See the comment on that gate for why the difference matters (#109).
	clientId, clientIdPresent := httpHelper.LookupFromUrlQueryOrFormPost(r, "client_id")

	// An encrypted hint is a Nested JWT (OpenID Connect Core 1.0 section 2) and must be decrypted
	// before anything can be read from it. The key derives from a client secret, so client_id is what
	// says whose. This one reads the value rather than the presence, correctly: an empty client_id
	// selects no key whether it was supplied empty or left out.
	if isEncryptedIDTokenHint(hint) {
		if len(clientId) == 0 {
			return reject("JWE key selection", "reason", "an encrypted id_token_hint needs client_id to select the key")
		}
		decrypted, err := decryptIDTokenHint(hint, clientId, database)
		if err != nil {
			// decryptIDTokenHint has already logged which half failed.
			return reject("JWE decryption")
		}
		hint = decrypted
	}

	idToken, err := tokenParser.DecodeAndValidateTokenString(hint, nil, false)
	if err != nil || idToken == nil {
		return reject("parse and signature", "err", err)
	}

	// Is this an ID Token at all? Without this gate a session-bound ACCESS token satisfies every
	// other check here whenever a resource identifier happens to equal a client identifier, which
	// nothing in the product prevents: client identifiers are checked for uniqueness against clients
	// and resource identifiers against resources, and no code compares the two namespaces. An access
	// token carries iss, sub, iat, nbf, exp and a session-bound sid, and its aud is the resource
	// identifier, so GetClientByClientIdentifier resolves it under the collision. Confirming it would
	// skip the consent page entirely and end that client's half of the session (#109).
	if typ := idToken.GetStringClaim("typ"); nonIdTokenTypValues[typ] {
		return reject("ID-Token shape", "reason", "typ names a token that is not an ID Token", "typ", typ)
	}

	// sub and iat are REQUIRED on an ID Token by OpenID Connect Core 1.0 section 2, and RP-Initiated
	// Logout 1.0 section 2 defines this parameter as an "ID Token previously issued by the OP", so
	// establishing ID-Token shape belongs here. They do not close the access-token hole above on
	// their own, since an access token carries both.
	//
	// Kept rather than measured and discarded: the ownership gate at the bottom compares it against
	// the owner of the session sid names.
	subject := idToken.GetStringClaim("sub")
	if len(subject) == 0 {
		return reject("ID-Token shape", "reason", "sub is missing or empty")
	}
	if _, ok := idToken.GetIntClaim("iat"); !ok {
		return reject("ID-Token shape", "reason", "iat is missing or is not an integral number")
	}

	settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
	issuer := idToken.GetStringClaim("iss")
	if len(issuer) == 0 {
		return reject("iss", "reason", "iss is missing")
	}
	if issuer != settings.Issuer {
		return reject("iss", "reason", "iss is not this server", "iss", issuer)
	}

	// GetStringClaim yields "" for an aud that arrived as an array, which is right for a hint: an ID
	// Token this server issues has exactly one audience, the client identifier.
	clientIdentifier := idToken.GetStringClaim("aud")
	if len(clientIdentifier) == 0 {
		return reject("aud", "reason", "aud is missing, or is not a single string")
	}

	// RP-Initiated Logout 1.0 section 2: "When both client_id and id_token_hint are present, the OP
	// MUST verify that the Client Identifier matches the one used when issuing the ID Token."
	//
	// PRESENT, not non-empty. "client_id=" is a parameter the request carried, and an empty string is
	// not a Client Identifier valid at this server, so it fails the check and rejects the hint exactly
	// as a wrong client_id does. Reading it as absent would skip a MUST on a parameter that arrived.
	// RP-Initiated Logout is silent on empty-valued parameters; RFC 6749 section 3.1's "Parameters
	// sent without a value MUST be treated as if they were omitted from the request" is stated for the
	// OAuth authorization endpoint and is not carried into this one, which serializes per OpenID
	// Connect Core's Query String and Form Serialization instead.
	//
	// What it costs a caller who sends "client_id=" beside an otherwise good hint: a consent page
	// instead of a silent logout, a whole-session teardown instead of a per-client one, and no
	// post-logout redirect. That is the same price any non-matching client_id already pays here, and
	// the fail-safe direction of both (#109).
	//
	// Compared before the lookup so a mismatch costs no query.
	if clientIdPresent && clientId != clientIdentifier {
		return reject("client_id", "reason", "client_id does not match the aud the hint is signed over",
			"clientId", clientId, "aud", clientIdentifier)
	}

	client, err := database.GetClientByClientIdentifier(nil, clientIdentifier)
	if err != nil {
		// Rejected rather than propagated, unlike the expiry lookup below. This runs before any
		// teardown, so a 500 here would put the End-User on a terminal page while still signed in,
		// which is the defect #109 exists to remove. Rejecting instead widens the teardown from
		// per-client to whole-session and forbids the redirect, which is the fail-safe direction.
		return reject("aud", "reason", "the client lookup failed", "aud", clientIdentifier, "err", err)
	}
	if client == nil {
		return reject("aud", "reason", "aud names no client", "aud", clientIdentifier)
	}

	now := time.Now().UTC()

	// nbf is optional on an ID Token, but a present one still binds. Raw map presence rather than a
	// zero-value test, so a present-but-malformed nbf is refused instead of read as absent.
	if _, hasNbf := idToken.Claims["nbf"]; hasNbf {
		nbf, ok := idToken.GetIntClaim("nbf")
		if !ok {
			return reject("nbf", "reason", "nbf is present and is not an integral number")
		}
		if time.Unix(nbf, 0).After(now) {
			return reject("nbf", "reason", "nbf is in the future")
		}
	}

	// exp must still be THERE. Decision 14 tolerates a past exp, not a missing one: a hint with no
	// expiry at all is an indefinitely replayable forced-logout token, which is what the tolerance
	// below is bounded to avoid becoming.
	exp, ok := idToken.GetIntClaim("exp")
	if !ok {
		return reject("exp", "reason", "exp is missing or is not an integral number")
	}

	sid := idToken.GetStringClaim("sid")
	if len(sid) == 0 {
		return reject("sid", "reason", "sid is missing")
	}

	sessionIdentifier := ""
	if v := r.Context().Value(constants.ContextKeySessionIdentifier); v != nil {
		sessionIdentifier, _ = v.(string)
	}
	if len(sessionIdentifier) == 0 {
		// An RP may end a session with a hint alone and no cookie in play, which is what makes
		// RP-initiated logout work from a back-channel-less RP, so the hint's own sid names the
		// session. MiddlewareSessionIdentifier fills the context only when the cookie resolves to a
		// live row, so "no identifier" covers a cookie whose session has already gone too.
		sessionIdentifier = sid
	} else if sid != sessionIdentifier {
		// Not an error and not a 500, which is what it used to be. The spec's answer to a hint that
		// does not belong to the current session is to ask the End-User, and a user whose session was
		// reaped or replaced between signing in and logging out reaches this with nobody at fault.
		return reject("sid", "reason", "sid names a different session than the browser's")
	}

	// One lookup, read by the expiry-tolerance branch below and by the ownership gate after it. It
	// used to sit inside that branch, so a hint that had not expired never loaded the session at all
	// and there was nothing to compare its sub against.
	userSession, err := database.GetUserSessionBySessionIdentifier(nil, sessionIdentifier)
	if err != nil {
		// Propagated rather than read as "no such session". A database failure and a row that is
		// not there have different answers, and conflating them would decide whether an expired
		// hint is honoured, and whether an ownership mismatch is seen, on the database's health. The
		// caller surfaces this as a 500, and the teardown reads the same row through the same call,
		// so it would have failed anyway.
		return hintClassification{}, err
	}

	if time.Unix(exp, 0).Before(now) {
		if userSession == nil {
			return reject("expiry tolerance", "reason", "exp has passed and sid names no live session")
		}
		// "Recent session" has exactly one meaning in this codebase: the row is still there.
		slog.Info("logout: accepting an expired id_token_hint because its session is still live",
			"aud", clientIdentifier)
	}

	// Does the session this hint names belong to the End-User the hint is signed over? An artifact
	// carrying both a user identity and a session identifier may act on that session only when the
	// two agree, and until this gate existed nothing here compared them: sub was read for presence
	// and sid was read for whether it matched the browser's cookie, never for whose it was.
	//
	// Rejecting is the required outcome and not merely the cautious one. RP-Initiated Logout 1.0
	// section 2: "the OP MUST ask the End-User this question if an id_token_hint was not provided or
	// if the supplied ID Token does not belong to the current OP session with the RP and/or currently
	// logged in End-User". A hint signed for one user over another user's session is exactly that,
	// and hintConfirmed is the one branch that does not ask. The same section adds that a sid not
	// corresponding to a session at the OP SHOULD be treated as suspect.
	//
	// A session row that is not there skips the gate, deliberately. Ownership cannot be decided
	// without it, sessions are swept after hours while the grants naming them last far longer, and a
	// swept session is the ordinary state of a healthy older hint (#133).
	//
	// Nothing legitimate reaches the refusal: a code's user and the owner of the session it names
	// always agree once the ceremony is bound to a session it owns, and session ownership never
	// changes afterwards, so only an artifact issued before that rule existed can disagree.
	if userSession != nil {
		user, err := database.GetUserBySubject(nil, subject)
		if err != nil {
			// Propagated, like the session lookup above and unlike the client lookup further up. Both
			// of these decide whether the hint's session may be trusted at all, and answering that on
			// the database's health is what the comment above refuses to do.
			return hintClassification{}, err
		}
		if user == nil || user.Id != userSession.UserId {
			return reject("session ownership", "reason", "sid names a session that does not belong to sub")
		}
	}

	return hintClassification{
		state:             hintConfirmed,
		client:            client,
		sessionIdentifier: sessionIdentifier,
	}, nil
}

// handleExistingSessionOnLogout performs the per-client teardown a CONFIRMED id_token_hint earns:
// delete this client's row on the session, and the session row itself when that client was the last
// one on it.
//
// Per-client rather than whole-session, unchanged by this rewrite, because #129 decided that logging
// one client out must not stop the session-bound tokens of the other clients sharing that session.
// Two of its integration tests exist so that widening this has to be deliberate (#109 decision 3).
//
// The sid guard this used to open with is gone. Whether the hint names the browser's session is part
// of whether the hint can be confirmed at all, and classifyIdTokenHint decides that before anything
// reaches here. It used to be decided here, by returning an error the caller turned into a 500, which
// is what a user whose session had merely been reaped or replaced saw (#109 decision 11).
//
// A lookup or delete failure is returned so the caller can surface a 500. A session row that is not
// there is nothing to tear down rather than a failure, and those two used to be one branch returning
// a variable that was sometimes nil to mean both (#109 item 4).
func handleExistingSessionOnLogout(
	r *http.Request,
	sessionIdentifier string,
	client *models.Client,
	database data.Database,
	auditLogger AuditLogger,
	authHelper AuthHelper,
) error {
	userSession, err := database.GetUserSessionBySessionIdentifier(nil, sessionIdentifier)
	if err != nil {
		return err
	}
	if userSession == nil {
		return nil
	}

	err = database.UserSessionLoadClients(nil, userSession)
	if err != nil {
		return err
	}

	err = database.UserSessionClientsLoadClients(nil, userSession.Clients)
	if err != nil {
		return err
	}

	for idx, sessionClient := range userSession.Clients {
		if sessionClient.Client.ClientIdentifier == client.ClientIdentifier {
			err = database.DeleteUserSessionClient(nil, userSession.Clients[idx].Id)
			if err != nil {
				return err
			}

			auditLogger.Log(constants.AuditDeletedUserSessionClient, map[string]interface{}{
				"userId":        userSession.UserId,
				"userSessionId": userSession.Id,
				"clientId":      sessionClient.Client.Id,
				"loggedInUser":  authHelper.GetLoggedInSubject(r),
			})

			if len(userSession.Clients) == 1 {
				err = database.DeleteUserSession(nil, userSession.Id)
				if err != nil {
					return err
				}

				auditLogger.Log(constants.AuditLogout, map[string]interface{}{
					"userId":            userSession.UserId,
					"sessionIdentifier": sessionIdentifier,
					"loggedInUser":      authHelper.GetLoggedInSubject(r),
				})
			}
			break
		}
	}

	return nil
}

func HandleAccountLogoutPost(
	httpHelper HttpHelper,
	httpSession sessions.Store,
	authHelper AuthHelper,
	database data.Database,
	tokenParser TokenParser,
	auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r = refineLogoutLocale(r)
		doLogout(w, r, httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)
	}
}

// doLogout is the whole endpoint, entered identically by GET and by POST. Four steps, and the design
// is in keeping them independent:
//
//  1. Classify the id_token_hint into confirmed, absent or rejected.
//  2. Decide whether the End-User has to be asked.
//  3. Resolve the redirect target, which is only ever a question about the RESPONSE.
//  4. Tear down and respond, reading nothing step 3 produced.
//
// Step 4 not reading step 3 is the fix for #109's first item and its six siblings at once. Every
// error path in this endpoint used to return before both the database teardown and the cookie wipe,
// so a request the OP considered malformed rendered a page saying so and left the user signed in.
// Hint validity now decides only whether the End-User is asked, redirect-target validity decides only
// whether a redirect happens, and neither decides whether the logout happens.
func doLogout(
	w http.ResponseWriter,
	r *http.Request,
	httpHelper HttpHelper,
	httpSession sessions.Store,
	authHelper AuthHelper,
	database data.Database,
	tokenParser TokenParser,
	auditLogger AuditLogger,
) {
	// 1. Classify.
	hint, err := classifyIdTokenHint(r, httpHelper, database, tokenParser)
	if err != nil {
		// Classification propagates a failure instead of rejecting for one narrow reason: a database
		// fault in either of the two lookups that decide whether the hint's session may be trusted,
		// the session its sid names and the user its sub names. Everything else is a rejection,
		// because a hint the OP cannot confirm is a reason to ask rather than an error to report.
		httpHelper.InternalServerError(w, r, err)
		return
	}

	// 2. Decide whether to ask. RP-Initiated Logout 1.0 section 2: "the OP MUST ask the End-User this
	// question if an id_token_hint was not provided or if the supplied ID Token does not belong to the
	// current OP session with the RP and/or currently logged in End-User".
	switch {
	case hint.state == hintConfirmed:
		// The hint names a client and a session and validates, so there is nobody to ask.

	case hint.state == hintAbsent && r.Method == http.MethodPost:
		// The confirming submission of the consent page. A hintless POST is not CSRF-exempt, so it
		// had to pass the origin check, so it was submitted by a document served from this origin.
		// That is what makes it consent rather than a cross-site request, and it is why the consent
		// form drops the hint (#109 decision 13). It used to be a CSRF token that carried this
		// argument; #155 replaced the token with the origin check, and the conclusion is unchanged.

	case hint.state == hintRejected && r.Method == http.MethodPost:
		redirectToHintlessLogout(w, r, httpHelper)
		return

	default:
		// Absent on GET, and rejected on either method that is not POST. Ask.
		renderLogoutConsent(w, r, httpHelper, hint.state)
		return
	}

	// 3. Resolve the redirect target, independently of step 2 above and of step 4 below.
	postLogoutRedirectURI := httpHelper.GetFromUrlQueryOrFormPost(r, "post_logout_redirect_uri")
	location := ""
	if len(postLogoutRedirectURI) > 0 {
		// A confirmed hint carries its own client, resolved from the aud it is signed over. Only step
		// 2's second row reaches here with no hint, and there the sole thing that can authorize a
		// target is client_id, which is that parameter's documented primary purpose: RP-Initiated
		// Logout 1.0 section 2, "The most common use case for this parameter is to specify the Client
		// Identifier when post_logout_redirect_uri is used but id_token_hint is not". That is the
		// "other means of confirming the legitimacy of the post-logout redirection target" section 3
		// requires before an OP may redirect.
		//
		// A rejected hint never arrives here at all, because step 2 always asks first, and the consent
		// page it renders drops client_id. That is how a detected error is kept from becoming a
		// redirect (#109 decision 15).
		client := hint.client
		if hint.state == hintAbsent {
			client = clientForPostLogoutRedirect(httpHelper.GetFromUrlQueryOrFormPost(r, "client_id"), database)
		}
		location = postLogoutRedirectLocation(r, httpHelper, database, client, postLogoutRedirectURI)
	}

	// 4. Tear down, which the step above cannot prevent.
	if hint.state == hintConfirmed {
		// Scoped to the client the hint's SIGNED aud names. client_id is never allowed to scope a
		// teardown, because it is unauthenticated and a caller could name any client; it is trusted
		// only for deciding whether a supplied URI is registered to the client it names, which is
		// self-limiting (#109).
		if err := handleExistingSessionOnLogout(r, hint.sessionIdentifier, hint.client, database, auditLogger, authHelper); err != nil {
			// A failed teardown is the one thing here that does deserve a 500: the End-User is still
			// signed in and saying otherwise would be a lie. Contrast the redirect resolution above,
			// whose failures deliberately degrade to "no redirect".
			httpHelper.InternalServerError(w, r, err)
			return
		}
		// AuditLogout is emitted inside, and only when the session row itself goes, which is what this
		// path did before the rewrite and what decision 3 keeps.
	} else {
		// No client to scope to, so the whole session goes (#109 decision 2).
		sessionIdentifier := ""
		if v := r.Context().Value(constants.ContextKeySessionIdentifier); v != nil {
			sessionIdentifier, _ = v.(string)
		}

		userId := int64(0)
		if len(sessionIdentifier) > 0 {
			var err error
			userId, err = deleteWholeUserSession(r, sessionIdentifier, database, auditLogger, authHelper)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		// Unconditional, as before, so a logout with no usable session still records the attempt.
		// There being no session to end is not a failure: it may have been reaped or ended from
		// another device, and the End-User asking to leave has got what they asked for either way.
		auditLogger.Log(constants.AuditLogout, map[string]interface{}{
			"userId":            userId,
			"sessionIdentifier": sessionIdentifier,
			"loggedInUser":      authHelper.GetLoggedInSubject(r),
		})
	}

	// 5. Respond.
	finishLogout(w, r, httpHelper, httpSession, location, len(postLogoutRedirectURI) > 0)
}

// redirectToHintlessLogout answers a POST whose id_token_hint could not be confirmed with a 303 back
// to the GET binding, carrying what the consent page still needs and dropping the two parameters it
// must not have.
//
// Why a redirect rather than simply rendering the consent page here. The original reason has
// expired and is worth recording, because it is the kind that looks live until someone checks it.
// The CSRF exemption the POST binding needs keys on the hint being PRESENT, since middleware cannot
// judge whether a hint is genuine. gorilla/csrf returned from its handler on that skip flag before
// saving its cookie and attaching its token, so a consent page rendered on such a request carried an
// empty token field while its own confirming POST was hintless, therefore not exempt, therefore
// refused: an End-User stranded on a page they could not submit while still signed in. There is no
// token now (#155). Protection is the origin check, a page served from here is a document at our own
// origin whichever binding produced it, and its confirming POST is same-origin either way, so the
// trap is gone.
//
// The redirect stays because it is the behaviour #109 landed and what the tests pin, and because it
// keeps an independent property: the End-User ends on a GET, so a reload or a back-navigation does
// not resubmit the failed POST. Do not read the exemption as the reason for it any more (#109, #155).
//
// id_token_hint is dropped, and not to prevent a loop: the follow-up is a GET, and the switch above
// sends a rejected hint on any method but POST to the consent page, so sending the hint back would
// terminate rather than return here. It is dropped because carrying it puts an ID token in the
// address bar of a top-level navigation, its history and its referrers, which is the exposure the
// POST binding exists to avoid, and because feeding input already judged unusable into the next
// request gives that request nothing it can act on anyway.
// client_id is dropped because the follow-up GET is then the hint-absent shape, where client_id is
// what authorizes a post-logout redirect: keeping it would hand the request the redirect authority a
// rejected hint is specifically denied. With no client_id nothing validates the target, so the
// End-User is signed out and lands on the signed-out page with the "we could not return you" note,
// which is the intended outcome for a hint that failed to validate (#109 decision 15).
func redirectToHintlessLogout(w http.ResponseWriter, r *http.Request, httpHelper HttpHelper) {
	query := url.Values{}
	if postLogoutRedirectURI := httpHelper.GetFromUrlQueryOrFormPost(r, "post_logout_redirect_uri"); len(postLogoutRedirectURI) > 0 {
		query.Set("post_logout_redirect_uri", postLogoutRedirectURI)
	}
	// Presence-aware, so a state supplied empty survives as "state=" and an absent one stays absent,
	// which is the contract the consent form's hidden field keeps too (#109 decision 16).
	if state, statePresent := httpHelper.LookupFromUrlQueryOrFormPost(r, "state"); statePresent {
		query.Set("state", state)
	}
	if uiLocales := httpHelper.GetFromUrlQueryOrFormPost(r, "ui_locales"); len(uiLocales) > 0 {
		query.Set("ui_locales", uiLocales)
	}

	location := logoutFormPath
	if encoded := query.Encode(); len(encoded) > 0 {
		location += "?" + encoded
	}

	// 303 rather than 302, because the browser must re-request by GET and that is what the status
	// means: RFC 7231 section 6.4.4, "the user agent ... performing a retrieval request on the
	// alternate URI ... using the GET method".
	http.Redirect(w, r, location, http.StatusSeeOther)
}

// deleteWholeUserSession ends the whole OP session named by the browser's cookie and returns the
// user it belonged to, or 0 when there was no such row.
//
// Whole-session, not per-client, because a request that named no client has nothing to scope a
// per-client teardown to. Deleting the row is what stops the session-bound refresh tokens
// immediately, since RequireValidSession resolves it; offline grants survive, which is OIDC Core
// section 11's reading and the one #129 adopted for the hinted path. The child rows in
// user_session_clients go with the parent on every engine, on the fk_user_sessions_clients cascade
// that TerminateUserSessionTx already relies on.
//
// A lookup or delete failure is returned so the caller can surface a 500; a row that is simply not
// there is not an error, it is nothing to tear down. Those two used to be one branch returning a
// variable that was sometimes nil to mean both (#109 item 4).
func deleteWholeUserSession(
	r *http.Request,
	sessionIdentifier string,
	database data.Database,
	auditLogger AuditLogger,
	authHelper AuthHelper,
) (int64, error) {
	userSession, err := database.GetUserSessionBySessionIdentifier(nil, sessionIdentifier)
	if err != nil {
		return 0, err
	}
	if userSession == nil {
		return 0, nil
	}

	if err := database.DeleteUserSession(nil, userSession.Id); err != nil {
		return 0, err
	}

	auditLogger.Log(constants.AuditDeletedUserSession, map[string]interface{}{
		"userSessionId": userSession.Id,
		"loggedInUser":  authHelper.GetLoggedInSubject(r),
	})

	return userSession.UserId, nil
}

// clientForPostLogoutRedirect resolves the client whose registered URIs may authorize a post-logout
// redirect for a request that carried no confirmable id_token_hint. Returns nil for a client_id that
// is absent, unknown or unreadable, and nil means no redirect.
//
// client_id is unauthenticated, so a caller can name any client. It is trusted for exactly one
// thing, deciding whether a supplied URI is registered to the client it names, which is
// self-limiting because the URI has to be in that client's set already. It is never allowed to
// scope a teardown: only an id_token_hint, whose aud is signed, does that.
//
// A database failure here returns nil rather than propagating, which is deliberate. This runs before
// the teardown, so turning it into a 500 would put the End-User back on a terminal page while still
// signed in, which is the defect #109 exists to remove. Losing a redirect is the safe direction; the
// reason is logged.
func clientForPostLogoutRedirect(clientId string, database data.Database) *models.Client {
	if len(clientId) == 0 {
		// RP-Initiated Logout 1.0 section 3: "if it is not supplied with post_logout_redirect_uri,
		// the OP MUST NOT perform post-logout redirection unless the OP has other means of
		// confirming the legitimacy of the post-logout redirection target". With neither a hint nor
		// a client_id there are no such means.
		slog.Warn("logout: post_logout_redirect_uri supplied with no id_token_hint and no client_id, not redirecting")
		return nil
	}

	client, err := database.GetClientByClientIdentifier(nil, clientId)
	if err != nil {
		slog.Error("logout: client lookup failed, not redirecting", "clientId", clientId, "err", err)
		return nil
	}
	if client == nil {
		slog.Warn("logout: client_id names no client, not redirecting", "clientId", clientId)
		return nil
	}

	return client
}

// postLogoutRedirectLocation returns the Location value for the post-logout redirect, or "" when the
// request has not earned one. A nil client always returns "", which is how a rejected id_token_hint
// is denied a redirect however valid the client_id beside it looks.
//
// The match is exact, as OpenID Connect RP-Initiated Logout 1.0 section 2 requires ("The OP also
// MUST NOT perform post-logout redirection if the post_logout_redirect_uri value supplied does not
// exactly match one of the previously registered post_logout_redirect_uris values") and as RFC 9700
// section 2.1 requires of redirect URIs generally.
//
// Goiabada has no separate post_logout_redirect_uris client metadata, so the set matched against is
// the client's OAuth redirect URIs. The spec permits that: the value "MUST have been previously
// registered with the OP, either using the post_logout_redirect_uris Registration parameter or via
// other mechanisms". Registering the two separately is tracked as its own change.
//
// A registered URI that is not an absolute URI earns no redirect either, which is the third way of
// returning "" and the only one where the request is otherwise in order. Matching the same rows as
// the authorization endpoint means inheriting the same defect: a row stored before those rules
// existed can be scheme-relative, or can carry a scheme with no authority, and this endpoint would
// then emit it verbatim as a Location the user agent resolves against a host nobody registered. The
// authorization endpoint's own gate does not cover this one, because the value never passes through
// it (#122).
func postLogoutRedirectLocation(
	r *http.Request,
	httpHelper HttpHelper,
	database data.Database,
	client *models.Client,
	postLogoutRedirectURI string,
) string {
	if client == nil {
		return ""
	}

	// Ahead of the load, so a value that can never be redirected to costs no query. The reason is
	// its own line rather than a reuse of the "is not registered" warning below: this URI may well
	// be registered, and telling an operator it is not would send them to fix the wrong thing. The
	// URI itself is not logged, for the reason decision 4 gives at the authorization endpoint: it is
	// unbounded caller-controlled input, and the client identifier is the bounded value that finds
	// the offending row (#122).
	if !urlutil.IsAbsoluteRedirectURI(postLogoutRedirectURI) {
		slog.Warn("logout: post_logout_redirect_uri is not an absolute URI, not redirecting",
			"clientIdentifier", client.ClientIdentifier)
		return ""
	}

	if err := database.ClientLoadRedirectURIs(nil, client); err != nil {
		slog.Error("logout: load redirect URIs failed, not redirecting",
			"clientIdentifier", client.ClientIdentifier, "err", err)
		return ""
	}

	registered := false
	for _, uri := range client.RedirectURIs {
		if uri.URI == postLogoutRedirectURI {
			registered = true
			break
		}
	}
	if !registered {
		slog.Warn("logout: post_logout_redirect_uri is not registered for this client, not redirecting",
			"clientIdentifier", client.ClientIdentifier)
		return ""
	}

	// Presence-aware, because "state=" and no state at all are different requests and the RP can
	// tell the difference in what comes back.
	state, statePresent := httpHelper.LookupFromUrlQueryOrFormPost(r, "state")
	location, err := buildPostLogoutRedirect(postLogoutRedirectURI, state, statePresent)
	if err != nil {
		slog.Error("logout: could not build the post-logout redirect, not redirecting",
			"clientIdentifier", client.ClientIdentifier, "err", err)
		return ""
	}

	return location
}

// finishLogout clears the OP session cookie and writes the terminal response.
//
// The cookie wipe is unconditional and covers the whole session even when the database teardown was
// scoped to one client. That asymmetry is deliberate and worth stating, because it looks like an
// oversight: the RP asked the OP to log the End-User out, and the cookie IS the OP session, so
// leaving the session identifier in it would keep the user signed in at the OP right after they
// asked to be signed out. The per-client database teardown stays per-client because #129 decided
// grants survive logout. The residue is that while other clients remain on the session, the row
// outlives the browser's ability to reach it until the idle reaper takes it; cutting those clients'
// tokens off properly needs client-scoped revocation, which is #135's job.
//
// redirectDeclined is passed through rather than derived from location being empty, so the signed-out
// page can tell "no target was asked for" from "a target was asked for and refused".
func finishLogout(
	w http.ResponseWriter,
	r *http.Request,
	httpHelper HttpHelper,
	httpSession sessions.Store,
	location string,
	targetSupplied bool,
) {
	sess, err := httpSession.Get(r, constants.AuthServerSessionName)
	if err != nil {
		httpHelper.InternalServerError(w, r, err)
		return
	}
	sess.Values = make(map[interface{}]interface{})
	if err := httpSession.Save(r, w, sess); err != nil {
		httpHelper.InternalServerError(w, r, err)
		return
	}

	if len(location) > 0 {
		http.Redirect(w, r, location, http.StatusFound)
		return
	}

	renderLoggedOut(w, r, httpHelper, targetSupplied)
}

// buildPostLogoutRedirect returns the Location value for a post-logout redirect: the
// registered URI with the RP's state written into its query, properly escaped. Building
// it by string concatenation instead is what let a state containing "+", "/", "=", "#"
// or "&" reach the RP altered or truncated, and let a registered URI that already
// carried a query gain a second "?" (#109).
//
// The construction itself is writeResponseParams, which every emitter in this package now
// shares. Its comment carries why the registered query is copied field by field rather
// than decoded and re-encoded. Keeping a second copy here is what produced #146: #109
// fixed this site and left the authorization emitters running the broken shape, so the
// defect outlived its own fix by one file.
//
// Two properties are this site's own, so changing either back is a behaviour change
// rather than a tidy-up:
//
//   - No TrimSpace. OpenID Connect RP-Initiated Logout 1.0 section 2 calls state an
//     "Opaque value used by the RP to maintain state between the logout request and the
//     callback", so the OP has no licence to alter it. Trimming would turn a
//     whitespace-only state into no state at all.
//   - statePresent, rather than a len(state) > 0 guard, is what keeps three cases
//     distinct: a state that was absent writes nothing, a state supplied empty comes back
//     as "state=", and a whitespace-only state survives byte-identical. That differs from
//     the authorization endpoint on purpose. RFC 6749 section 3.1 makes a valueless
//     parameter an omitted one there, while RP-Initiated Logout 1.0 carries no such rule
//     anywhere in the document, so the two endpoints answer "?state=" differently because
//     their two specifications do (#146).
//
// With statePresent false nothing is written, so a registered post-logout "?state=fixed"
// is kept rather than filtered: an empty params replaces no field. That is the behaviour
// this function had before it delegated, preserved deliberately.
func buildPostLogoutRedirect(registeredURI string, state string, statePresent bool) (string, error) {
	var params []responseParam
	if statePresent {
		params = []responseParam{{"state", state}}
	}

	location, err := writeResponseParams(registeredURI, params)
	if err != nil {
		return "", errors.Wrap(err, "unable to parse post-logout redirect URI")
	}

	return location, nil
}
