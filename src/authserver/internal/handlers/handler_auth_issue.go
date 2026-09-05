package handlers

import (
	"bytes"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/urlutil"
	"github.com/pkg/errors"
)

func HandleIssueGet(
	httpHelper HttpHelper,
	authHelper AuthHelper,
	templateFS fs.FS,
	codeIssuer CodeIssuer,
	tokenIssuer TokenIssuer,
	database data.Database,
	auditLogger AuditLogger,
	userSessionManager UserSessionManager,
	permissionChecker PermissionChecker,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authContext, err := authHelper.GetAuthContext(r)
		if err != nil {
			if errDetail, ok := err.(*customerrors.ErrorDetail); ok && errDetail.IsError(customerrors.ErrNoAuthContext) {
				var profileUrl = GetProfileURL()
				slog.Warn(fmt.Sprintf("auth context is missing, redirecting to %v", profileUrl))
				http.Redirect(w, r, profileUrl, http.StatusFound)
			} else {
				httpHelper.InternalServerError(w, r, err)
			}
			return
		}

		requiredState := oauth.AuthStateReadyToIssueCode
		if authContext.AuthState != requiredState {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("authContext.AuthState is not "+requiredState)))
			return
		}

		// The redirect URI this ceremony would be answered at has to STILL be registered on the
		// client, and this is where that is asked. It was matched once, at /auth/authorize, and
		// the consent screen has no bound on how long it holds a ceremony still, so an operator
		// who deleted a callback while it sat there has an expectation this check is what meets
		// (#241).
		//
		// The position is load-bearing rather than tidy. EVERY refusal below this line answers
		// the client by redirect: the id_token_hint mismatch and the prompt=none arm of the
		// binding check both call redirToClientWithError, and so does the empty-scope refusal.
		// Delivering any of them to a callback the operator has just pulled navigates a browser
		// to that host on a request this server refused, which is the RFC 9700 section 4.11.2
		// harm the check exists to prevent. Placed first, this handler has one property worth
		// stating: nothing in it can send a browser to an unregistered callback.
		//
		// The client loaded here is passed down to handleImplicitFlow, which used to load it
		// again.
		issuingClient, err := database.GetClientByClientIdentifier(nil, authContext.ClientId)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		// Loopback port flexibility is the caller's gate to compute, per urlutil's package
		// contract (#41), and this is validator.ValidateClientAndRedirectURI's own test applied
		// to the stored response type. Read off the token sequence rather than off
		// ParseResponseType's booleans for the reason stated there: the parser ignores
		// unrecognised values and collapses duplicates, so "code code" and "code foo" are true
		// for HasCode && !HasToken && !HasIdToken and must not buy an arbitrary loopback port.
		responseTypes := strings.Fields(authContext.ResponseType)
		allowLoopbackPortFlexibility := len(responseTypes) == 1 && responseTypes[0] == "code"

		registered := []string{}
		if issuingClient != nil {
			err = database.ClientLoadRedirectURIs(nil, issuingClient)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			for _, redirectURI := range issuingClient.RedirectURIs {
				registered = append(registered, redirectURI.URI)
			}
		}

		// A nil client REFUSES rather than answering 500. A client deleted while its ceremony
		// waited on the consent screen has no registrations at all, so the question this gate
		// asks has been answered rather than errored, and renderRedirectBlocked already
		// documents a nil client as the case it renders without a name.
		if !urlutil.RedirectURIIsRegistered(registered, authContext.RedirectURI, allowLoopbackPortFlexibility) {
			// The client identifier is a bounded stored value and is safe to log; the URI is
			// not logged, matching the authorization endpoint's refusal, since the operator
			// reads the offending value off the client's page.
			slog.Warn("the redirect URI this ceremony would be answered at is no longer registered on the client, so nothing is issued and nothing is emitted",
				"clientIdentifier", authContext.ClientId)

			auditLogger.Log(constants.AuditIssuanceRefusedRedirectURI, map[string]interface{}{
				"userId":   authContext.UserId,
				"clientId": authContext.ClientId,
			})

			// The clear goes FIRST, the order every refusal in this handler uses: ClearAuthContext
			// persists the deletion through a Set-Cookie on w, and the render below commits the
			// response, so clearing afterwards leaves the header on a response already written
			// (#141).
			err = authHelper.ClearAuthContext(w, r)
			if err != nil {
				// This is the ONE refusal in the file whose fallback is not "answer the client
				// with server_error". Answering this client is precisely what the gate exists to
				// prevent, and an error redirect is a response to the deregistered URI just as a
				// code would be. So the page is rendered regardless and the browser keeps a
				// replayable auth context, which is the lesser of the two: a replay arrives back
				// at this same gate and is refused again for as long as the registration is gone.
				slog.Error("failed to clear the auth context while withholding a redirect to a deregistered URI, rendering the refusal anyway",
					"error", err)
			}

			// Rendered locally, never redirected: this URI must receive nothing, an error
			// response included. auth_redirect_blocked.html is the page redirToClientWithError
			// already withholds a redirect through, so one condition keeps one page wherever it
			// fires (#241 decision 4, as amended by decision 11).
			//
			// Built directly rather than through redirectErrorFromAuthContext, which fills in an
			// error code, a description, a state and a response mode: this page carries none of
			// them, and naming the two fields it does read says so.
			err = renderRedirectBlocked(httpHelper, w, r, redirectErrorInput{
				client:      issuingClient,
				redirectURI: authContext.RedirectURI,
			})
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
			return
		}

		// id_token_hint sub enforcement (OIDC Core 3.1.2.2, Authentication Request Validation):
		// "The Authorization Server MUST NOT reply with an ID Token or Access Token for a
		// different user, even if they have an active session with the Authorization Server."
		// This is the critical safety net that catches mismatched users even after successful authentication.
		// Hoisted, because the scope re-filter below needs the same user and the hint check may
		// already have loaded it. Nil here means "not loaded yet", never "no such user": the
		// branch below refuses on a nil.
		var user *models.User

		if authContext.IdTokenHintSub != "" {
			user, err = database.GetUserById(nil, authContext.UserId)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			if user == nil || user.Subject.String() != authContext.IdTokenHintSub {
				// Cannot issue tokens for a different user than the hint identifies.
				//
				// An error redirect carries the client it is answering, so its provenance has to
				// be resolved ahead of the dispatch (#108). The registration gate above already
				// loaded it and refused a nil, so issuingClient is that client rather than a
				// clientProvenance call of its own; before #241 this handler loaded no client at
				// all above handleImplicitFlow and had to.
				//
				// The clear goes FIRST, the order the prompt=none refusal below and the success
				// path both use. ClearAuthContext persists the deletion through a Set-Cookie on
				// w, and redirToClientWithError commits the response in every response mode, so
				// clearing afterwards leaves the header on a response already written. This is
				// the one refusal that leaves the context in ready_to_issue_code, the state that
				// mints codes, so a browser keeping it can replay this endpoint with only the
				// comparison above standing between the replay and a code (#141).
				err := authHelper.ClearAuthContext(w, r)
				if err != nil {
					// The clear failed, so Save wrote no cookie and the browser still holds the
					// auth context. The client is owed an error response regardless: its redirect
					// URI was validated upstream, so OIDC Core 1.0 3.1.2.2 with 3.1.2.6 applies,
					// and RFC 6749 4.1.2.1 mints server_error for exactly this condition (#141).
					slog.Error("failed to clear the auth context, answering the client with server_error",
						"error", err)
					err = redirToClientWithError(w, r, database, httpHelper, templateFS,
						redirectErrorFromAuthContext(authContext, issuingClient, "server_error", "Internal server error"))
					if err != nil {
						// Nowhere left to send the client, so the 500 is the last resort here.
						httpHelper.InternalServerError(w, r, err)
					}
					return
				}

				err = redirToClientWithError(w, r, database, httpHelper, templateFS,
					redirectErrorFromAuthContext(authContext, issuingClient, constants.ErrorLoginRequired,
						"The authenticated user does not match the id_token_hint"))
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}
				return
			}
		}

		sessionIdentifier := ""
		if r.Context().Value(constants.ContextKeySessionIdentifier) != nil {
			sessionIdentifier = r.Context().Value(constants.ContextKeySessionIdentifier).(string)
		}

		// A ceremony must not bind a grant to a session that no longer exists (#129
		// decision 6, second half). The session was alive at /auth/completed, which bumped
		// or created it, and the user may then have spent minutes on the consent screen;
		// if it was ended in between, the grant minted below is brand new and no marker
		// written by the termination can reach it, because the row did not exist yet.
		//
		// An EMPTY identifier is the shape that case actually arrives in, not a stale one.
		// MiddlewareSessionIdentifier looks the session up on every request and puts the
		// identifier in the request context ONLY when the row exists, so the read above
		// yields "" for a ceremony whose session was ended. The non-empty branch below
		// covers the narrower race where the middleware saw the session alive on this very
		// request and the termination committed afterwards.
		//
		// Neither case is inert. grantIsOffline treats an empty session identifier as an
		// offline grant on its own, so a code issued here would yield an Offline refresh
		// token: it stores a max lifetime instead of a session identifier and the validator
		// never consults a session, which means it outlives the terminated session by up to
		// RefreshTokenOfflineMaxLifetimeInSeconds whether or not offline_access was asked
		// for.
		//
		// Liveness is not enough, though, which is what #133 adds: the row can resolve and
		// still belong to somebody else. User A is signed in, the browser holds A's session
		// cookie, and prompt=login or an id_token_hint sends user B through a fresh
		// authentication without the cookie ever being cleared. Binding B's grant to A's
		// session hands B a code or a token stamped with A's session identifier, which then
		// governs B's access by A's lifetimes and dies when A's session does. So the
		// question here is ownership, and liveness is the half of it that a missing row
		// already answers.
		//
		// Since #241 the third question is validity, which the two above deliberately left to
		// /auth/completed. That gate applies the idle timeout and the maximum lifetime once and
		// the consent screen then holds the ceremony for however long a person takes, so a
		// session that timed out on that screen still resolves and is still owned. Redemption
		// does not catch it either: the authorization_code arm checks ownership and not
		// validity, so the access token works and only the FIRST refresh answers invalid_grant,
		// which is a confusing failure to debug from the relying party's side. All three
		// questions take the same two answers below, so widening the predicate reuses them
		// whole.
		var ambientSession *models.UserSession
		if sessionIdentifier != "" {
			ambientSession, err = database.GetUserSessionBySessionIdentifier(nil, sessionIdentifier)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		// The gate sits ABOVE the response-type dispatch on purpose. handleImplicitFlow
		// copies sessionIdentifier straight into ImplicitGrantInput.SessionIdentifier and
		// never loads the session, so a response_type of token, id_token or id_token token
		// would otherwise mint a signed token for B carrying A's sid with every check in
		// this handler above it. The later backstops cannot cover that: a third-party
		// resource server validating an already-signed token has no way to compare the
		// session's owner against the token's subject (#133).
		isImplicitFlow := oauth.ParseResponseType(authContext.ResponseType).IsImplicitFlow()

		// nil for the requested max age, and that is decision 1 rather than an omission. max_age
		// bounds the age of the AUTHENTICATION, which this ceremony already satisfied at
		// /auth/completed; re-applying it here would turn it into a deadline for reading the
		// consent screen. UserSession.IsValid measures it from Started, so max_age=0 is violated
		// a microsecond later and every such ceremony would restart at level 1, mint a fresh
		// session and fail again (#241).
		sessionIsValid := userSessionManager.HasValidUserSession(r.Context(), ambientSession, nil)

		// The conjunction goes ABOVE the implicit exemption, not below it.
		// HasValidUserSession answers false for a nil session, so folding it in afterwards would
		// undo the exemption and refuse every implicit ceremony that arrives without a session.
		mayBind := authContext.OwnsSession(ambientSession) && sessionIsValid
		if isImplicitFlow && sessionIdentifier == "" {
			// No ambient session at all, so there is nothing to cross-bind to. The code flow
			// still refuses here, because #129 showed an empty identifier there produces an
			// Offline refresh token that outlives the session it came from. The implicit
			// flow issues no refresh token and its access token carries the identifier only
			// as a claim, so refusing would change behaviour in a case where no session is
			// being taken over. Whether implicit should require a session at all is a
			// separate question from this one (#133).
			mayBind = true
		}

		if !mayBind {
			// Three shapes, and each gets its own sentence rather than one covering all three.
			// "The session backing this ceremony is gone" would be the wrong sentence for a session
			// that resolves but belongs to another user, and an operator reading that one needs to
			// see the two user ids that failed to match (#133 decision 7); it is equally wrong for a
			// session that is present, owned and merely out of time, which is what an operator's idle
			// timeout doing its job looks like.
			//
			// The answer itself lives in refuseIssuanceUnusableSession because this handler asks the
			// same question twice: here, from the liveness read, and again below the dispatch, where
			// the acquisition that orders the code insert against a session termination can find the
			// row gone in the few statements between the two. One condition gets one answer wherever
			// it is learned, and a single implementation is what makes that true rather than claimed
			// (#139 decision 3).
			shape := sessionGone
			switch {
			case ambientSession != nil && !authContext.OwnsSession(ambientSession):
				shape = sessionForeign
			case ambientSession != nil && !sessionIsValid:
				shape = sessionExpired
			}

			refuseIssuanceUnusableSession(w, r, shape, authContext, issuingClient, ambientSession,
				sessionIdentifier, httpHelper, authHelper, templateFS, database, auditLogger)
			return
		}

		// The scope is re-filtered against the user's LIVE permissions, immediately before
		// anything is minted. /auth/completed filtered it once and that is the only live
		// permission check the ceremony performs today: everything after it reads the stored
		// value, the consent screen builds its checkboxes from it, the code issuer writes it
		// onto the code and the implicit branch signs it. Nothing downstream catches a removal
		// either, because the authorization_code arm of the token endpoint never consults the
		// permission checker, while a REFRESH of an older grant does, so without this a
		// brand-new grant is the one thing minted without a live check (#241).
		//
		// Placed below the binding check so a ceremony about to be restarted at level 1 pays
		// none of it, and below the registration gate so the refusal here is safe to deliver by
		// redirect.
		if user == nil {
			user, err = database.GetUserById(nil, authContext.UserId)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}
		if user == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New(fmt.Sprintf("user %v not found", authContext.UserId))))
			return
		}

		// Whichever field the issuer will READ, and never the other one. CreateAuthCode and
		// handleImplicitFlow both prefer ConsentedScope and fall back to Scope when it is empty,
		// so writing an emptied ConsentedScope back would fall through to the full unfiltered
		// request, which is why the empty result refuses instead of writing anything at all
		// (#241 decision 2).
		scopeField := &authContext.Scope
		if authContext.ConsentedScope != "" {
			scopeField = &authContext.ConsentedScope
		}
		effectiveScope, err := permissionChecker.FilterOutScopesWhereUserIsNotAuthorized(*scopeField, user)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		if effectiveScope == "" {
			slog.Warn("the user holds none of the permissions behind the scopes this ceremony would grant, so nothing is issued",
				"userId", authContext.UserId,
				"clientIdentifier", authContext.ClientId)

			auditLogger.Log(constants.AuditIssuanceRefusedScopeDenied, map[string]interface{}{
				"userId":   authContext.UserId,
				"clientId": authContext.ClientId,
			})

			// The wording and the error code are /auth/completed's for the same condition,
			// arriving later: the same removal gets one answer wherever it lands.
			//
			// The clear goes FIRST, for the reason every refusal in this handler states: a
			// Set-Cookie written after redirToClientWithError has committed never reaches the
			// wire, so the browser would keep a replayable auth context (#141).
			err = authHelper.ClearAuthContext(w, r)
			if err != nil {
				// The clear failed, so Save wrote no cookie and the browser still holds the
				// auth context. The client is owed an error response regardless: its redirect
				// URI was validated upstream and re-checked above, so OIDC Core 1.0 3.1.2.2
				// with 3.1.2.6 applies, and RFC 6749 4.1.2.1 mints server_error for exactly
				// this condition (#141).
				slog.Error("failed to clear the auth context, answering the client with server_error",
					"error", err)
				err = redirToClientWithError(w, r, database, httpHelper, templateFS,
					redirectErrorFromAuthContext(authContext, issuingClient, "server_error", "Internal server error"))
				if err != nil {
					// Nowhere left to send the client, so the 500 is the last resort here.
					httpHelper.InternalServerError(w, r, err)
				}
				return
			}

			err = redirToClientWithError(w, r, database, httpHelper, templateFS,
				redirectErrorFromAuthContext(authContext, issuingClient, "access_denied",
					"The user is not authorized to access any of the requested scopes"))
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
			return
		}

		// A narrowed set is issued rather than refused, which is RFC 6749 section 3.3's "The
		// authorization server MAY fully or partially ignore the scope requested by the client"
		// and what /auth/completed's own filter did with the same removal seconds earlier. The
		// client is told what it actually got: TokenResponse.Scope carries the granted set on
		// the code arm, and issueImplicitTokens appends a scope parameter on the implicit arm
		// (decision 2).
		*scopeField = effectiveScope

		if isImplicitFlow {
			err = handleImplicitFlow(w, r, authContext, sessionIdentifier, issuingClient, user, authHelper, tokenIssuer, auditLogger)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
			return
		}

		// Authorization Code Flow

		createCodeInput := &oauth.CreateCodeInput{
			AuthContext:       *authContext,
			SessionIdentifier: sessionIdentifier,
		}

		// The observation that the session is still there and the insert that binds a grant to it
		// go in ONE transaction, and the acquisition is what orders this ceremony against a
		// termination of that session (#139).
		//
		// The liveness read above cannot do this on its own, however recently it ran: it is a
		// read on one connection followed by an insert on another, so a termination can commit in
		// between, and worse, a code inserted after that termination's sweep and before its
		// COMMIT is invisible to the sweep and the termination is invisible to any compensating
		// read, which still sees the uncommitted-deleted session row. The termination now deletes
		// the session row as its first statement, so both sides write the same row before
		// touching anything else and one of them waits. Either this transaction waits and the
		// acquisition then matches no rows, so nothing is issued, or the termination waits and
		// its code sweep runs after this insert committed, so the code it hands the client is
		// marked revoked and redemption answers invalid_grant. There is no third case: that row
		// is the only object both sides touch and neither takes any other lock before it.
		//
		// Opened HERE rather than higher up so the row is held across as few statements as
		// possible, and on the authorization code branch only: the implicit flow mints no code
		// and no refresh token, so it has no durable grant for this to protect (#139 decision 6).
		tx, err := database.BeginTransaction()
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		defer database.RollbackTransaction(tx) //nolint:errcheck

		// THE USER'S ROW FIRST, above the session row this ceremony is about to take (#139).
		//
		// codes.user_id is a foreign key, so the insert below takes a lock on the parent users row
		// without naming it, and it does so while this transaction is already holding the session
		// row. Every credential operation goes the other way: a password change, a reset, an
		// administrator setting a password and disabling or deleting an account all write the
		// users row and only then reach the sessions and the grants hanging off them. Those two
		// orders are a cycle. Measured on MySQL and SQL Server it deadlocks with the CREDENTIAL
		// OPERATION as the victim, which is the worse one to lose: the account owner changing a
		// password because a session was stolen gets a 500, the session survives, and the racing
		// ceremony gets its code. Taking the row here puts this ceremony on the same order
		// everything else already uses, so one of the two simply waits.
		//
		// It costs one small UPDATE per authorization code issued, which is the price of the
		// ordering rather than an incidental write: nothing reads the updated_at it moves.
		if err := database.AcquireUserRow(tx, user.Id); err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		// Existence only, deliberately. Ownership and the two timeouts were asked a few statements
		// ago and are not re-asked here: the only thing this narrower question misses is an idle
		// timeout elapsing in the microseconds between the two, and buying that would cost a
		// SELECT on every authorization code issued (#139 decision 7).
		live, err := database.AcquireUserSessionRow(tx, sessionIdentifier)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		if !live {
			// Rolled back HERE, explicitly, before the refusal reaches anything. Every path out of
			// refuseIssuanceUnusableSession touches the database on a nil transaction through the
			// server-side session store: SaveAuthContext and ClearAuthContext write it and
			// redirToClientWithError reads the client. On SQLite the whole process shares one
			// connection, the one this transaction is holding, so leaving the rollback to the
			// deferred call above would have the refusal wait on itself. The deferred call still
			// runs and is a no-op against a finished transaction.
			//
			// A rollback that FAILS is a 500 rather than a refusal, because the connection is then
			// still held and the refusal would be the statement that discovers it.
			if err := database.RollbackTransaction(tx); err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			// The gone shape, and it is answered exactly as the liveness read above answers it:
			// the browser restarts at level 1 and a prompt=none ceremony is told login_required.
			// The acquisition cannot tell WHY the row is gone, which is #129's own finding, so an
			// explicit termination, a logout in another tab and either background reaper all get
			// this one answer (#139 decisions 3 and 9). No code row is written at all, so nothing
			// is left behind to reap.
			refuseIssuanceUnusableSession(w, r, sessionGone, authContext, issuingClient, ambientSession,
				sessionIdentifier, httpHelper, authHelper, templateFS, database, auditLogger)
			return
		}

		code, err := codeIssuer.CreateAuthCode(tx, createCodeInput)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		// Everything below this line attests to a write, so it waits for the commit, which is the
		// rule TerminateUserSessionTx documents: never attest to a write that could still roll
		// back. A commit that returns an error leaves the code row's fate indeterminate, which is
		// the same contract that helper already carries, and the client is answered with a 500
		// rather than a code.
		if err := database.CommitTransaction(tx); err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		auditLogger.Log(constants.AuditCreatedAuthCode, map[string]interface{}{
			"userId":   createCodeInput.UserId,
			"clientId": code.ClientId,
			"codeId":   code.Id,
		})

		err = authHelper.ClearAuthContext(w, r)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		err = issueAuthCode(w, r, templateFS, code, authContext.ResponseMode)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
		}
	}
}

// sessionRefusalShape names which of the three conditions on the session backing a ceremony
// refuseIssuanceUnusableSession is answering. They are mutually exclusive by construction: a row
// that is absent cannot be foreign, and a foreign one is refused on ownership before its clock is
// read.
type sessionRefusalShape int

const (
	// sessionGone is a session identifier with no row behind it. What removed the row is not
	// asked and cannot be told from here, which is #129's own finding: an explicit termination, a
	// logout in another tab, the idle reaper and the max-lifetime reaper all look identical to
	// the reader (#139 decision 9).
	sessionGone sessionRefusalShape = iota
	// sessionForeign is a row that resolves and belongs to a different user than the ceremony's
	// (#133).
	sessionForeign
	// sessionExpired is a row that resolves, is owned, and is outside its idle timeout or its
	// maximum lifetime (#241).
	sessionExpired
)

// refuseIssuanceUnusableSession is /auth/issue's one answer to "this ceremony cannot bind a grant
// to this session", and it exists as a function because the handler reaches that conclusion at two
// different points: the liveness read above the response-type dispatch, and the acquisition that
// orders the code insert against a session termination below it. Decision 3 of #139 is that one
// condition gets one answer wherever it is learned, and a shared implementation is what makes that
// checkable rather than a claim about two blocks that currently agree.
//
// Two outcomes, one predicate. An interactive ceremony is restarted at level 1, and a prompt=none
// ceremony is answered login_required, because a request that forbids UI cannot be sent to a
// password form. No code is minted on either branch.
//
// ambientSession is read only for the two shapes that have a row: the log lines for a foreign or
// an expired session name the user the row belongs to, and the gone shape has nothing to name.
func refuseIssuanceUnusableSession(
	w http.ResponseWriter,
	r *http.Request,
	shape sessionRefusalShape,
	authContext *oauth.AuthContext,
	issuingClient *models.Client,
	ambientSession *models.UserSession,
	sessionIdentifier string,
	httpHelper HttpHelper,
	authHelper AuthHelper,
	templateFS fs.FS,
	database data.Database,
	auditLogger AuditLogger,
) {
	// Only the expired shape audits. The foreign and gone shapes are #133's and #129's refusals,
	// writing no audit row today; this event attests the check #241 added, which is the one an
	// administrator can cause by configuring a timeout, and stretching it over two older
	// conditions would make it useless for answering the question it exists for.
	if shape == sessionExpired {
		auditLogger.Log(constants.AuditIssuanceRefusedSessionInvalid, map[string]interface{}{
			"userId":            authContext.UserId,
			"clientId":          authContext.ClientId,
			"sessionIdentifier": sessionIdentifier,
		})
	}

	// prompt=none is the one ceremony that cannot be restarted: /auth/level1 sends the browser to
	// /auth/pwd, which renders a form, and this request forbids any UI at all (OIDC Core 3.1.2.1,
	// and concepts/prompt-parameter.mdx says the same). Nothing between here and the form reads
	// the prompt, so the client would be handed a login page and no error, and a silent-renewal
	// iframe would wait for its own timeout instead. It gets login_required instead (#129 decision
	// 16), which is what handlePromptNone itself returns when its session lookup finds no row: the
	// condition really is the same one, arriving one redirect hop later, so the client cannot tell
	// the two apart and does not need to. No code is minted on either branch, so the fail-open
	// decision 6 closes stays closed.
	if authContext.HasPromptValue("none") {
		switch shape {
		case sessionForeign:
			slog.Warn("the session in this browser belongs to a different user, returning login_required instead of binding this silent ceremony to it",
				"sessionIdentifier", sessionIdentifier,
				"sessionUserId", ambientSession.UserId,
				"ceremonyUserId", authContext.UserId)
		case sessionExpired:
			slog.Warn("the session backing this silent ceremony is no longer within its idle timeout or maximum lifetime, returning login_required instead of issuing a code",
				"sessionIdentifier", sessionIdentifier,
				"sessionUserId", ambientSession.UserId)
		default:
			slog.Warn("the session backing this silent ceremony is gone, returning login_required instead of issuing a code",
				"sessionIdentifier", sessionIdentifier)
		}
		// The clear goes FIRST, which is the order the restart below uses too. ClearAuthContext
		// persists the deletion through a Set-Cookie on w, and redirToClientWithError commits the
		// response in every response mode, so clearing afterwards leaves the header on a response
		// already written and the browser keeps a ready_to_issue_code context it can replay.
		//
		// Provenance is resolved before the dispatch, for the same reason as at the id_token_hint
		// refusal (#108). The registration gate at the top of the handler loaded the client and
		// refused a nil, so issuingClient is it.
		err := authHelper.ClearAuthContext(w, r)
		if err != nil {
			// A failed clear leaves the auth context either wholly there or wholly gone, never
			// half, so withholding the client's response buys nothing whichever way it failed.
			// That was inherited from ChunkedCookieStore, whose every error return sat above its
			// first http.SetCookie; against a server-side store it is re-derived rather than
			// assumed, because the save now writes in two places. The row is written before the
			// cookie, so a failure before the row leaves the context intact, exactly as before,
			// and a failure after it leaves the context already gone server-side while the
			// browser's identifier still names the same cleared row. Neither outcome lets the
			// browser replay a ready_to_issue_code context (#266).
			//
			// The client is owed a response either way: its redirect URI was validated upstream,
			// so OIDC Core 1.0 3.1.2.2 with 3.1.2.6 applies, and RFC 6749 4.1.2.1 mints
			// server_error for exactly this condition (#141).
			slog.Error("failed to clear the auth context, answering the client with server_error",
				"error", err)
			err = redirToClientWithError(w, r, database, httpHelper, templateFS,
				redirectErrorFromAuthContext(authContext, issuingClient, "server_error", "Internal server error"))
			if err != nil {
				// Nowhere left to send the client, so the 500 is the last resort here.
				httpHelper.InternalServerError(w, r, err)
			}
			return
		}
		err = redirToClientWithError(w, r, database, httpHelper, templateFS,
			redirectErrorFromAuthContext(authContext, issuingClient, constants.ErrorLoginRequired,
				"User authentication is required"))
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		return
	}

	switch shape {
	case sessionForeign:
		slog.Warn("the session in this browser belongs to a different user, restarting level 1 instead of binding this ceremony to it",
			"sessionIdentifier", sessionIdentifier,
			"sessionUserId", ambientSession.UserId,
			"ceremonyUserId", authContext.UserId)
	case sessionExpired:
		slog.Warn("the session backing this ceremony is no longer within its idle timeout or maximum lifetime, restarting level 1 instead of issuing a code",
			"sessionIdentifier", sessionIdentifier,
			"sessionUserId", ambientSession.UserId)
	default:
		slog.Warn("the session backing this ceremony is gone, restarting level 1 instead of issuing a code",
			"sessionIdentifier", sessionIdentifier)
	}
	authContext.AuthState = oauth.AuthStateRequiresLevel1
	err := authHelper.SaveAuthContext(w, r, authContext)
	if err != nil {
		httpHelper.InternalServerError(w, r, err)
		return
	}
	http.Redirect(w, r, config.GetAuthServer().BaseURL+"/auth/level1", http.StatusFound)
}

// handleImplicitFlow handles the implicit grant flow token issuance.
// Per RFC 6749 4.2.2 and OIDC Core 3.2.2.5, tokens are returned in fragment.
// handleImplicitFlow takes the client and the user rather than loading them. HandleIssueGet
// resolves both above the dispatch now, the client for the registration gate and the user for the
// scope re-filter, and both gates refuse a nil, so re-reading them here would be two queries for
// values already in hand (#241).
func handleImplicitFlow(
	w http.ResponseWriter,
	r *http.Request,
	authContext *oauth.AuthContext,
	sessionIdentifier string,
	client *models.Client,
	user *models.User,
	authHelper AuthHelper,
	tokenIssuer TokenIssuer,
	auditLogger AuditLogger,
) error {
	// Determine what tokens to issue based on response_type
	rtInfo := oauth.ParseResponseType(authContext.ResponseType)
	issueAccessToken := rtInfo.HasToken
	issueIdToken := rtInfo.HasIdToken

	// Use provided AuthenticatedAt if set (for prompt=none, preserves session's auth_time),
	// otherwise use current time (normal flow, prompt=login).
	authenticatedAt := time.Now().UTC()
	if authContext.AuthenticatedAt != nil && !authContext.AuthenticatedAt.IsZero() {
		authenticatedAt = *authContext.AuthenticatedAt
	}

	// Determine the scope to use (consented scope if available, otherwise requested scope)
	scope := authContext.Scope
	if authContext.ConsentedScope != "" {
		scope = authContext.ConsentedScope
	}

	// Generate tokens
	implicitInput := &oauth.ImplicitGrantInput{
		Client:            client,
		User:              user,
		Scope:             scope,
		AcrLevel:          authContext.AcrLevel,
		AuthMethods:       authContext.AuthMethods,
		SessionIdentifier: sessionIdentifier,
		Nonce:             authContext.Nonce,
		AuthenticatedAt:   authenticatedAt,

		AuthStateGeneration: authContext.AuthStateGeneration,
	}

	tokenResponse, err := tokenIssuer.GenerateTokenResponseForImplicit(r.Context(), implicitInput, issueAccessToken, issueIdToken)
	if err != nil {
		return err
	}

	// Audit log
	auditLogger.Log(constants.AuditTokenIssuedImplicitResponse, map[string]interface{}{
		"userId":           user.Id,
		"clientId":         client.Id,
		"scope":            scope,
		"responseType":     authContext.ResponseType,
		"issueAccessToken": issueAccessToken,
		"issueIdToken":     issueIdToken,
	})

	// Clear auth context
	err = authHelper.ClearAuthContext(w, r)
	if err != nil {
		return err
	}

	// Issue tokens via fragment (implicit flow always uses fragment response mode)
	return issueImplicitTokens(w, r, authContext.RedirectURI, authContext.State, tokenResponse)
}

// issueImplicitTokens redirects to the client with tokens in the fragment.
// Per RFC 6749 4.2.2, implicit grant tokens MUST be delivered via fragment.
func issueImplicitTokens(
	w http.ResponseWriter,
	r *http.Request,
	redirectURI string,
	state string,
	tokenResponse *oauth.ImplicitGrantResponse,
) error {
	// Gate 4, the last resort. This flow hands over access and ID tokens rather than a code, so a
	// redirect URI that resolves to a host the operator never registered exfiltrates credentials
	// directly rather than something still to be exchanged. Nothing can reach here with such a value
	// once the authorization endpoint has refused it, and the check stays so that the property is
	// enforced by a test rather than claimed by a comment (#122).
	if err := checkRedirectURIEmittable("issueImplicitTokens", redirectURI); err != nil {
		return err
	}

	// The response's parameters, in the order they reach the client. Each carries the condition it
	// already had; what changed is the construction underneath and the rule for state.
	//
	// state is appended on its value being non-empty and nothing else. There is no TrimSpace: RFC
	// 6749 section 3.1 says "Parameters sent without a value MUST be treated as if they were
	// omitted from the request", so "?state=" and "?state" are requests that carried no state, and
	// Appendix A.5's "state = 1*VSCHAR" admits no empty value in the response either. Space is
	// %x20 and so is VSCHAR, so a whitespace-only state is a value the client chose and section
	// 4.2.2 requires "the exact value received from the client": trimming it away substituted this
	// server's judgement for the client's (#146).
	params := make([]responseParam, 0, 6)

	if tokenResponse.AccessToken != "" {
		params = append(params,
			responseParam{"access_token", tokenResponse.AccessToken},
			responseParam{"token_type", tokenResponse.TokenType},
			responseParam{"expires_in", fmt.Sprintf("%d", tokenResponse.ExpiresIn)},
		)
	}

	if tokenResponse.IdToken != "" {
		params = append(params, responseParam{"id_token", tokenResponse.IdToken})
	}

	if tokenResponse.Scope != "" {
		params = append(params, responseParam{"scope", tokenResponse.Scope})
	}

	if state != "" {
		params = append(params, responseParam{"state", state})
	}

	// Appended rather than written through writeResponseParams, for the same reason the error
	// emitter's fragment branch appends: the redirect URI cannot carry a fragment of its own for
	// these fields to collide with, since RFC 6749 3.1.2 forbids one and checkRedirectURIEmittable
	// refuses one just above. Its query, if it registered one, is left exactly as it stands.
	//
	// Field order is now declaration order rather than Encode's alphabetical sort. Nothing depends
	// on it: RFC 6749 4.2.2 defines a set of parameters and not a sequence.
	http.Redirect(w, r, redirectURI+"#"+encodeResponseParams(params), http.StatusFound)
	return nil
}

func issueAuthCode(w http.ResponseWriter, r *http.Request, templateFS fs.FS, code *models.Code, responseMode string) error {

	// Gate 4, the last resort, ABOVE the response-mode dispatch so that it covers query, fragment
	// and form_post alike. All three emit the stored value: the first two into a Location header,
	// the third into the action of an auto-submitting form, which html/template's URL filter passes
	// through untouched for a scheme-relative value. Unreachable once the authorization endpoint has
	// refused the URI, and kept so that a test enforces it (#122).
	//
	// The caller answers a non-nil error with a 500, which leaves the code unredeemed rather than
	// delivered to the wrong host; it expires in 60 seconds.
	if err := checkRedirectURIEmittable("issueAuthCode", code.RedirectURI); err != nil {
		return err
	}

	if responseMode == "" {
		responseMode = "query"
	}

	// The response's parameters, in the order they reach the client, built once for all three
	// response modes because all three answer with the same two fields.
	//
	// state is appended on its value being non-empty and nothing else, the same rule the error
	// emitter states at length: RFC 6749 section 3.1 makes a parameter sent without a value an
	// omitted one, and Appendix A.5's "state = 1*VSCHAR" admits no empty value in the response. A
	// whitespace-only state is a real value, because space is %x20 and so is VSCHAR, and section
	// 4.1.2 requires "the exact value received from the client", so the TrimSpace that used to drop
	// it is gone (#146).
	params := []responseParam{{"code", code.Code}}
	if code.State != "" {
		params = append(params, responseParam{"state", code.State})
	}

	if responseMode == "fragment" {
		// Appended rather than written through writeResponseParams: a redirect URI cannot carry a
		// fragment of its own for these fields to collide with, so there is no registered field
		// list here to preserve or replace, and its query is left exactly as registered.
		http.Redirect(w, r, code.RedirectURI+"#"+encodeResponseParams(params), http.StatusFound)
		return nil
	}
	if responseMode == "form_post" {
		m := make(map[string]interface{})
		m["redirectURI"] = code.RedirectURI
		m["code"] = code.Code
		// The same rule as the params slice above, restated because this branch answers through a
		// bind map rather than a field list. What the client actually receives is then decided by
		// form_post.html, whose {{if .state}} omits the input entirely.
		//
		// {{.state}} and {{if .state}} cannot tell an absent key from a key holding "", but a
		// template that enumerates the map can: range yields the key only when it is present, and
		// len counts it. form_post.html is operator supplied whenever GOIABADA_AUTHSERVER_TEMPLATEDIR
		// is set, so that is a real reader, and it is what pins this guard in
		// TestFormPostBindMapOmitsAnAbsentState (#146).
		if code.State != "" {
			m["state"] = code.State
		}

		t, err := template.ParseFS(templateFS, "form_post.html")
		if err != nil {
			return errors.Wrap(err, "unable to parse template")
		}

		// Render into a buffer, not straight to w, matching the error emitter's twin. Execute
		// writes as it walks the template, so a template that parses and then fails part way
		// through leaves a partial body and an implicit 200 already on the wire; the caller answers
		// an error from here with httpHelper.InternalServerError, and a WriteHeader after the
		// response is committed changes nothing, so the client would be told 200 for a page that
		// was never finished. Here that half-written page would be a form carrying an
		// authorization code with no submit to deliver it. form_post.html is operator supplied
		// whenever GOIABADA_AUTHSERVER_TEMPLATEDIR is set, so this is reachable in a real
		// deployment rather than only in tests (#141, #146 decision 10).
		var rendered bytes.Buffer
		err = t.Execute(&rendered, m)
		if err != nil {
			return errors.Wrap(err, "unable to execute template")
		}
		// OAuth 2.0 Form Post Response Mode section 2: "Because the Authorization Response is
		// intended to be used only once, the Authorization Server MUST instruct the User Agent (and
		// any intermediaries) not to store or reuse the content of the response." This page carries
		// an authorization code and the client's state, so a cached or reused copy is a replayable
		// response sitting in an intermediary. This pair is what the rest of this codebase already
		// writes for a no-store response (#146).
		//
		// Set here rather than before Execute deliberately: a render that fails must leave the
		// response completely untouched, so the caller's last-resort InternalServerError owns every
		// header as well as the status (#141).
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")

		_, err = w.Write(rendered.Bytes())
		if err != nil {
			// The connection itself failed. Nothing can be recovered from here, including the
			// caller's 500, but the error is still worth reporting rather than swallowing.
			return errors.Wrap(err, "unable to write the form_post response")
		}
		return nil
	}

	// default to query
	//
	// writeResponseParams, not ParseRequestURI() then Query() then Encode(). That sequence seeded
	// url.Values from the registered redirect URI's own query and Add'ed on top of it, so a client
	// that had registered "?state=fixed" got back two state parameters and Go's own
	// url.Values.Get answers with the first, which is the registered one. This is the redirect
	// carrying the authorization code, so it is the response an RP's RFC 9700 2.1 CSRF check exists
	// to guard, and unlike the error path it fired on every successful authorization rather than
	// only on a refusal. Re-encoding also rewrote the registered query in five separate ways,
	// against RFC 6749 3.1.2's "MUST be retained". Both are the shared helper's to prevent, and its
	// comment carries the detail (#146).
	//
	// authorizationResponseParamNames, so a registered "error" is dropped from a success response as
	// well: without it a client registering "?error=stale" completed an authorization and received
	// "?error=stale&code=fresh&state=...", which an RP checking for "error" before reading "code"
	// reads as a refusal of the authorization it just granted. It is also what drops a registered
	// "?state=fixed" when the request carried no state of its own, so the client is never handed a
	// state on this redirect that it did not send (#146).
	location, err := writeResponseParams(code.RedirectURI, params, authorizationResponseParamNames)
	if err != nil {
		return errors.Wrap(err, "unable to build the authorization code redirect")
	}

	http.Redirect(w, r, location, http.StatusFound)
	return nil
}
