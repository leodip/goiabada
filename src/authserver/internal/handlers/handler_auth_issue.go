package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/urlutil"
	"github.com/leodip/goiabada/core/errs"
)

// authIssueDatabase is what /auth/issue reads before it issues: the client, its redirect URIs, the
// user and the ambient session. The session row taken before the insert, and the transaction, are
// the code issuer's (#139).
//
// It embeds the authorize port because a refusal here is answered through redirToClientWithError.
type authIssueDatabase interface {
	authorizeDatabase

	ClientLoadRedirectURIs(ctx context.Context, tx *sql.Tx, client *models.Client) error
	GetClientByClientIdentifier(ctx context.Context, tx *sql.Tx, clientIdentifier string) (*models.Client, error)
	GetUserById(ctx context.Context, tx *sql.Tx, userId int64) (*models.User, error)
	GetUserSessionBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (*models.UserSession, error)
}

func HandleIssueGet(
	pageRenderer PageRenderer,
	ceremonyStore CeremonyStore,
	templateFS fs.FS,
	codeIssuer CodeIssuer,
	implicitTokenIssuer ImplicitTokenIssuer,
	database authIssueDatabase,
	auditLogger AuditLogger,
	userSessionManager UserSessionManager,
	permissionChecker PermissionChecker,
	baseURL string,
	adminConsoleBaseURL string,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authContext, ok := loadAuthContext(pageRenderer, ceremonyStore, w, r, adminConsoleBaseURL)
		if !ok {
			return
		}

		if !requireAuthState(pageRenderer, w, r, authContext, ceremony.AuthStateReadyToIssueCode) {
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
		issuingClient, err := database.GetClientByClientIdentifier(r.Context(), nil, authContext.ClientId)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
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
			err = database.ClientLoadRedirectURIs(r.Context(), nil, issuingClient)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
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
			slog.WarnContext(r.Context(), "the redirect URI this ceremony would be answered at is no longer registered on the client, so nothing is issued and nothing is emitted",
				"client_identifier", authContext.ClientId)

			auditLogger.Log(r.Context(), audit.AuditIssuanceRefusedRedirectURI, map[string]interface{}{
				"userId":   authContext.UserId,
				"clientId": authContext.ClientId,
			})

			// The clear goes FIRST, the order every refusal in this handler uses: ClearAuthContext
			// persists the deletion through a Set-Cookie on w, and the render below commits the
			// response, so clearing afterwards leaves the header on a response already written
			// (#141).
			err = ceremonyStore.ClearAuthContext(w, r)
			if err != nil {
				// This is the ONE refusal in the file whose fallback is not "answer the client
				// with server_error". Answering this client is precisely what the gate exists to
				// prevent, and an error redirect is a response to the deregistered URI just as a
				// code would be. So the page is rendered regardless and the browser keeps a
				// replayable auth context, which is the lesser of the two: a replay arrives back
				// at this same gate and is refused again for as long as the registration is gone.
				slog.ErrorContext(r.Context(), "unable to clear the auth context while withholding a redirect to a deregistered URI, rendering the refusal anyway",
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
			err = renderRedirectBlocked(pageRenderer, w, r, redirectErrorInput{
				client:      issuingClient,
				redirectURI: authContext.RedirectURI,
			})
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
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
			user, err = database.GetUserById(r.Context(), nil, authContext.UserId)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
				return
			}
			if user == nil || user.Subject != authContext.IdTokenHintSub {
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
				refusalErr := ceremonyStore.ClearAuthContext(w, r)
				if refusalErr != nil {
					// The clear failed, so Save wrote no cookie and the browser still holds the
					// auth context. The client is owed an error response regardless: its redirect
					// URI was validated upstream, so OIDC Core 1.0 3.1.2.2 with 3.1.2.6 applies,
					// and RFC 6749 4.1.2.1 mints server_error for exactly this condition (#141).
					slog.ErrorContext(r.Context(), "unable to clear the auth context, answering the client with server_error",
						"error", refusalErr)
					refusalErr = redirToClientWithError(w, r, database, pageRenderer, templateFS,
						redirectErrorFromAuthContext(authContext, issuingClient, "server_error", "Internal server error"))
					if refusalErr != nil {
						// Nowhere left to send the client, so the 500 is the last resort here.
						pageRenderer.InternalServerError(w, r, refusalErr)
					}
					return
				}

				refusalErr = redirToClientWithError(w, r, database, pageRenderer, templateFS,
					redirectErrorFromAuthContext(authContext, issuingClient, oidc.ErrorLoginRequired,
						"The authenticated user does not match the id_token_hint"))
				if refusalErr != nil {
					pageRenderer.InternalServerError(w, r, refusalErr)
					return
				}
				return
			}
		}

		sessionIdentifier, _ := reqctx.SessionIdentifierFrom(r.Context())

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
			ambientSession, err = database.GetUserSessionBySessionIdentifier(r.Context(), nil, sessionIdentifier)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
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
		isImplicitFlow := protocolvalidation.ParseResponseType(authContext.ResponseType).IsImplicitFlow()

		// nil for the requested max age, and that is decision 1 rather than an omission. max_age
		// bounds the age of the AUTHENTICATION, which this ceremony already satisfied at
		// /auth/completed; re-applying it here would turn it into a deadline for reading the
		// consent screen. UserSession.IsValid measures it from the session's AuthTime, so
		// max_age=0 is violated a nanosecond after the credential was accepted and every such
		// ceremony would restart at level 1, mint a fresh session and fail again (#241).
		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			pageRenderer.InternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}
		sessionIsValid := userSessionManager.HasValidUserSession(ambientSession,
			settings.UserSessionIdleTimeoutInSeconds, settings.UserSessionMaxLifetimeInSeconds, nil)

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
				sessionIdentifier, pageRenderer, ceremonyStore, templateFS, database, auditLogger, baseURL)
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
			user, err = database.GetUserById(r.Context(), nil, authContext.UserId)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
				return
			}
		}
		if user == nil {
			pageRenderer.InternalServerError(w, r, errs.Errorf("user %v not found", authContext.UserId))
			return
		}

		// Whichever field the issuer will READ, and never the other one. IssueAuthCodeTx and
		// handleImplicitFlow both prefer ConsentedScope and fall back to Scope when it is empty,
		// so writing an emptied ConsentedScope back would fall through to the full unfiltered
		// request, which is why the empty result refuses instead of writing anything at all
		// (#241 decision 2).
		scopeField := &authContext.Scope
		if authContext.ConsentedScope != "" {
			scopeField = &authContext.ConsentedScope
		}
		effectiveScope, err := permissionChecker.FilterOutScopesWhereUserIsNotAuthorized(r.Context(), *scopeField, user)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}

		if effectiveScope == "" {
			slog.WarnContext(r.Context(), "the user holds none of the permissions behind the scopes this ceremony would grant, so nothing is issued",
				"user_id", authContext.UserId,
				"client_identifier", authContext.ClientId)

			auditLogger.Log(r.Context(), audit.AuditIssuanceRefusedScopeDenied, map[string]interface{}{
				"userId":   authContext.UserId,
				"clientId": authContext.ClientId,
			})

			// The wording and the error code are /auth/completed's for the same condition,
			// arriving later: the same removal gets one answer wherever it lands.
			//
			// The clear goes FIRST, for the reason every refusal in this handler states: a
			// Set-Cookie written after redirToClientWithError has committed never reaches the
			// wire, so the browser would keep a replayable auth context (#141).
			err = ceremonyStore.ClearAuthContext(w, r)
			if err != nil {
				// The clear failed, so Save wrote no cookie and the browser still holds the
				// auth context. The client is owed an error response regardless: its redirect
				// URI was validated upstream and re-checked above, so OIDC Core 1.0 3.1.2.2
				// with 3.1.2.6 applies, and RFC 6749 4.1.2.1 mints server_error for exactly
				// this condition (#141).
				slog.ErrorContext(r.Context(), "unable to clear the auth context, answering the client with server_error",
					"error", err)
				err = redirToClientWithError(w, r, database, pageRenderer, templateFS,
					redirectErrorFromAuthContext(authContext, issuingClient, "server_error", "Internal server error"))
				if err != nil {
					// Nowhere left to send the client, so the 500 is the last resort here.
					pageRenderer.InternalServerError(w, r, err)
				}
				return
			}

			err = redirToClientWithError(w, r, database, pageRenderer, templateFS,
				redirectErrorFromAuthContext(authContext, issuingClient, "access_denied",
					"The user is not authorized to access any of the requested scopes"))
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
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
			err = handleImplicitFlow(w, r, authContext, sessionIdentifier, issuingClient, user, settings, ceremonyStore, implicitTokenIssuer, auditLogger)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
			}
			return
		}

		// Authorization Code Flow

		createCodeInput := newCreateCodeInput(authContext, sessionIdentifier)

		// The session row and the insert share one transaction the issuer opens, which is what
		// orders this ceremony against a termination of that session (#139); the liveness read
		// above cannot do it alone. It is opened here, on the authorization code branch only, so
		// the row is held across as few statements as possible: the implicit flow mints no code and
		// no refresh token, so it has no durable grant for this to protect (#139 decision 6).
		code, err := codeIssuer.IssueAuthCodeTx(r.Context(), createCodeInput)
		if errors.Is(err, issuance.ErrIssuingSessionGone) || errors.Is(err, issuance.ErrIssuingClientGone) {
			if errors.Is(err, issuance.ErrIssuingClientGone) {
				// The client's registration went away under this ceremony, between the liveness
				// read above the dispatch and the insert. Answered as the session-gone shape rather
				// than as a 500: nothing is wrong with this server, the application the browser was
				// signing in to no longer exists, and the refusal path already knows how to say that
				// once for an interactive ceremony and once for a silent one. redirectWillBeEmitted
				// re-reads the registration on its way out and withholds the redirect, so a deleted
				// client is told on an interstitial rather than by a redirect to an address nobody
				// owns any more (#248 part 5).
				slog.WarnContext(r.Context(), "the client this ceremony is issuing for no longer exists, refusing to issue a code",
					"client_identifier", authContext.ClientId,
					"session_identifier", sessionIdentifier)
			}
			// The gone shape, answered exactly as the liveness read above answers it: the browser
			// restarts at level 1 and a prompt=none ceremony is told login_required. The issuer
			// returns either sentinel only after its transaction has rolled back, which the refusal
			// needs: it writes the session store on a nil transaction, and on SQLite that is the
			// connection the transaction was holding (#139).
			refuseIssuanceUnusableSession(w, r, sessionGone, authContext, issuingClient, ambientSession,
				sessionIdentifier, pageRenderer, ceremonyStore, templateFS, database, auditLogger, baseURL)
			return
		}

		// Everything below this line attests to a write, so it waits for the issuer to return,
		// which is after the commit: the rule revocation.TerminateUserSessionTx documents, never
		// attest to a write that could still roll back. A commit that returns an error leaves the
		// code row's fate indeterminate, and the client is answered with a 500 rather than a code.
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}

		auditLogger.Log(r.Context(), audit.AuditCreatedAuthCode, map[string]interface{}{
			"userId":   createCodeInput.UserId,
			"clientId": code.ClientId,
			"codeId":   code.Id,
		})

		// A failed clear leaves the context in ready_to_issue_code, so a reload mints a second
		// code, and that is a retry rather than a second grant. The code row stores only the
		// plaintext's SHA-256 (models.Code.Code is db:"-"), and this 500 is answered before
		// issueAuthCode, so the first code reaches nobody and cannot be redeemed; the reload's is
		// the only one delivered, and the worker's code sweep deletes the orphaned row once it is
		// past its grace cutoff. Clearing before minting would strand the user on a transient
		// mint fault where a reload now retries (#248 part 6, #436).
		err = ceremonyStore.ClearAuthContext(w, r)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
		err = issueAuthCode(w, r, templateFS, code, authContext.ResponseMode)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
		}
	}
}

// newCreateCodeInput copies the fields an authorization code is written from off the ceremony,
// with the session the code binds to. Issuance names only these, so it depends on no ceremony
// state it does not read (#437).
func newCreateCodeInput(authContext *ceremony.AuthContext, sessionIdentifier string) *issuance.CreateCodeInput {
	return &issuance.CreateCodeInput{
		ClientId:            authContext.ClientId,
		RedirectURI:         authContext.RedirectURI,
		ResponseMode:        authContext.ResponseMode,
		Scope:               authContext.Scope,
		ConsentedScope:      authContext.ConsentedScope,
		CodeChallenge:       authContext.CodeChallenge,
		CodeChallengeMethod: authContext.CodeChallengeMethod,
		State:               authContext.State,
		Nonce:               authContext.Nonce,
		UserAgent:           authContext.UserAgent,
		IpAddress:           authContext.IpAddress,
		UserId:              authContext.UserId,
		AcrLevel:            authContext.AcrLevel,
		AuthMethods:         authContext.AuthMethods,
		AuthenticatedAt:     authContext.AuthenticatedAt,
		AuthStateGeneration: authContext.AuthStateGeneration,
		SessionIdentifier:   sessionIdentifier,
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
	authContext *ceremony.AuthContext,
	issuingClient *models.Client,
	ambientSession *models.UserSession,
	sessionIdentifier string,
	pageRenderer PageRenderer,
	ceremonyStore CeremonyStore,
	templateFS fs.FS,
	database authIssueDatabase,
	auditLogger AuditLogger,
	baseURL string,
) {
	// Only the expired shape audits. The foreign and gone shapes are #133's and #129's refusals,
	// writing no audit row today; this event attests the check #241 added, which is the one an
	// administrator can cause by configuring a timeout, and stretching it over two older
	// conditions would make it useless for answering the question it exists for.
	if shape == sessionExpired {
		auditLogger.Log(r.Context(), audit.AuditIssuanceRefusedSessionInvalid, map[string]interface{}{
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
			slog.WarnContext(r.Context(), "the session in this browser belongs to a different user, returning login_required instead of binding this silent ceremony to it",
				"session_identifier", sessionIdentifier,
				"session_user_id", ambientSession.UserId,
				"ceremony_user_id", authContext.UserId)
		case sessionExpired:
			slog.WarnContext(r.Context(), "the session backing this silent ceremony is no longer within its idle timeout or maximum lifetime, returning login_required instead of issuing a code",
				"session_identifier", sessionIdentifier,
				"session_user_id", ambientSession.UserId)
		default:
			slog.WarnContext(r.Context(), "the session backing this silent ceremony is gone, returning login_required instead of issuing a code",
				"session_identifier", sessionIdentifier)
		}
		// The clear goes FIRST, which is the order the restart below uses too. ClearAuthContext
		// persists the deletion through a Set-Cookie on w, and redirToClientWithError commits the
		// response in every response mode, so clearing afterwards leaves the header on a response
		// already written and the browser keeps a ready_to_issue_code context it can replay.
		//
		// Provenance is resolved before the dispatch, for the same reason as at the id_token_hint
		// refusal (#108). The registration gate at the top of the handler loaded the client and
		// refused a nil, so issuingClient is it.
		err := ceremonyStore.ClearAuthContext(w, r)
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
			slog.ErrorContext(r.Context(), "unable to clear the auth context, answering the client with server_error",
				"error", err)
			err = redirToClientWithError(w, r, database, pageRenderer, templateFS,
				redirectErrorFromAuthContext(authContext, issuingClient, "server_error", "Internal server error"))
			if err != nil {
				// Nowhere left to send the client, so the 500 is the last resort here.
				pageRenderer.InternalServerError(w, r, err)
			}
			return
		}
		err = redirToClientWithError(w, r, database, pageRenderer, templateFS,
			redirectErrorFromAuthContext(authContext, issuingClient, oidc.ErrorLoginRequired,
				"User authentication is required"))
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
		return
	}

	switch shape {
	case sessionForeign:
		slog.WarnContext(r.Context(), "the session in this browser belongs to a different user, restarting level 1 instead of binding this ceremony to it",
			"session_identifier", sessionIdentifier,
			"session_user_id", ambientSession.UserId,
			"ceremony_user_id", authContext.UserId)
	case sessionExpired:
		slog.WarnContext(r.Context(), "the session backing this ceremony is no longer within its idle timeout or maximum lifetime, restarting level 1 instead of issuing a code",
			"session_identifier", sessionIdentifier,
			"session_user_id", ambientSession.UserId)
	default:
		slog.WarnContext(r.Context(), "the session backing this ceremony is gone, restarting level 1 instead of issuing a code",
			"session_identifier", sessionIdentifier)
	}
	// Restart route 2. Whoever signs in next may not be the user this attempt authenticated, so
	// their methods, scope and consent are computed afresh from the request (#140, #436).
	authContext.Restart()
	err := ceremonyStore.SaveAuthContext(w, r, authContext)
	if err != nil {
		pageRenderer.InternalServerError(w, r, err)
		return
	}
	http.Redirect(w, r, baseURL+"/auth/level1", http.StatusFound)
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
	authContext *ceremony.AuthContext,
	sessionIdentifier string,
	client *models.Client,
	user *models.User,
	settings *models.Settings,
	ceremonyStore CeremonyStore,
	implicitTokenIssuer ImplicitTokenIssuer,
	auditLogger AuditLogger,
) error {
	// Determine what tokens to issue based on response_type
	rtInfo := protocolvalidation.ParseResponseType(authContext.ResponseType)
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
	implicitInput := &issuance.ImplicitGrantInput{
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

	tokenResponse, err := implicitTokenIssuer.GenerateTokenResponseForImplicit(r.Context(), settings, implicitInput, issueAccessToken, issueIdToken)
	if err != nil {
		return err
	}

	// Audit log
	auditLogger.Log(r.Context(), audit.AuditTokenIssuedImplicitResponse, map[string]interface{}{
		"userId":           user.Id,
		"clientId":         client.Id,
		"scope":            scope,
		"responseType":     authContext.ResponseType,
		"issueAccessToken": issueAccessToken,
		"issueIdToken":     issueIdToken,
	})

	// Clear auth context
	err = ceremonyStore.ClearAuthContext(w, r)
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
	tokenResponse *issuance.ImplicitGrantResponse,
) error {
	// Gate 4, the last resort. This flow hands over access and ID tokens rather than a code, so a
	// redirect URI that resolves to a host the operator never registered exfiltrates credentials
	// directly rather than something still to be exchanged. Nothing can reach here with such a value
	// once the authorization endpoint has refused it, and the check stays so that the property is
	// enforced by a test rather than claimed by a comment (#122).
	if err := checkRedirectURIEmittable(r.Context(), "issueImplicitTokens", redirectURI); err != nil {
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
	//nolint:gosec // G710: a redirect URI registered on the client and matched exactly, checked again at gate 4 above
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
	if err := checkRedirectURIEmittable(r.Context(), "issueAuthCode", code.RedirectURI); err != nil {
		return err
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

	// An empty response mode is the query, the default for response_type=code (OAuth 2.0 Multiple
	// Response Type Encoding Practices 2.1).
	return writeAuthorizationResponse(w, r, templateFS, responseMode, code.RedirectURI, params)
}
