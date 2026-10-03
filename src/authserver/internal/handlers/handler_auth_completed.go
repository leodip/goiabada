package handlers

import (
	"context"
	"database/sql"
	"io/fs"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/revocation"
	"github.com/leodip/goiabada/authserver/internal/usersession"
	"github.com/leodip/goiabada/core/errs"
)

// authCompletedDatabase is what the end of the authentication ceremony needs: the session it
// bumps or replaces, and the generation it promotes.
//
// It embeds the authorize port because a refusal here is answered through redirToClientWithError,
// and the revocation port because an unusable session is terminated through
// revocation.TerminateUserSessionTx.
type authCompletedDatabase interface {
	authorizeDatabase
	revocation.Database

	GetClientByClientIdentifier(ctx context.Context, tx *sql.Tx, clientIdentifier string) (*models.Client, error)
	GetUserById(ctx context.Context, tx *sql.Tx, userId int64) (*models.User, error)
	GetUserSessionBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (*models.UserSession, error)
	PromoteUserSessionOtpConfigGeneration(ctx context.Context, tx *sql.Tx, userSessionId int64, generation int64) error
	UpdateUserSession(ctx context.Context, tx *sql.Tx, userSession *models.UserSession) error
	UserSessionLoadUser(ctx context.Context, tx *sql.Tx, userSession *models.UserSession) error
}

func HandleAuthCompletedGet(
	pageRenderer PageRenderer,
	ceremonyStore CeremonyStore,
	userSessionManager UserSessionManager,
	database authCompletedDatabase,
	templateFS fs.FS,
	auditLogger AuditLogger,
	permissionChecker PermissionChecker,
	baseURL string,
	adminConsoleBaseURL string,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		authContext, ok := loadAuthContext(pageRenderer, ceremonyStore, auditLogger, w, r, adminConsoleBaseURL)
		if !ok {
			return
		}

		if !requireAuthState(pageRenderer, w, r, authContext, ceremony.AuthStateAuthenticationCompleted) {
			return
		}

		sessionIdentifier, _ := reqctx.SessionIdentifierFrom(r.Context())

		userSession, err := database.GetUserSessionBySessionIdentifier(r.Context(), nil, sessionIdentifier)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}

		err = database.UserSessionLoadUser(r.Context(), nil, userSession)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}

		client, err := database.GetClientByClientIdentifier(r.Context(), nil, authContext.ClientId)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
		if client == nil {
			pageRenderer.InternalServerError(w, r, errs.Errorf("client %v not found", authContext.ClientId))
			return
		}

		targetAcrLevel := authContext.GetTargetAcrLevel(client.DefaultAcrLevel)
		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			pageRenderer.InternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}
		hasValidUserSession := userSessionManager.HasValidUserSession(userSession,
			settings.UserSessionIdleTimeoutInSeconds, settings.UserSessionMaxLifetimeInSeconds, authContext.RequestedMaxAge())

		plan := decideCompletion(completionFacts{
			sessionPresent:  userSession != nil,
			sessionValid:    hasValidUserSession,
			sessionOwned:    authContext.OwnsSession(userSession),
			level1Completed: authContext.Level1AuthCompleted,
			// authContext.AuthenticatedAt is set when the user actually enters credentials in
			// this ceremony, by the password handler and by the OTP handler. It is nil for SSO
			// session reuse (existing session flows through level1completed without hitting
			// either). It is NOT proof of level 1, since OTP alone sets it (#129 decision 15).
			credentialEntered:           authContext.AuthenticatedAt != nil && !authContext.AuthenticatedAt.IsZero(),
			raisesPrivilege:             usersession.WillRaisePrivilege(userSession, authContext.AuthMethods, targetAcrLevel),
			otpConfigGenerationCaptured: authContext.OtpConfigGeneration != nil,
			target:                      targetAcrLevel,
		})

		// The session this ceremony actually bound to, which is what the ACR below is taken
		// against. It is the bumped row on the reuse arm and the freshly created row on the
		// create arm, never the ambient one the browser happened to carry (#133).
		var boundSession *models.UserSession

		switch plan.arm {
		case completionArmRestart:
			// Restart route 1. The attempt is discarded with it, so methods and the user
			// carried in from the session that ended do not reach the session the second
			// pass creates (#140, #436).
			authContext.Restart()
			err = ceremonyStore.SaveAuthContext(w, r, authContext)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, ceremonyStepURL(baseURL, "/auth/level1", authContext), http.StatusFound)
			return
		case completionArmReuse:
			boundSession, err = bindReusedSession(w, r, plan, ceremonyStore, userSessionManager, database,
				auditLogger, authContext, client, sessionIdentifier, targetAcrLevel)
		default:
			boundSession, err = bindNewSession(w, r, plan, userSessionManager, database, auditLogger,
				authContext, client, userSession, targetAcrLevel)
		}
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}

		// set the acr level in the auth context
		//
		// Against the session this ceremony bound to, not the one the browser arrived with. The
		// two differ whenever the create arm ran with an ambient session present, and the ACR is
		// the maximum of the two arguments, so feeding the ambient row lets a session this
		// ceremony did not bind to raise the acr claim of a token bound to a different session:
		// another user's completed second factor, or this user's own expired one, would satisfy
		// a level 2 client that this ceremony only ever answered with a password (#133).
		err = authContext.SetAcrLevel(targetAcrLevel, boundSession)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}

		user, err := database.GetUserById(r.Context(), nil, authContext.UserId)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
		if user == nil {
			pageRenderer.InternalServerError(w, r, errs.New("user not found"))
			return
		}

		facts := afterBindingFacts{
			userEnabled:     user.Enabled,
			promptConsent:   authContext.HasPromptValue("consent"),
			consentRequired: client.ConsentRequired,
		}
		answer, need := decideAfterBinding(facts)
		for need != afterBindingFactNone {
			switch need {
			case afterBindingFactEffectiveScope:
				// The effective scope is the requested one with every scope the user is not
				// authorized for filtered out, and it replaces the ceremony's scope.
				effectiveScope, filterErr := permissionChecker.FilterOutScopesWhereUserIsNotAuthorized(r.Context(), authContext.Scope, user)
				if filterErr != nil {
					pageRenderer.InternalServerError(w, r, filterErr)
					return
				}
				authContext.SetScope(effectiveScope)
				scope := authContext.Scope
				facts.effectiveScope = &scope
			}
			answer, need = decideAfterBinding(facts)
		}

		switch answer {
		case afterBindingUserDisabled:
			auditLogger.Log(r.Context(), audit.EventUserDisabled, map[string]interface{}{
				"userId": user.Id,
			})
			answerClientWithError(w, r, database, pageRenderer, ceremonyStore, templateFS,
				redirectErrorFromAuthContext(authContext, client, "access_denied", userDisabledDescription))
		case afterBindingNoScope:
			answerClientWithError(w, r, database, pageRenderer, ceremonyStore, templateFS,
				redirectErrorFromAuthContext(authContext, client,
					"access_denied", "The user is not authorized to access any of the requested scopes"))
		case afterBindingConsent:
			authContext.AuthState = ceremony.AuthStateRequiresConsent
			err = ceremonyStore.SaveAuthContext(w, r, authContext)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, ceremonyStepURL(baseURL, "/auth/consent", authContext), http.StatusFound)
		default:
			authContext.AuthState = ceremony.AuthStateReadyToIssueCode
			err = ceremonyStore.SaveAuthContext(w, r, authContext)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, ceremonyStepURL(baseURL, "/auth/issue", authContext), http.StatusFound)
		}
	}
}

// completionArm is how /auth/completed binds the ceremony to a session.
type completionArm int

const (
	// completionArmReuse bumps the session the browser arrived with.
	completionArmReuse completionArm = iota + 1
	// completionArmCreate starts a new session.
	completionArmCreate
	// completionArmRestart sends the ceremony back to level 1 (restart route 1).
	completionArmRestart
)

// completionFacts is what decideCompletion decides from, every one of them read before the
// decision.
type completionFacts struct {
	// sessionPresent, sessionValid and sessionOwned are about the session the browser arrived with.
	sessionPresent bool
	sessionValid   bool
	sessionOwned   bool
	// level1Completed is the ceremony's Level1AuthCompleted.
	level1Completed bool
	// credentialEntered says a credential was accepted in this ceremony: AuthenticatedAt is set.
	credentialEntered bool
	// raisesPrivilege is usersession.WillRaisePrivilege for the arrived-with session.
	raisesPrivilege bool
	// otpConfigGenerationCaptured says the ceremony captured the user's OTP config generation.
	otpConfigGenerationCaptured bool
	target                      models.AcrLevel
}

// completionPlan is decideCompletion's answer: the arm, and what that arm does beyond its core
// write. The reuse arm's three flags and the create arm's two are false on every other arm.
type completionPlan struct {
	arm completionArm

	// rotateIdentifier rotates the browser session's identifier before the bump.
	rotateIdentifier bool
	// refreshAuthTime writes the credential's instant onto the bumped session.
	refreshAuthTime bool
	// promoteOtpConfigGeneration records the generation the session answered level 2 against.
	promoteOtpConfigGeneration bool

	// terminateForeignSession ends the arrived-with session, which is another user's.
	terminateForeignSession bool
	// replaceOwnSession has the new session replace the arrived-with one, which is this user's.
	replaceOwnSession bool
}

// decideCompletion decides how the end of an authentication ceremony binds it to a session.
//
// Reuse needs the arrived-with session both valid and owned. Validity and ownership are separate
// questions and both have to be yes before this ceremony may reuse the session the browser arrived
// with. The browser can still be carrying user A's cookie while user B authenticates: prompt=login
// and an id_token_hint naming someone else both redirect to the login page without clearing it,
// and a session row that has stopped being valid keeps its cookie too. Reusing A's session for B's
// ceremony bumps A's row with B's methods and stamps A's session identifier onto B's authorization
// code, so B's grant is bound to a session B does not own and A's next request resumes a session
// B's ceremony rewrote (#133). On that arm:
//
//   - the identifier rotates when the bump will raise a privilege, the other half of OWASP's
//     "regenerate on any privilege level change", since this server's ACR levels are privilege
//     levels by construction (#266 decision 6). It is not fixation defence: reaching this arm means
//     the browser already held a session this ceremony may reuse, and fixation is closed on the
//     create arm, inside StartNewUserSession;
//   - AuthTime is refreshed when a credential was entered in this ceremony (prompt=login, step-up),
//     since the bump preserves the old AuthTime, which is right for SSO reuse only;
//   - the OTP config generation is promoted when the ceremony captured one and the target is above
//     level 1. A missing capture means the ceremony never reached /auth/level2, which can only
//     happen when the snapshot already matched, so there is nothing to promote. The ACR gate is
//     needed because the password handler captures too: without it a prompt=login ceremony at a
//     level 1 client would discharge a level 2 obligation it never addressed. It is the level test
//     ceremony.StepUpOwed applies when /auth/level1completed decides the step-up, so the two agree
//     by construction (#242 decision 3).
//
// With no session this ceremony may reuse (there is none, it is no longer valid, or it belongs to
// somebody else), only level 1 authentication performed in THIS ceremony justifies creating one:
// without this gate StartNewUserSession mints a session from the ceremony's UserId with no proof
// anyone authenticated, so a ceremony whose session was ended mid-flight silently recreates it
// (#129 decision 6). The predicate is deliberately "this ceremony did level 1" rather than "no
// valid session". The second shape is legitimate: a session is deleted and the user then starts a
// fresh ceremony and really does enter a password, which is what
// TestSessionDeletedDuringAuthFlow_LoginSucceeds guards (#46). There is no loop either, because the
// second pass has Level1AuthCompleted set by handler_auth_pwd. It reads Level1AuthCompleted rather
// than credentialEntered, and that is the whole point of the field (#129 decision 15):
// AuthenticatedAt has two writers, and a ceremony that stepped up to OTP by reusing a session
// satisfies it without a password. handlePromptNone sets AuthenticatedAt too, from the session it
// reused, and while it goes straight to /auth/issue and never arrives here, it would be stopped
// rather than let through if it ever did.
//
// On the create arm, an arrived-with session that is another user's is terminated, valid or not:
// the browser carries the cookie either way, and a row that can never be resumed achieves nothing
// while its offline grants keep working (#133). One that is this user's is not reusable (expired,
// idle, or older than the max_age asked for), so the new session replaces it (#133, #243).
func decideCompletion(f completionFacts) completionPlan {
	if f.sessionValid && f.sessionOwned {
		return completionPlan{
			arm:                        completionArmReuse,
			rotateIdentifier:           f.raisesPrivilege,
			refreshAuthTime:            f.credentialEntered,
			promoteOtpConfigGeneration: f.otpConfigGenerationCaptured && ceremony.TargetRequiresSecondFactor(f.target),
		}
	}
	if !f.level1Completed {
		return completionPlan{arm: completionArmRestart}
	}
	return completionPlan{
		arm:                     completionArmCreate,
		terminateForeignSession: f.sessionPresent && !f.sessionOwned,
		replaceOwnSession:       f.sessionPresent && f.sessionOwned,
	}
}

// bindReusedSession is the reuse arm: it bumps the session the browser arrived with, as plan says,
// and answers the bumped row.
func bindReusedSession(
	w http.ResponseWriter,
	r *http.Request,
	plan completionPlan,
	ceremonyStore CeremonyStore,
	userSessionManager UserSessionManager,
	database authCompletedDatabase,
	auditLogger AuditLogger,
	authContext *ceremony.AuthContext,
	client *models.Client,
	sessionIdentifier string,
	targetAcrLevel models.AcrLevel,
) (*models.UserSession, error) {
	// Rotate the browser session's identifier before the privilege is committed.
	//
	// The order is the whole of it. BumpUserSession opens its own transaction and commits before
	// it returns, so rotating afterwards leaves a window in which the identifier the browser
	// arrived with names a user session that is already at the higher level: an identifier stolen
	// at level 1 would keep working after the step-up, which is the carryover rotation exists to
	// stop. Deciding from the pre-bump session and rotating first means a failure between the two
	// leaves a fresh identifier on a session that has not been raised, which is the safe direction.
	if plan.rotateIdentifier {
		if err := ceremonyStore.RegenerateSession(w, r); err != nil {
			return nil, err
		}
	}

	// Bump session with current auth context's methods and target ACR level.
	// This handles step-up authentication: if the user had a level1 session but just
	// completed OTP for a level2 client, the session's AuthMethods and AcrLevel
	// will be upgraded to reflect the stronger authentication that was performed.
	bumpedSession, err := userSessionManager.BumpUserSession(r.Context(), sessionIdentifier, client.Id,
		authContext.AuthMethods, targetAcrLevel, middleware.ClientIP(r))
	if err != nil {
		return nil, err
	}

	if plan.refreshAuthTime {
		// The value is the one the credential handler captured, never the clock read here.
		// auth_time is what max_age is measured against, "the last time the End-User was actively
		// authenticated by the OP" in OIDC Core 3.1.2.1, and the browser owns the hop between the
		// credential and this handler: reading the clock here lets a tab paused after the password
		// was accepted and resumed hours later mint a token saying the user authenticated just now,
		// so a relying party that asked for a fresh sign-in is told it got one (#252 decision 8).
		// refreshAuthTime is exactly the guard that makes the dereference safe: non-nil and
		// non-zero.
		bumpedSession.AuthTime = authContext.AuthenticatedAt.UTC()
		err = database.UpdateUserSession(r.Context(), nil, bumpedSession)
		if err != nil {
			return nil, err
		}
	}

	// Use session's AuthTime as auth_time source of truth. For SSO reuse
	// this preserves the original value; for re-auth it was just refreshed.
	// Legacy sessions without AuthTime fall back to Started (consistent with
	// the prompt=none path in handler_authorize.go).
	if bumpedSession.AuthTime.IsZero() {
		authContext.AuthenticatedAt = &bumpedSession.Started
	} else {
		authContext.AuthenticatedAt = &bumpedSession.AuthTime
	}

	// After the bump and after the AuthTime write above, both of which write the whole row:
	// otp_config_generation is tagged dont-update so neither carries it, and this narrow write is
	// the only thing that moves it (#242).
	if plan.promoteOtpConfigGeneration {
		err = database.PromoteUserSessionOtpConfigGeneration(r.Context(), nil, bumpedSession.Id,
			*authContext.OtpConfigGeneration)
		if err != nil {
			return nil, err
		}
		bumpedSession.OtpConfigGeneration = *authContext.OtpConfigGeneration
	}

	auditLogger.Log(r.Context(), audit.EventBumpedUserSession, map[string]interface{}{
		"userId":   authContext.UserId,
		"clientId": client.Id,
	})

	return bumpedSession, nil
}

// bindNewSession is the create arm: it ends the arrived-with session when plan says it is another
// user's, starts a new one, and answers it.
func bindNewSession(
	w http.ResponseWriter,
	r *http.Request,
	plan completionPlan,
	userSessionManager UserSessionManager,
	database authCompletedDatabase,
	auditLogger AuditLogger,
	authContext *ceremony.AuthContext,
	client *models.Client,
	userSession *models.UserSession,
	targetAcrLevel models.AcrLevel,
) (*models.UserSession, error) {
	// The browser changed hands, so the session it was carrying is ended rather than left behind.
	// StartNewUserSession below does not do this: it sweeps sibling sessions of the NEW user, so
	// the previous user's row is never a candidate and would survive orphaned, its refresh tokens
	// still working and still bumping it while nobody can reach it through this browser.
	// Termination is the #129 path, so the codes and refresh tokens that session authorized are
	// revoked with it: they are grants this browser holds, and this browser now belongs to someone
	// else. Only grants originating from this session are touched, since both sweeps key on the
	// session identifier, so the previous user's other devices are unaffected (#133).
	//
	// It runs only on this arm, after decideCompletion's level 1 gate, deliberately: destroying
	// somebody's session must follow a real authentication in this ceremony, never a ceremony that
	// merely arrived here. A failure returns 500 with the browser still cookied to the old session
	// and no new session and no code minted, which is the fail-closed direction.
	if plan.terminateForeignSession {
		terminationResult, err := revocation.TerminateUserSessionTx(r.Context(), database, userSession)
		if err != nil {
			return nil, err
		}

		// Three events, all of them after the commit and none before it, so nothing here can
		// attest to a termination that rolled back.
		//
		// This one comes first because it is the reason the other two happened. It attests the
		// handover and the ending, and deliberately not that a replacement now exists:
		// StartNewUserSession below can still fail and return a 500, and started_new_user_session
		// is what attests the replacement. Its absence after this event is how an operator sees a
		// handover that did not complete. Emitting this one after the creation instead would leave
		// that failure recorded as a termination with no actor and no reason, which is the worse
		// trade (#133).
		//
		// Neither event below carries loggedInUser: this is a browser ceremony with no bearer
		// token, and the only identity in scope is the cookie's, which at this instant still names
		// the user being terminated -- recording it would name the party losing the session as the
		// actor who ended it. The actor is this event's userId, which is where an auditor reads it.
		auditLogger.Log(r.Context(), audit.EventCrossUserSessionReplaced, map[string]interface{}{
			"userId":                    authContext.UserId,
			"previousUserId":            userSession.UserId,
			"previousSessionIdentifier": userSession.SessionIdentifier,
			"clientId":                  client.Id,
		})

		// deleted_user_session beside terminated_user_session, the pairing every caller of
		// revocation.TerminateUserSessionTx writes (#129 decision 9): the lifecycle record that a
		// session row is gone, next to the security record of what its grants authorized.
		// Emitting one without the other would make a browser handover the only termination that
		// never reaches a consumer watching the lifecycle stream, and it would falsify the promise
		// that ending a session always writes both.
		auditLogger.Log(r.Context(), audit.EventDeletedUserSession, map[string]interface{}{
			"userSessionId": userSession.Id,
			"loggedInUser":  "",
		})
		revocation.LogTerminatedUserSession(r.Context(), auditLogger, userSession, "", terminationResult)
	}

	// start new session
	// AuthenticatedAt is the credential's instant, and it is what the new row's AuthTime is stamped
	// with rather than the clock inside StartNewUserSession, for the reason bindReusedSession gives
	// (#252 decision 8). It is always set here: decideCompletion refuses this arm without
	// Level1AuthCompleted, and the password handler is the only writer of that field, setting
	// AuthenticatedAt beside it. StartNewUserSession refuses a nil or zero instant rather than
	// inventing one, so if that invariant ever breaks this arm answers 500 instead of minting a
	// session that claims a sign-in happened just now.
	//
	// The browser's own session, when it is this user's, is the one this sign-in replaces, wherever
	// it was last seen from. Nothing it authorized is revoked, which is the policy for a same-user
	// re-login: its session-bound refresh tokens stop as they would on expiry and its offline grants
	// survive (#133, #243). A foreign session was terminated above and is not passed.
	var replacing *models.UserSession
	if plan.replaceOwnSession {
		replacing = userSession
	}
	newSession, removedSessions, err := userSessionManager.StartNewUserSession(
		w, r, authContext.UserId, client.Id, authContext.AuthMethods, targetAcrLevel,
		authContext.AuthStateGeneration, authContext.OtpConfigGeneration,
		authContext.AuthenticatedAt, middleware.ClientIP(r), replacing)

	// Every row the sign-in removed is gone once its transaction committed, which includes a
	// failure that came after the commit, so each is audited before either answer. The payload is
	// the handover's above: this is a browser ceremony with no bearer token, so there is no actor
	// to name beyond the user the new session is for.
	for _, removedSession := range removedSessions {
		auditLogger.Log(r.Context(), audit.EventDeletedUserSession, map[string]interface{}{
			"userSessionId": removedSession.Id,
			"loggedInUser":  "",
		})
	}
	if err != nil {
		return nil, err
	}

	// Use session's AuthTime so auth_time is consistent across SSO requests.
	// For legacy sessions with zero AuthTime, fall back to Started (consistent
	// with the prompt=none path in handler_authorize.go).
	if newSession.AuthTime.IsZero() {
		authContext.AuthenticatedAt = &newSession.Started
	} else {
		authContext.AuthenticatedAt = &newSession.AuthTime
	}

	auditLogger.Log(r.Context(), audit.EventStartedNewUserSession, map[string]interface{}{
		"userId":   authContext.UserId,
		"clientId": client.Id,
	})

	return newSession, nil
}

// afterBindingFact is a fact decideAfterBinding needs and has not been given. HandleAuthCompletedGet
// loads it and asks again.
type afterBindingFact int

const (
	// afterBindingFactNone means the answer is decided.
	afterBindingFactNone afterBindingFact = iota
	// afterBindingFactEffectiveScope is the ceremony's scope narrowed to what the user holds, as
	// AuthContext.SetScope stores it.
	afterBindingFactEffectiveScope
)

// afterBindingAnswer is where a ceremony bound to a session goes next.
type afterBindingAnswer int

const (
	// afterBindingUndecided is returned beside a fact still to load.
	afterBindingUndecided afterBindingAnswer = iota
	// afterBindingUserDisabled answers access_denied for a disabled user.
	afterBindingUserDisabled
	// afterBindingNoScope answers access_denied for a user holding none of the requested scopes.
	afterBindingNoScope
	// afterBindingConsent goes on to the consent screen.
	afterBindingConsent
	// afterBindingIssue goes on to issuance.
	afterBindingIssue
)

// afterBindingFacts is what decideAfterBinding decides from. The effective scope is nil until
// HandleAuthCompletedGet has loaded it.
type afterBindingFacts struct {
	userEnabled bool
	// promptConsent is the prompt's consent token.
	promptConsent bool
	// consentRequired is the client's ConsentRequired.
	consentRequired bool
	effectiveScope  *string
}

// decideAfterBinding decides where a ceremony goes once it is bound to a session, or names the
// next fact it needs to decide that. A disabled user is refused before the scope is filtered, so
// the permission check is made only for a user who may be issued something. prompt=consent forces
// the consent screen regardless of an existing consent or the client's setting; otherwise it is
// shown when the client requires it or offline_access is asked for.
func decideAfterBinding(f afterBindingFacts) (afterBindingAnswer, afterBindingFact) {
	if !f.userEnabled {
		return afterBindingUserDisabled, afterBindingFactNone
	}
	if f.effectiveScope == nil {
		return afterBindingUndecided, afterBindingFactEffectiveScope
	}
	if len(*f.effectiveScope) == 0 {
		return afterBindingNoScope, afterBindingFactNone
	}
	if f.promptConsent || f.consentRequired || oidc.HasOfflineAccessScope(*f.effectiveScope) {
		return afterBindingConsent, afterBindingFactNone
	}
	return afterBindingIssue, afterBindingFactNone
}
