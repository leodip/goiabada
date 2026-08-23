package handlers

import (
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/oidc"
	"github.com/pkg/errors"
)

func HandleAuthCompletedGet(
	httpHelper HttpHelper,
	authHelper AuthHelper,
	userSessionManager UserSessionManager,
	database data.Database,
	templateFS fs.FS,
	auditLogger AuditLogger,
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

		requiredState := oauth.AuthStateAuthenticationCompleted
		if authContext.AuthState != requiredState {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("authContext.AuthState is not "+requiredState)))
			return
		}

		sessionIdentifier := ""
		if r.Context().Value(constants.ContextKeySessionIdentifier) != nil {
			sessionIdentifier = r.Context().Value(constants.ContextKeySessionIdentifier).(string)
		}

		userSession, err := database.GetUserSessionBySessionIdentifier(nil, sessionIdentifier)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		err = database.UserSessionLoadUser(nil, userSession)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		client, err := database.GetClientByClientIdentifier(nil, authContext.ClientId)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if client == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New(fmt.Sprintf("client %v not found", authContext.ClientId))))
			return
		}

		targetAcrLevel := authContext.GetTargetAcrLevel(client.DefaultAcrLevel)
		hasValidUserSession := userSessionManager.HasValidUserSession(r.Context(), userSession, authContext.ParseRequestedMaxAge())
		// Validity and ownership are separate questions and both have to be yes before this
		// ceremony may reuse the session the browser arrived with. The browser can still be
		// carrying user A's cookie while user B authenticates: prompt=login and an id_token_hint
		// naming someone else both redirect to the login page without clearing it, and a session
		// row that has stopped being valid keeps its cookie too. Reusing A's session for B's
		// ceremony bumps A's row with B's methods and stamps A's session identifier onto B's
		// authorization code, so B's grant is bound to a session B does not own and A's next
		// request resumes a session B's ceremony rewrote (#133).
		sessionBelongsToCeremony := authContext.OwnsSession(userSession)
		// authContext.AuthenticatedAt is set when the user actually enters credentials in
		// this ceremony, by the password handler and by the OTP handler. It is nil for SSO
		// session reuse (existing session flows through level1completed without hitting
		// either). Used only to decide whether to refresh the session's AuthTime below:
		// it is NOT proof of level 1, since OTP alone sets it (#129 decision 15).
		userReallyAuthenticated := authContext.AuthenticatedAt != nil && !authContext.AuthenticatedAt.IsZero()

		// The session this ceremony actually bound to, which is what the ACR below is taken
		// against. It is the bumped row on the reuse arm and the freshly created row on the
		// create arm, never the ambient one the browser happened to carry (#133).
		var boundSession *models.UserSession

		if hasValidUserSession && sessionBelongsToCeremony {
			// Bump session with current auth context's methods and target ACR level.
			// This handles step-up authentication: if the user had a level1 session but just
			// completed OTP for a level2 client, the session's AuthMethods and AcrLevel
			// will be upgraded to reflect the stronger authentication that was performed.
			bumpedSession, err := userSessionManager.BumpUserSession(r, sessionIdentifier, client.Id,
				authContext.AuthMethods, targetAcrLevel.String())
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			if userReallyAuthenticated {
				// User re-authenticated (prompt=login, step-up, etc.).
				// BumpUserSession preserves the old AuthTime (correct for SSO reuse
				// in handler_authorize.go), but here the user actually entered
				// credentials again, so refresh AuthTime to reflect that.
				utcNow := time.Now().UTC()
				bumpedSession.AuthTime = utcNow
				err = database.UpdateUserSession(nil, bumpedSession)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
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

			// The session has answered this ceremony's level 2 question, so record the OTP
			// configuration generation it answered against and stop owing a re-prompt for it.
			//
			// After the bump and after the AuthTime write above, both of which write the whole
			// row: otp_config_generation is tagged dont-update so neither carries it, and this
			// narrow write is the only thing that moves it.
			//
			// Two conditions, and both are load-bearing. A missing capture means the ceremony
			// never reached /auth/level2, which can only happen when the snapshot already
			// matched, so there is nothing to promote. The ACR gate is needed because the
			// password handler captures too: without it a prompt=login ceremony at a level 1
			// client would discharge a level 2 obligation it never addressed. It is the same
			// predicate /auth/level1completed uses to decide the step-up, so the two agree by
			// construction (#242 decision 3).
			if authContext.OtpConfigGeneration != nil && targetAcrLevel.IsHigherThan(enums.AcrLevel1) {
				err = database.PromoteUserSessionOtpConfigGeneration(nil, bumpedSession.Id,
					*authContext.OtpConfigGeneration)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}
				bumpedSession.OtpConfigGeneration = *authContext.OtpConfigGeneration
			}

			auditLogger.Log(constants.AuditBumpedUserSession, map[string]interface{}{
				"userId":   authContext.UserId,
				"clientId": client.Id,
			})

			boundSession = bumpedSession
		} else {
			// No session this ceremony may reuse: there is none, it is no longer valid, or it
			// belongs to somebody else. Only level 1 authentication performed in THIS ceremony
			// justifies creating one: without this gate StartNewUserSession below mints a
			// session from authContext.UserId with no proof anyone authenticated, so a
			// ceremony whose session was ended mid-flight silently recreates it (#129
			// decision 6).
			//
			// The predicate is deliberately "this ceremony did level 1" rather than "no
			// valid session". The second shape is legitimate: a session is deleted and the
			// user then starts a fresh ceremony and really does enter a password, which is
			// what TestSessionDeletedDuringAuthFlow_LoginSucceeds guards (#46). There is no
			// loop either, because the second pass through here has Level1AuthCompleted set
			// by handler_auth_pwd.
			//
			// It reads Level1AuthCompleted rather than userReallyAuthenticated above, and
			// that is the whole point of the field (#129 decision 15): AuthenticatedAt has
			// two writers, and a ceremony that stepped up to OTP by reusing a session
			// satisfies it without a password. handlePromptNone sets AuthenticatedAt too,
			// from the session it reused, and while it goes straight to /auth/issue and
			// never arrives here, it would be stopped rather than let through if it ever did.
			if !authContext.Level1AuthCompleted {
				authContext.AuthState = oauth.AuthStateRequiresLevel1
				err = authHelper.SaveAuthContext(w, r, authContext)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}
				http.Redirect(w, r, config.GetAuthServer().BaseURL+"/auth/level1", http.StatusFound)
				return
			}

			// The browser changed hands, so the session it was carrying is ended rather than
			// left behind. StartNewUserSession below does not do this: it sweeps sibling
			// sessions of the NEW user, so the previous user's row is never a candidate and
			// would survive orphaned, its refresh tokens still working and still bumping it
			// while nobody can reach it through this browser. Termination is the #129 path, so
			// the codes and refresh tokens that session authorized are revoked with it: they are
			// grants this browser holds, and this browser now belongs to someone else. Only
			// grants originating from this session are touched, since both sweeps key on the
			// session identifier, so the previous user's other devices are unaffected (#133).
			//
			// This runs for an invalid foreign session as well as a valid one. The browser
			// carries the cookie either way, and leaving a row that can never be resumed
			// achieves nothing while its offline grants keep working.
			//
			// It sits AFTER the level 1 gate above, deliberately: destroying somebody's session
			// must follow a real authentication in this ceremony, never a ceremony that merely
			// arrived here. A failure returns 500 with the browser still cookied to the old
			// session and no new session and no code minted, which is the fail-closed direction.
			if userSession != nil && !sessionBelongsToCeremony {
				terminationResult, err := TerminateUserSessionTx(database, userSession)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}

				// Three events, all of them after the commit and none before it, so nothing here
				// can attest to a termination that rolled back.
				//
				// This one comes first because it is the reason the other two happened. It
				// attests the handover and the ending, and deliberately not that a replacement
				// now exists: StartNewUserSession below can still fail and return a 500, and
				// started_new_user_session is what attests the replacement. Its absence after
				// this event is how an operator sees a handover that did not complete. Emitting
				// this one after the creation instead would leave that failure recorded as a
				// termination with no actor and no reason, which is the worse trade (#133).
				//
				// Both events below carry "" for loggedInUser rather than
				// authHelper.GetLoggedInSubject(r), which reads the cookie: at this instant the
				// cookie still names the user being terminated, so passing it would record the
				// party losing the session as the actor who ended it. The actor is this event's
				// userId, which is where an auditor reads it.
				auditLogger.Log(constants.AuditCrossUserSessionReplaced, map[string]interface{}{
					"userId":                    authContext.UserId,
					"previousUserId":            userSession.UserId,
					"previousSessionIdentifier": userSession.SessionIdentifier,
					"clientId":                  client.Id,
				})

				// deleted_user_session beside terminated_user_session, the pairing every caller of
				// TerminateUserSessionTx writes (#129 decision 9): the lifecycle record that a
				// session row is gone, next to the security record of what its grants authorized.
				// Emitting one without the other would make a browser handover the only
				// termination that never reaches a consumer watching the lifecycle stream, and it
				// would falsify the promise that ending a session always writes both.
				auditLogger.Log(constants.AuditDeletedUserSession, map[string]interface{}{
					"userSessionId": userSession.Id,
					"loggedInUser":  "",
				})
				LogTerminatedUserSession(auditLogger, userSession, "", terminationResult)
			}

			// start new session
			newSession, err := userSessionManager.StartNewUserSession(
				w, r, authContext.UserId, client.Id, authContext.AuthMethods, targetAcrLevel.String(),
				authContext.AuthStateGeneration, authContext.OtpConfigGeneration)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			// Use session's AuthTime so auth_time is consistent across SSO requests.
			// For legacy sessions with zero AuthTime, fall back to Started (consistent
			// with the prompt=none path in handler_authorize.go).
			if newSession.AuthTime.IsZero() {
				authContext.AuthenticatedAt = &newSession.Started
			} else {
				authContext.AuthenticatedAt = &newSession.AuthTime
			}

			auditLogger.Log(constants.AuditStartedNewUserSesson, map[string]interface{}{
				"userId":   authContext.UserId,
				"clientId": client.Id,
			})

			boundSession = newSession
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
			httpHelper.InternalServerError(w, r, err)
			return
		}

		user, err := database.GetUserById(nil, authContext.UserId)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if user == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("user not found")))
			return
		}

		if !user.Enabled {
			auditLogger.Log(constants.AuditUserDisabled, map[string]interface{}{
				"userId": user.Id,
			})
			// The clear goes FIRST. ClearAuthContext persists the deletion through a Set-Cookie
			// on w, and redirToClientWithError commits the response in every response mode, so
			// clearing afterwards leaves the header on a response already written and the
			// browser keeps an auth context it can replay (#141).
			err := authHelper.ClearAuthContext(w, r)
			if err != nil {
				// The clear failed, so Save wrote no cookie and the browser still holds the
				// auth context. The client is owed an error response regardless: its redirect
				// URI was validated upstream, so OIDC Core 1.0 3.1.2.2 with 3.1.2.6 applies,
				// and RFC 6749 4.1.2.1 mints server_error for exactly this condition (#141).
				slog.Error("failed to clear the auth context, answering the client with server_error",
					"error", err)
				err = redirToClientWithError(w, r, httpHelper, templateFS,
					redirectErrorFromAuthContext(authContext, client, "server_error", "Internal server error"))
				if err != nil {
					// Nowhere left to send the client, so the 500 is the last resort here.
					httpHelper.InternalServerError(w, r, err)
				}
				return
			}

			err = redirToClientWithError(w, r, httpHelper, templateFS,
				redirectErrorFromAuthContext(authContext, client, "access_denied", "The user account is disabled."))
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			return
		}

		// we need to check if consent is required

		// we'll first find out what is the effective scope,
		// by filtering out the scopes where the user is not authorized
		effectiveScope, err := permissionChecker.FilterOutScopesWhereUserIsNotAuthorized(authContext.Scope, user)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		// in the auth context replace the scope with the effective scope
		authContext.SetScope(effectiveScope)
		if len(authContext.Scope) == 0 {
			// The clear goes FIRST, for the same reason as the disabled-user refusal above: a
			// Set-Cookie written after redirToClientWithError has committed never reaches the
			// wire, so the browser keeps a replayable auth context (#141).
			err = authHelper.ClearAuthContext(w, r)
			if err != nil {
				// The clear failed, so Save wrote no cookie and the browser still holds the
				// auth context. The client is owed an error response regardless: its redirect
				// URI was validated upstream, so OIDC Core 1.0 3.1.2.2 with 3.1.2.6 applies,
				// and RFC 6749 4.1.2.1 mints server_error for exactly this condition (#141).
				slog.Error("failed to clear the auth context, answering the client with server_error",
					"error", err)
				err = redirToClientWithError(w, r, httpHelper, templateFS,
					redirectErrorFromAuthContext(authContext, client, "server_error", "Internal server error"))
				if err != nil {
					// Nowhere left to send the client, so the 500 is the last resort here.
					httpHelper.InternalServerError(w, r, err)
				}
				return
			}

			err = redirToClientWithError(w, r, httpHelper, templateFS,
				redirectErrorFromAuthContext(authContext, client,
					"access_denied", "The user is not authorized to access any of the requested scopes"))
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			return
		}

		// Handle prompt=consent: force consent screen regardless of existing consent or client settings
		if authContext.HasPromptValue("consent") {
			authContext.AuthState = oauth.AuthStateRequiresConsent
			err = authHelper.SaveAuthContext(w, r, authContext)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, config.GetAuthServer().BaseURL+"/auth/consent", http.StatusFound)
			return
		}

		// we must redirect to consent if the client requires it or if there's an offline_access scope
		if client.ConsentRequired || authContext.HasScope(oidc.OfflineAccessScope) {
			authContext.AuthState = oauth.AuthStateRequiresConsent

			err = authHelper.SaveAuthContext(w, r, authContext)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, config.GetAuthServer().BaseURL+"/auth/consent", http.StatusFound)
			return
		}

		// if there's no need for consent, we're ready to issue the code
		authContext.AuthState = oauth.AuthStateReadyToIssueCode
		err = authHelper.SaveAuthContext(w, r, authContext)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		http.Redirect(w, r, config.GetAuthServer().BaseURL+"/auth/issue", http.StatusFound)
	}
}
