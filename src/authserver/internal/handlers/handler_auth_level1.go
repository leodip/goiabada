package handlers

import (
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"slices"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/pkg/errors"
)

func HandleAuthLevel1Get(
	httpHelper HttpHelper,
	authHelper AuthHelper,
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

		requiredState := oauth.AuthStateRequiresLevel1
		if authContext.AuthState != requiredState {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("authContext.AuthState is not "+requiredState)))
			return
		}

		// here we'll select what type of level1 auth we'll use (pwd, pin, magic_link)
		// today we only support pwd, other types will be added in the future

		authContext.AuthState = oauth.AuthStateLevel1Password
		err = authHelper.SaveAuthContext(w, r, authContext)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		http.Redirect(w, r, config.GetAuthServer().BaseURL+"/auth/pwd", http.StatusFound)
	}
}

func HandleAuthLevel1CompletedGet(
	httpHelper HttpHelper,
	authHelper AuthHelper,
	userSessionManager UserSessionManager,
	database data.Database,
	templateFS fs.FS,
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

		requiredStates := []string{oauth.AuthStateLevel1PasswordCompleted, oauth.AuthStateLevel1ExistingSession}
		if !slices.Contains(requiredStates, authContext.AuthState) {
			errorMsg := fmt.Sprintf("authContext.AuthState '%s' does not match any required state", authContext.AuthState)
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New(errorMsg)))
			return
		}

		// An authorization error the endpoint refused to deliver to a logged-out browser is
		// delivered here, and this is the whole point of the deferral: RFC 9700 4.11.2 requires
		// that the server "MUST always authenticate the user first ... before redirecting the
		// user", and this is the first junction reached once level 1 credentials are verified.
		// Level 2 is about the ACR a client asked for in a token, and no token is issued on this
		// path, so waiting for it would drag a visitor through OTP for a request the server
		// already knows is invalid (#213 decision 2).
		//
		// After the state gate above, so a ceremony in an unexpected state still answers 500 as it
		// does today, and before this handler's own session lookup, because the ceremony ends
		// here: nothing is persisted, and since the user session row is created at /auth/completed
		// a visitor who logged in only to receive an error is left without an SSO session.
		//
		// Either state the gate admits is accepted. A parked error can only arrive on
		// AuthStateLevel1PasswordCompleted today, because the AuthStateLevel1ExistingSession
		// shortcut is reached only with a valid session and that request was answered at once, but
		// the delivery does not depend on which one it is.
		if authContext.DeferredErrorCode != "" {
			answerClientWithError(w, r, httpHelper, authHelper, templateFS,
				redirectErrorFromAuthContext(authContext,
					clientProvenance(database, authContext.ClientId),
					authContext.DeferredErrorCode, authContext.DeferredErrorDescription))
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

		// should we redirect to level 2 auth?
		shouldRedirectToLevel2 := false
		// The session only counts when it belongs to the user this ceremony authenticated. The
		// browser may still hold user A's session cookie while user B signs in, and the block below
		// would then decide B's step-up from A's ACR: an A session already at or above the target
		// sends B straight to /auth/completed with a password only, skipping the second factor a
		// level2 client asked for. A session belonging to anyone else is treated as no session, so
		// the target alone decides, and A's OTP configuration snapshot is left alone (#133).
		hasValidUserSession := userSessionManager.HasValidUserSession(r.Context(), userSession, authContext.ParseRequestedMaxAge()) && authContext.OwnsSession(userSession)

		if hasValidUserSession {
			// Parse the session's ACR level
			acrLevelFromSession, err := enums.AcrLevelFromString(userSession.AcrLevel)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			// Step-up required if target ACR is higher than session ACR.
			// Uses enums.AcrLevel.IsHigherThan() as the single source of truth.
			if targetAcrLevel.IsHigherThan(acrLevelFromSession) {
				shouldRedirectToLevel2 = true
			}

			// The user's authenticator has changed since this session last answered the level
			// 2 question, so ask it again. Both numbers are already in hand: UserSessionLoadUser
			// above populated userSession.User, so the comparison costs no query.
			//
			// **This block writes nothing, and that is the fix.** It used to clear a boolean
			// here and commit it, which meant a visitor who closed the browser at the OTP form
			// had already spent the re-prompt: the next ceremony found the flag clear and let
			// them through with a password. A comparison cannot be consumed by reading it, so
			// the obligation stands until /auth/completed records that a ceremony actually
			// answered it (#242 decision 1).
			//
			// != rather than <, so a snapshot somehow ahead of the counter re-prompts too. That
			// should not happen, and if it does the fail-closed answer is the one to give. It is
			// also what makes migration 000031's -1 seed work with no special case.
			if userSession.OtpConfigGeneration != userSession.User.OtpConfigGeneration &&
				targetAcrLevel.IsHigherThan(enums.AcrLevel1) {
				shouldRedirectToLevel2 = true
			}
		} else if targetAcrLevel.IsHigherThan(enums.AcrLevel1) {
			// No valid session and target requires level2
			shouldRedirectToLevel2 = true
		}

		if shouldRedirectToLevel2 {
			// We need to redirect to level 2
			authContext.AuthState = oauth.AuthStateRequiresLevel2
			err = authHelper.SaveAuthContext(w, r, authContext)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, config.GetAuthServer().BaseURL+"/auth/level2", http.StatusFound)
			return
		} else {
			// Auth is completed
			authContext.AuthState = oauth.AuthStateAuthenticationCompleted
			err = authHelper.SaveAuthContext(w, r, authContext)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, config.GetAuthServer().BaseURL+"/auth/completed", http.StatusFound)
			return
		}
	}
}
