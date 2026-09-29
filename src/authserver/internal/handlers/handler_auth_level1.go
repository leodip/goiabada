package handlers

import (
	"context"
	"database/sql"
	"io/fs"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/errs"
)

func HandleAuthLevel1Get(
	pageRenderer PageRenderer,
	ceremonyStore CeremonyStore,
	baseURL string,
	adminConsoleBaseURL string,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		authContext, ok := loadAuthContext(pageRenderer, ceremonyStore, w, r, adminConsoleBaseURL)
		if !ok {
			return
		}

		if !requireAuthState(pageRenderer, w, r, authContext, ceremony.AuthStateRequiresLevel1) {
			return
		}

		// here we'll select what type of level1 auth we'll use (pwd, pin, magic_link)
		// today we only support pwd, other types will be added in the future

		authContext.AuthState = ceremony.AuthStateLevel1Password
		err := ceremonyStore.SaveAuthContext(w, r, authContext)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
		http.Redirect(w, r, baseURL+"/auth/pwd", http.StatusFound)
	}
}

// authLevel1Database is what the level 1 hops need: the client and the session behind the step-up
// decision.
//
// It embeds the authorize port because a deferred error is delivered through
// answerClientWithError.
type authLevel1Database interface {
	authorizeDatabase

	GetClientByClientIdentifier(ctx context.Context, tx *sql.Tx, clientIdentifier string) (*models.Client, error)
	GetUserSessionBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (*models.UserSession, error)
	UserSessionLoadUser(ctx context.Context, tx *sql.Tx, userSession *models.UserSession) error
}

func HandleAuthLevel1CompletedGet(
	pageRenderer PageRenderer,
	ceremonyStore CeremonyStore,
	userSessionManager UserSessionManager,
	database authLevel1Database,
	templateFS fs.FS,
	baseURL string,
	adminConsoleBaseURL string,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		authContext, ok := loadAuthContext(pageRenderer, ceremonyStore, w, r, adminConsoleBaseURL)
		if !ok {
			return
		}

		if !requireAuthState(pageRenderer, w, r, authContext,
			ceremony.AuthStateLevel1PasswordCompleted, ceremony.AuthStateLevel1ExistingSession) {
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
			answerClientWithError(w, r, database, pageRenderer, ceremonyStore, templateFS,
				redirectErrorFromAuthContext(authContext,
					clientProvenance(r.Context(), database, authContext.ClientId),
					authContext.DeferredErrorCode, authContext.DeferredErrorDescription))
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

		// The session only counts when it belongs to the user this ceremony authenticated. The
		// browser may still hold user A's session cookie while user B signs in, and the step-up
		// would then be decided from A's ACR: an A session already at or above the target sends B
		// straight to /auth/completed with a password only, skipping the second factor a level2
		// client asked for. A session belonging to anyone else is treated as no session, so the
		// target alone decides, and A's OTP configuration snapshot is left alone (#133).
		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			pageRenderer.InternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}
		var reusableSession *models.UserSession
		if userSessionManager.HasValidUserSession(userSession,
			settings.UserSessionIdleTimeoutInSeconds, settings.UserSessionMaxLifetimeInSeconds,
			authContext.RequestedMaxAge()) && authContext.OwnsSession(userSession) {
			reusableSession = userSession
		}

		// UserSessionLoadUser above populated userSession.User, so the rule's OTP configuration
		// comparison costs no query.
		stepUp, err := ceremony.StepUpOwed(targetAcrLevel, reusableSession)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}

		if stepUp != ceremony.StepUpNone {
			// We need to redirect to level 2
			authContext.AuthState = ceremony.AuthStateRequiresLevel2
			err = ceremonyStore.SaveAuthContext(w, r, authContext)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, baseURL+"/auth/level2", http.StatusFound)
			return
		} else {
			// Auth is completed
			authContext.AuthState = ceremony.AuthStateAuthenticationCompleted
			err = ceremonyStore.SaveAuthContext(w, r, authContext)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, baseURL+"/auth/completed", http.StatusFound)
			return
		}
	}
}
