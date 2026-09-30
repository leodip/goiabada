package handlers

import (
	"context"
	"database/sql"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/errs"
)

// authLevel2Database is what the level 2 hop needs: the client and the user whose OTP enrolment
// decides the path.
type authLevel2Database interface {
	GetClientByClientIdentifier(ctx context.Context, tx *sql.Tx, clientIdentifier string) (*models.Client, error)
	GetUserById(ctx context.Context, tx *sql.Tx, userId int64) (*models.User, error)
}

func HandleAuthLevel2Get(
	pageRenderer PageRenderer,
	ceremonyStore CeremonyStore,
	database authLevel2Database,
	auditLogger AuditLogger,
	baseURL string,
	adminConsoleBaseURL string,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		authContext, ok := loadAuthContext(pageRenderer, ceremonyStore, auditLogger, w, r, adminConsoleBaseURL)
		if !ok {
			return
		}

		if !requireAuthState(pageRenderer, w, r, authContext, ceremony.AuthStateRequiresLevel2) {
			return
		}

		// here we'll select what type of level2 auth we'll use (otp, email_code, sms_code, magic_link)
		// today we only support otp, other types will be added in the future

		client, err := database.GetClientByClientIdentifier(r.Context(), nil, authContext.ClientId)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
		if client == nil {
			pageRenderer.InternalServerError(w, r, errs.Errorf("client %v not found", authContext.ClientId))
			return
		}

		user, err := database.GetUserById(r.Context(), nil, authContext.UserId)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
		// GetUserById answers (nil, nil) for a row that is not there, so a user deleted
		// mid-ceremony reaches the dereference below. Byte-identical to the six sibling
		// ceremony handlers that already check this (HandleAuthOtpGet, HandleAuthOtpPost,
		// HandleConsentGet, HandleConsentPost, HandleAuthCompletedGet and
		// handleImplicitFlow): consistency is the point rather than a side benefit, because
		// "every handler nil-checks except this one" is the kind of gap that regresses
		// (#242 decision 5).
		if user == nil {
			pageRenderer.InternalServerError(w, r, errs.New("user not found"))
			return
		}

		// Capture the user's OTP configuration generation, before the switch so that every
		// arm below carries it: the level2_optional OTP prompt, the level2_optional skip for
		// a user with no authenticator, and level2_mandatory. **The skip has to count.** A
		// level2_optional ceremony for a user who has removed their authenticator is
		// legitimately answered by skipping OTP, and if that did not promote, every session
		// of that user would stay permanently behind and handlePromptNone would answer
		// interaction_required for the rest of each session's life.
		//
		// Nothing is written here. The value rides on the auth context and is promoted once,
		// at /auth/completed, so a ceremony abandoned at the OTP form discharges nothing
		// (#242 decision 3).
		otpConfigGeneration := user.OtpConfigGeneration
		authContext.OtpConfigGeneration = &otpConfigGeneration

		nextState, nextPath, err := decideLevel2Arm(authContext.GetTargetAcrLevel(client.DefaultAcrLevel), user.OTPEnabled)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}

		authContext.AuthState = nextState
		err = ceremonyStore.SaveAuthContext(w, r, authContext)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
		//nolint:gosec // G710: nextPath is one of decideLevel2Arm's two constant routes, under the configured base URL
		http.Redirect(w, r, ceremonyStepURL(baseURL, nextPath, authContext), http.StatusFound)
	}
}

// decideLevel2Arm is /auth/level2's choice of second factor, from the ceremony's target and
// whether the user has an authenticator: the state the ceremony moves to and the route it goes to.
// Today there is one second factor, OTP.
//
//   - level2_optional asks for OTP when the user has it enabled, and otherwise skips it, which is
//     the one path that bypasses /auth/otp entirely.
//   - level2_mandatory always asks; a user with no authenticator enrols at /auth/otp.
//   - Any other target never reaches this hop, since /auth/level1completed sends only a target above
//     level 1 here, and is answered with an error.
func decideLevel2Arm(target models.AcrLevel, userHasOTP bool) (ceremony.AuthState, string, error) {
	switch target {
	case models.AcrLevel2Optional:
		if userHasOTP {
			return ceremony.AuthStateLevel2OTP, "/auth/otp", nil
		}
		return ceremony.AuthStateAuthenticationCompleted, "/auth/completed", nil
	case models.AcrLevel2Mandatory:
		return ceremony.AuthStateLevel2OTP, "/auth/otp", nil
	default:
		return "", "", errs.New("invalid targetAcrLevel: " + target.String())
	}
}
