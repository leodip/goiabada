package handlers

import (
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/authflow"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
)

// HandleAuthCompletedGet is GET /auth/completed, which accepts authentication_completed and runs
// authflow.Completion, then answers what it did: the redirect to /auth/level1 on a restart, or to
// /auth/consent or /auth/issue once the ceremony is bound to a session; an error to the client,
// access_denied or the hint's login_required; or the "no longer active" page for a bind a newer
// sign-in made stale (#538) or a ceremony the browser session no longer holds (#579).
//
// deviceCookie is the device cookie the per-request adapter reads the browser's device from and
// writes once the create arm has bound a new session to the browser session.
func HandleAuthCompletedGet(
	boundary *CeremonyBoundary,
	responder *ClientErrorResponder,
	pageRenderer PageRenderer,
	ceremonyStore CeremonyStore,
	deviceCookie *DeviceCookie,
	completion *authflow.Completion,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		settings, authContext, ok := boundary.beginStep(w, r, ceremony.AuthStateAuthenticationCompleted)
		if !ok {
			return
		}

		sessionIdentifier, _ := reqctx.SessionIdentifierFrom(r.Context())
		result, err := completion.Run(r.Context(),
			newSessionStartingBrowserSession(w, r, ceremonyStore, deviceCookie),
			settings, authContext, sessionIdentifier, middleware.ClientIP(r))
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}

		switch {
		case result.Stale:
			// The newer sign-in began with its own /auth/authorize, which replaced this ceremony, so
			// this one is answered as replaced and puts nothing back (#538). It is not restarted: a
			// restart verifies the password itself and would replace the session's authentication
			// (#537), asking an SSO ceremony for a password nobody requested.
			boundary.renderCeremonyNoLongerActive(w, r)
		case result.Replaced:
			boundary.answerCeremonyReplaced(w, r)
		case result.ClientError != nil:
			answerClientAfterStepClear(w, r, boundary, responder,
				redirectErrorFromAuthContext(authContext, result.ClientError.Client,
					result.ClientError.Code, result.ClientError.Description),
				result.ClearErr)
		default:
			boundary.redirectAfterSave(w, r, authContext, result.NextStep, result.SaveErr)
		}
	}
}
