package handlers

import (
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/authflow"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
)

// HandleAuthLevel1Get is GET /auth/level1, which accepts requires_level_1 and runs
// authflow.SelectLevel1Method, then sends the browser to the method it chose.
func HandleAuthLevel1Get(
	boundary *CeremonyBoundary,
	ceremonyStore CeremonyStore,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, authContext, ok := boundary.beginStep(w, r, ceremony.AuthStateRequiresLevel1)
		if !ok {
			return
		}

		result := authflow.SelectLevel1Method(newBrowserSession(w, r, ceremonyStore), authContext)
		boundary.redirectAfterSave(w, r, authContext, result.NextStep, result.SaveErr)
	}
}

// HandleAuthLevel1CompletedGet is GET /auth/level1completed, which accepts
// level1_password_completed and level1_existing_session and runs authflow.Level1Completion. It
// answers a parked error to the client, or sends the browser to /auth/level2 or /auth/completed.
func HandleAuthLevel1CompletedGet(
	boundary *CeremonyBoundary,
	responder *ClientErrorResponder,
	pageRenderer PageRenderer,
	ceremonyStore CeremonyStore,
	level1Completion *authflow.Level1Completion,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		settings, authContext, ok := boundary.beginStep(w, r,
			ceremony.AuthStateLevel1PasswordCompleted, ceremony.AuthStateLevel1ExistingSession)
		if !ok {
			return
		}

		sessionIdentifier, _ := reqctx.SessionIdentifierFrom(r.Context())
		result, err := level1Completion.Run(r.Context(), newBrowserSession(w, r, ceremonyStore), settings,
			authContext, sessionIdentifier)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}

		if result.DeferredError != nil {
			answerClientAfterStepClear(w, r, boundary, responder,
				redirectErrorFromAuthContext(authContext, result.DeferredError.Client,
					result.DeferredError.Code, result.DeferredError.Description),
				result.ClearErr)
			return
		}
		boundary.redirectAfterSave(w, r, authContext, result.NextStep, result.SaveErr)
	}
}
