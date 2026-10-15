package handlers

import (
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/authflow"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
)

// HandleAuthLevel2Get is GET /auth/level2, which accepts requires_level_2 and runs
// authflow.Level2Selection, then sends the browser to /auth/otp or, for a level2_optional ceremony
// whose user has no authenticator, to /auth/completed.
func HandleAuthLevel2Get(
	boundary *CeremonyBoundary,
	pageRenderer PageRenderer,
	ceremonyStore CeremonyStore,
	level2Selection *authflow.Level2Selection,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, authContext, ok := boundary.beginStep(w, r, ceremony.AuthStateRequiresLevel2)
		if !ok {
			return
		}

		result, err := level2Selection.Run(r.Context(), newBrowserSession(w, r, ceremonyStore), authContext)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
		boundary.redirectAfterSave(w, r, authContext, result.NextStep, result.SaveErr)
	}
}
