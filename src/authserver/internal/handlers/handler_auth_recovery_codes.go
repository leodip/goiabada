package handlers

import (
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/authflow"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
)

// HandleAuthRecoveryCodesGet is GET /auth/recovery-codes, which accepts level2_recovery_codes and
// renders the page authflow.RecoveryCodesPrompt prepared: the set of recovery codes the
// authenticator set up during this sign-in came with, the first time, and the page saying they were
// already shown on every render after it. Both carry the Continue form (#257 decision 14).
//
// The page is drawn only once the save taking the set off the ceremony has landed, so a set is
// shown at most once; a save that failed is answered as any step's is.
func HandleAuthRecoveryCodesGet(
	boundary *CeremonyBoundary,
	pageRenderer PageRenderer,
	ceremonyStore CeremonyStore,
	prompt *authflow.RecoveryCodesPrompt,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		_, authContext, ok := boundary.beginStep(w, r, ceremony.AuthStateLevel2RecoveryCodes)
		if !ok {
			return
		}

		result, err := prompt.Run(r.Context(), newBrowserSession(w, r, ceremonyStore), authContext)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
		if result.SaveErr != nil {
			boundary.answerStepSaveFailure(w, r, result.SaveErr)
			return
		}

		bind := otpFormBind(authContext, result.Display, nil)
		bind["recoveryCodes"] = result.RecoveryCodes
		if err := pageRenderer.RenderTemplate(w, r, "/layouts/auth_layout.html", "/auth_recovery_codes.html", bind); err != nil {
			pageRenderer.InternalServerError(w, r, err)
		}
	}
}

// HandleAuthRecoveryCodesPost is POST /auth/recovery-codes, which accepts level2_recovery_codes: the
// page's Continue. It runs authflow.ContinueAfterRecoveryCodes and answers 303 to /auth/completed.
// It reads no credential, so it is behind no limiter.
func HandleAuthRecoveryCodesPost(
	boundary *CeremonyBoundary,
	ceremonyStore CeremonyStore,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		_, authContext, ok := boundary.beginStep(w, r, ceremony.AuthStateLevel2RecoveryCodes)
		if !ok {
			return
		}

		result := authflow.ContinueAfterRecoveryCodes(newBrowserSession(w, r, ceremonyStore), authContext)
		boundary.redirectAfterSave(w, r, authContext, result.NextStep, result.SaveErr)
	}
}
