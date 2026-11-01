package handlers

import (
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/authflow"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
)

// HandleLegalAcceptanceGet is GET /auth/legal-acceptance, which accepts requires_legal_acceptance
// and runs authflow.LegalAcceptance.Prompt, then renders the acceptance step it returns, or sends
// the browser on when nothing is owed any more (#622).
func HandleLegalAcceptanceGet(
	boundary *CeremonyBoundary,
	responder *ClientErrorResponder,
	pageRenderer PageRenderer,
	ceremonyStore CeremonyStore,
	step *authflow.LegalAcceptance,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, authContext, ok := boundary.beginStep(w, r, ceremony.AuthStateRequiresLegalAcceptance)
		if !ok {
			return
		}

		result, err := step.Prompt(r.Context(), newBrowserSession(w, r, ceremonyStore), authContext)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
		answerLegalAcceptance(w, r, boundary, responder, pageRenderer, authContext, result)
	}
}

// HandleLegalAcceptancePost is POST /auth/legal-acceptance, which accepts requires_legal_acceptance
// and runs authflow.LegalAcceptance.Submit, then answers what it did: the step again, access_denied
// to the client for a decline, or the redirect to the next step once the documents are accepted.
//
// The boundary refuses a submission naming another ceremony before the state gate and before the
// submission is read, so a form left open in another tab cannot accept or decline for the
// ceremony that is current.
func HandleLegalAcceptancePost(
	boundary *CeremonyBoundary,
	responder *ClientErrorResponder,
	pageRenderer PageRenderer,
	ceremonyStore CeremonyStore,
	step *authflow.LegalAcceptance,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, authContext, ok := boundary.beginStep(w, r, ceremony.AuthStateRequiresLegalAcceptance)
		if !ok {
			return
		}

		// r.PostForm, the body alone, as the consent step reads its own: a crafted query string is
		// no part of the submission.
		_ = r.ParseForm()
		result, err := step.Submit(r.Context(), newBrowserSession(w, r, ceremonyStore), authContext, r.PostForm)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
		answerLegalAcceptance(w, r, boundary, responder, pageRenderer, authContext, result)
	}
}

// answerLegalAcceptance answers the step's result: the client's error, the redirect to the next
// step, or the step's page.
func answerLegalAcceptance(w http.ResponseWriter, r *http.Request, boundary *CeremonyBoundary,
	responder *ClientErrorResponder, pageRenderer PageRenderer, authContext *ceremony.AuthContext,
	result authflow.LegalAcceptanceResult) {

	switch {
	case result.ClientError != nil:
		answerClientAfterStepClear(w, r, boundary, responder,
			redirectErrorFromAuthContext(authContext, result.ClientError.Client,
				result.ClientError.Code, result.ClientError.Description),
			result.ClearErr)
	case result.Screen == nil:
		boundary.redirectAfterSave(w, r, authContext, result.NextStep, result.SaveErr)
	default:
		bind := map[string]interface{}{
			"clientName": result.Screen.ClientName,
			"documents":  result.Screen.Documents,
			"unticked":   result.Screen.Unticked,
			"changed":    result.Screen.Changed,
			// The form names the ceremony that rendered it, and the boundary refuses a submission
			// naming any other.
			"ceremonyId": authContext.CeremonyId,
		}
		if err := pageRenderer.RenderTemplate(w, r, "/layouts/auth_layout.html", "/legal_acceptance.html", bind); err != nil {
			pageRenderer.InternalServerError(w, r, err)
		}
	}
}
