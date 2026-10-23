package handlers

import (
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/authflow"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
)

// HandleConsentGet is GET /auth/consent, which accepts requires_consent and runs
// authflow.ConsentPrompt, then renders the consent screen it returns, or sends the browser to
// /auth/issue when the scope is already consented.
func HandleConsentGet(
	boundary *CeremonyBoundary,
	pageRenderer PageRenderer,
	ceremonyStore CeremonyStore,
	prompt *authflow.ConsentPrompt,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, authContext, ok := boundary.beginStep(w, r, ceremony.AuthStateRequiresConsent)
		if !ok {
			return
		}

		result, err := prompt.Run(r.Context(), newBrowserSession(w, r, ceremonyStore), authContext)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}

		if result.Screen == nil {
			boundary.redirectAfterSave(w, r, authContext, result.NextStep, result.SaveErr)
			return
		}

		screen := result.Screen
		bind := map[string]interface{}{
			"showClientSection":    screen.ShowClientSection,
			"clientName":           screen.ClientName,
			"clientNameUnverified": screen.ClientNameUnverified,
			"clientDescription":    screen.ClientDescription,
			"clientLogoUrl":        screen.LogoURL,
			"clientWebsiteUrl":     screen.WebsiteURL,
			"hasLogo":              screen.HasLogo,
			"scopes":               screen.Scopes,
			// The form names the ceremony that rendered it, and the boundary refuses a submission
			// naming any other: the checkbox indices mean something only against this ceremony's
			// scope list (#79).
			"ceremonyId": authContext.CeremonyId,
		}

		err = pageRenderer.RenderTemplate(w, r, "/layouts/auth_layout.html", "/consent.html", bind)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
		}
	}
}

// HandleConsentPost is POST /auth/consent, which accepts requires_consent and runs
// authflow.ConsentSubmission, then answers what it did: access_denied to the client for a refused
// submission, or the redirect to /auth/issue for a recorded consent.
//
// The boundary refuses a submission naming another ceremony before the state gate and before the
// submission is read, so a form left open in another tab gets the "no longer active" page, and its
// cancel cannot clear the ceremony that is current (#79).
func HandleConsentPost(
	boundary *CeremonyBoundary,
	responder *ClientErrorResponder,
	pageRenderer PageRenderer,
	ceremonyStore CeremonyStore,
	submission *authflow.ConsentSubmission,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, authContext, ok := boundary.beginStep(w, r, ceremony.AuthStateRequiresConsent)
		if !ok {
			return
		}

		// r.PostForm, the body alone: r.Form would merge the URL query in (#79). The store's read of
		// the ceremony the body names parsed it already, and parsing it here keeps the submission
		// from depending on that. Its error is not read, as r.PostFormValue reads none: a body that
		// would not parse named no ceremony and was refused above, and a malformed query is no part
		// of the submission.
		_ = r.ParseForm()
		result, err := submission.Run(r.Context(), newBrowserSession(w, r, ceremonyStore), authContext, r.PostForm)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}

		if result.ClientError != nil {
			answerClientAfterStepClear(w, r, boundary, responder,
				redirectErrorFromAuthContext(authContext, result.ClientError.Client,
					result.ClientError.Code, result.ClientError.Description),
				result.ClearErr)
			return
		}
		boundary.redirectAfterSave(w, r, authContext, result.NextStep, result.SaveErr)
	}
}
