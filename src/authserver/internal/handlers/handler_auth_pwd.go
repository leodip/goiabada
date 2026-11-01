package handlers

import (
	"net/http"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/authflow"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/i18n"
)

// HandleAuthPwdGet is GET /auth/pwd, which accepts level1_password and renders the password form
// with the client block authflow.PasswordPrompt returns.
func HandleAuthPwdGet(
	boundary *CeremonyBoundary,
	pageRenderer PageRenderer,
	prompt *authflow.PasswordPrompt,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		settings, authContext, ok := boundary.beginStep(w, r, ceremony.AuthStateLevel1Password)
		if !ok {
			return
		}

		displayInfo, err := prompt.Run(r.Context(), authContext)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}

		renderPasswordForm(w, r, pageRenderer, settings, authContext, displayInfo, nil, "", "")
	}
}

// HandleAuthPwdPost is POST /auth/pwd, which accepts level1_password. It reads the form, refuses a
// missing address or password itself, and runs authflow.PasswordSubmission on the rest, then answers
// what it did: the form again beside a refusal, with the client block authflow.PasswordPrompt loads
// for it, or the redirect to /auth/level1completed.
//
// The boundary refuses a submission naming another ceremony before the state gate and before the
// credentials are read, so a login form left open in another tab gets the "no longer active" page
// and cannot authenticate anybody for anything (#79).
func HandleAuthPwdPost(
	boundary *CeremonyBoundary,
	pageRenderer PageRenderer,
	ceremonyStore CeremonyStore,
	credentialFailures CredentialFailureRecorder,
	prompt *authflow.PasswordPrompt,
	submission *authflow.PasswordSubmission,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		settings, authContext, ok := boundary.beginStep(w, r, ceremony.AuthStateLevel1Password)
		if !ok {
			return
		}

		// Lowercased and trimmed exactly as the rate limiter's account key is, and as every write
		// stores an address: the limiter and the account it protects must agree on which account a
		// request is, and mysql and mssql compare email case-insensitively while postgres and sqlite
		// do not (#219).
		email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))

		// The body alone: a credential in the request target reaches the browser's history, the
		// Referer and every proxy's access log (#202).
		password := r.PostFormValue("password")

		// renderRefusal reads r when it is called, so a refusal after the password was verified is
		// worded in the page language the user switched r to. It loads the client block then and only then:
		// an accepted submission redirects, and has no form to show it in. A failed read, or a client
		// not found, answers 500, as it does on the GET. field names the one field the refusal is
		// about, by its form name, and is empty for a refusal of the pair.
		renderRefusal := func(code, field string) {
			displayInfo, err := prompt.Run(r.Context(), authContext)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
				return
			}
			renderPasswordForm(w, r, pageRenderer, settings, authContext, displayInfo,
				i18n.NewLocalizedError(code, nil), field, email)
		}

		// Refused before any lookup, and never charged to the rate limiter: a form that verifies
		// nothing must not spend an account's failure budget (#219). A space can be part of a
		// password, so only one made of nothing else counts as missing.
		if len(email) == 0 {
			renderRefusal(i18n.ErrCodeLoginEmailRequired, "email")
			return
		}
		if len(strings.TrimSpace(password)) == 0 {
			renderRefusal(i18n.ErrCodeLoginPasswordRequired, "password")
			return
		}

		result, err := submission.Run(r.Context(),
			newCredentialCheckingBrowserSession(w, r, ceremonyStore, credentialFailures),
			authContext, email, password)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}

		if result.Answer == authflow.PasswordRefused {
			renderRefusal(i18n.ErrCodeLoginAuthFailed, "")
			return
		}

		// The password is verified, so the user's page language discloses nothing any more. It wins
		// over the browser session's user the page-language middleware applied, being the person
		// signing in now; on Automatic the page follows the language the request asks for, not the
		// session user's choice (#631 decisions 2 and 5).
		r = r.WithContext(i18n.WithPageLanguage(r.Context(), result.UserPageLanguage))

		if result.Answer == authflow.PasswordAccountDisabled {
			renderRefusal(i18n.ErrCodeLoginAccountDisabled, "")
			return
		}
		boundary.redirectAfterSave(w, r, authContext, result.NextStep, result.SaveErr)
	}
}

// renderPasswordForm renders the password form for the ceremony, with a refusal, the field it is
// about, and the address the user typed when it is shown again. The form names its ceremony, so the
// boundary reads the submission as that ceremony's, and refuses it once the browser no longer holds
// it (#79, #246).
func renderPasswordForm(w http.ResponseWriter, r *http.Request, pageRenderer PageRenderer,
	settings *record.Settings, authContext *ceremony.AuthContext, displayInfo *authflow.ClientDisplayInfo,
	refusal *i18n.LocalizedError, errorField, email string) {

	bind := map[string]interface{}{
		"error":       nil,
		"ceremonyId":  authContext.CeremonyId,
		"smtpEnabled": settings.SMTPEnabled,
		// The Register link goes to a page that answers not-found unless registration is available,
		// so the form offers it only then (#526 decision 2).
		"registrationAvailable":   settings.IsSelfRegistrationAvailable(),
		"layoutShowClientSection": displayInfo.ShowSection,
		"layoutClientName":        displayInfo.ClientName,
		"layoutHasClientLogo":     displayInfo.HasLogo,
		"layoutClientLogoUrl":     displayInfo.LogoURL,
		"layoutClientDescription": displayInfo.Description,
		"layoutClientWebsiteUrl":  displayInfo.WebsiteURL,
	}
	if refusal != nil {
		bind["error"] = refusal.Localize(r.Context())
		bind["errorField"] = errorField
		bind["email"] = email
	}

	if err := pageRenderer.RenderTemplate(w, r, "/layouts/auth_layout.html", "/auth_pwd.html", bind); err != nil {
		pageRenderer.InternalServerError(w, r, err)
	}
}
