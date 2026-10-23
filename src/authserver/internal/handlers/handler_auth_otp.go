package handlers

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/authflow"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/otp"
	"github.com/leodip/goiabada/core/i18n"
)

// HandleAuthOtpGet is GET /auth/otp, which accepts level2_otp and renders the form
// authflow.OTPPrompt prepared: the code form for a user with an authenticator, the enrolment form,
// with its QR code and secret, for one without.
func HandleAuthOtpGet(
	boundary *CeremonyBoundary,
	pageRenderer PageRenderer,
	ceremonyStore CeremonyStore,
	prompt *authflow.OTPPrompt,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		settings, authContext, ok := boundary.beginStep(w, r, ceremony.AuthStateLevel2OTP)
		if !ok {
			return
		}

		result, err := prompt.Run(r.Context(), newBrowserSession(w, r, ceremonyStore), authContext, settings.AppName)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
		if result.SaveErr != nil {
			boundary.answerStepSaveFailure(w, r, result.SaveErr)
			return
		}

		bind := otpFormBind(authContext, result.Display, nil)
		template := "/auth_otp.html"
		if result.Form == authflow.OTPEnrolmentForm {
			template = "/auth_otp_enrollment.html"
			bind["base64Image"] = result.QRCodeImage
			bind["secretKey"] = result.EnrolmentSecret
		}

		if err := pageRenderer.RenderTemplate(w, r, "/layouts/auth_layout.html", template, bind); err != nil {
			pageRenderer.InternalServerError(w, r, err)
		}
	}
}

// HandleAuthOtpPost is POST /auth/otp, which accepts level2_otp. It reads the code from the
// submitted body and runs authflow.OTPSubmission on it, then answers what it did: the form again
// beside a refusal, the lost-enrolment page, or the redirect to /auth/completed.
//
// The boundary refuses a submission naming another ceremony before the state gate and before the
// code is looked at, so an OTP form left open in another tab gets the "no longer active" page and
// spends no step of a code the current ceremony still needs (#79, #111 decision 3).
func HandleAuthOtpPost(
	boundary *CeremonyBoundary,
	pageRenderer PageRenderer,
	ceremonyStore CeremonyStore,
	credentialFailures CredentialFailureRecorder,
	submission *authflow.OTPSubmission,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		_, authContext, ok := boundary.beginStep(w, r, ceremony.AuthStateLevel2OTP)
		if !ok {
			return
		}

		// The body alone: a code in the request target reaches the browser's history, the Referer
		// and every proxy's access log (#202).
		code := r.PostFormValue("otp")

		result, err := submission.Run(r.Context(),
			newCredentialCheckingBrowserSession(w, r, ceremonyStore, credentialFailures), authContext, code)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}

		renderRefusal := func(errorCode string) {
			renderOTPFormAgain(w, r, pageRenderer, authContext, result,
				i18n.NewLocalizedError(errorCode, nil).Localize(r.Context()))
		}

		switch result.Answer {
		case authflow.OTPAccountDisabled:
			renderRefusal(i18n.ErrCodeOtpAccountDisabled)
		case authflow.OTPEnrolmentLost:
			answerLostEnrolment(w, r, boundary, pageRenderer, result.SaveErr)
		case authflow.OTPCodeMissing:
			renderRefusal(i18n.ErrCodeOtpCodeRequired)
		case authflow.OTPRefused:
			renderRefusal(i18n.ErrCodeOtpIncorrectCode)
		case authflow.OTPAccepted:
			boundary.redirectAfterSave(w, r, authContext, result.NextStep, result.SaveErr)
		}
	}
}

// otpFormBind is the data both OTP forms render with. The form names its ceremony, so the boundary
// reads the submission as that ceremony's, and refuses it once the browser no longer holds it (#79,
// #246).
func otpFormBind(authContext *ceremony.AuthContext, displayInfo *authflow.ClientDisplayInfo,
	message interface{}) map[string]interface{} {

	return map[string]interface{}{
		"error":                   message,
		"ceremonyId":              authContext.CeremonyId,
		"layoutShowClientSection": displayInfo.ShowSection,
		"layoutClientName":        displayInfo.ClientName,
		"layoutHasClientLogo":     displayInfo.HasLogo,
		"layoutClientLogoUrl":     displayInfo.LogoURL,
		"layoutClientDescription": displayInfo.Description,
		"layoutClientWebsiteUrl":  displayInfo.WebsiteURL,
	}
}

// renderOTPFormAgain renders the OTP form again beside a refusal: the enrolment form, its QR code
// drawn from the ceremony's enrolment key, when the ceremony holds one, and the code form otherwise.
// A refusal leaves the key on the ceremony as it was.
func renderOTPFormAgain(w http.ResponseWriter, r *http.Request, pageRenderer PageRenderer,
	authContext *ceremony.AuthContext, result authflow.OTPSubmissionResult, message string) {

	bind := otpFormBind(authContext, result.Display, message)
	template := "/auth_otp.html"
	if authContext.OTPKeyURL != "" {
		image, err := otp.RenderQRCodeImage(authContext.OTPKeyURL)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
		template = "/auth_otp_enrollment.html"
		bind["base64Image"] = image
		bind["secretKey"] = result.EnrolmentSecret
	}

	if err := pageRenderer.RenderTemplate(w, r, "/layouts/auth_layout.html", template, bind); err != nil {
		pageRenderer.InternalServerError(w, r, err)
	}
}

// answerLostEnrolment answers authflow.OTPEnrolmentLost, whose ceremony the operation has cleared
// (#471 decision 2). A clear that found the ceremony no longer held is answerCeremonyReplaced's: the
// browser has moved on from this sign-in for another reason than the authenticator change (#579).
// Otherwise
// the page says the account's two-factor settings changed, at 409, since the request conflicted with
// the account's current state (RFC 9110 section 15.5.10), in the visitor's language. Not the
// enrolment form again, whose QR code is for an authenticator that was never stored, and not the "no
// longer active" page, which says a later sign-in or sign-out ended this one. A clear that failed
// otherwise does not change the page: a replay of the context left behind meets the same refusal or
// a state gate.
func answerLostEnrolment(w http.ResponseWriter, r *http.Request, boundary *CeremonyBoundary,
	pageRenderer PageRenderer, clearErr error) {

	if errors.Is(clearErr, ceremony.ErrCeremonyReplaced) {
		boundary.answerCeremonyReplaced(w, r)
		return
	}
	if clearErr != nil {
		slog.ErrorContext(r.Context(), "unable to clear the auth context while ending a lost enrolment, rendering the page anyway",
			"error", clearErr)
	}

	bind := map[string]interface{}{
		"title":       i18n.T(r.Context(), "auth_error.otp_changed.title"),
		"error":       i18n.T(r.Context(), "auth_error.otp_changed.message"),
		"_httpStatus": http.StatusConflict,
	}
	if err := pageRenderer.RenderTemplate(w, r, "/layouts/no_menu_layout.html", "/auth_error.html", bind); err != nil {
		pageRenderer.InternalServerError(w, r, err)
	}
}
