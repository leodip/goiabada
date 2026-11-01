package accounthandlers

import (
	"net/http"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/turnstile"
	"github.com/leodip/goiabada/core/i18n"
)

// RequireForgotPasswordChallenge is the Turnstile challenge on POST /forgot-password, mounted after
// ForgotPasswordRequiresEmail and ahead of the form's rate limiter (#642 decision 5). With the
// challenge off it passes every request on untouched. With it on, a submission whose token the
// verifier refuses, or that carries none, is answered with the form again, beside the challenge's
// message and with the address as typed, before any tier of the limiter counts it and before the
// address is looked up. A pass, and every way the check fails open, go on as with the challenge off.
func RequireForgotPasswordChallenge(pageRenderer PageRenderer, verifier ChallengeVerifier) func(http.Handler) http.Handler {
	return requireChallenge(turnstile.FormForgotPassword, verifier,
		func(w http.ResponseWriter, r *http.Request, settings *record.Settings, refusal string) {
			// As typed, as the handler draws back an address it refuses. No field is marked: the
			// refusal is about the widget, not the address.
			renderForgotPasswordForm(w, r, pageRenderer, settings, r.PostFormValue("email"), refusal, "")
		})
}

// RequireRegistrationChallenge is the Turnstile challenge on POST /account/register, mounted after
// RefuseUnavailableRegistration and ahead of the form's rate limiter, as
// RequireForgotPasswordChallenge is on its form. The redrawn form keeps the address normalized as
// the handler's own refusals keep it, the sign-in the visitor came from, and the legal documents
// that sign-in's app links on the form.
func RequireRegistrationChallenge(pageRenderer PageRenderer, ceremonies registrationCeremonies,
	legalDocuments registrationLegalDocuments, verifier ChallengeVerifier) func(http.Handler) http.Handler {
	return requireChallenge(turnstile.FormRegister, verifier,
		func(w http.ResponseWriter, r *http.Request, settings *record.Settings, refusal string) {
			// No field is marked: the refusal is about the widget, and the password fields come
			// back empty, so focus goes where typing starts again.
			email := strings.TrimSpace(strings.ToLower(r.PostFormValue("email")))
			renderRegisterForm(w, r, pageRenderer, ceremonies, legalDocuments, settings, email, refusal, "")
		})
}

// requireChallenge checks the token of a submission of form while the challenge is on, read from
// the body alone, as every credential and form marker is, and has refuse redraw the form beside the
// challenge's message when the verifier refuses it or it carries none.
func requireChallenge(form turnstile.Form, verifier ChallengeVerifier,
	refuse func(w http.ResponseWriter, r *http.Request, settings *record.Settings, refusal string)) func(http.Handler) http.Handler {

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			settings, ok := reqctx.SettingsFrom(r.Context())
			if !ok || !settings.TurnstileEnabled {
				next.ServeHTTP(w, r)
				return
			}

			outcome := verifier.Check(r.Context(), settings, form, r.PostFormValue(turnstile.ResponseField))
			if !outcome.Refuses() {
				next.ServeHTTP(w, r)
				return
			}

			// i18n surface: A — browser-flow form rerender.
			refuse(w, r, settings, i18n.NewLocalizedError(i18n.ErrCodeChallengeFailed, nil).Localize(r.Context()))
		})
	}
}
