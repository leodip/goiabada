package handlers

import (
	"context"
	"net/http"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/authflow"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/turnstile"
	"github.com/leodip/goiabada/core/httpmw"
	"github.com/leodip/goiabada/core/i18n"
)

// ChallengeVerifier checks the Turnstile token a form's submission carries, under the secret key
// the settings store, and counts the check. *turnstile.Verifier satisfies it.
type ChallengeVerifier interface {
	Check(ctx context.Context, settings *record.Settings, form turnstile.Form, token string) turnstile.Outcome
}

// RequirePasswordChallenge is the Turnstile challenge on POST /auth/pwd, mounted ahead of the
// sign-in form's rate limiter (#642 decision 5). With the challenge off it passes every request on
// untouched. With it on, a submission whose token the verifier refuses, or that carries none, is
// answered with the form again, beside the challenge's message and with the address typed, before
// any tier of the limiter counts it and before any password is compared. A pass, and every way the
// check fails open, go on to the limiter and the handler exactly as with the challenge off.
//
// The ceremony boundary runs first, so a submission naming a ceremony the browser no longer holds
// still gets the "no longer active" page and is never checked (#79). The token is read from the
// body alone, as every ceremony form marker is.
func RequirePasswordChallenge(boundary *CeremonyBoundary, pageRenderer PageRenderer,
	prompt *authflow.PasswordPrompt, verifier ChallengeVerifier) func(http.Handler) http.Handler {

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if settings, ok := reqctx.SettingsFrom(r.Context()); !ok || !settings.TurnstileEnabled {
				next.ServeHTTP(w, r)
				return
			}

			settings, authContext, ok := boundary.beginStep(w, r, ceremony.AuthStateLevel1Password)
			if !ok {
				return
			}

			outcome := verifier.Check(r.Context(), settings, turnstile.FormLogin, r.PostFormValue(turnstile.ResponseField))
			if !outcome.Refuses() {
				next.ServeHTTP(w, r)
				return
			}

			displayInfo, err := prompt.Run(r.Context(), authContext)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
				return
			}
			// Normalized as the handler normalizes it, so the address shown again is the one a
			// refusal by the password check would show.
			email := strings.ToLower(strings.TrimSpace(r.PostFormValue("email")))
			renderPasswordForm(w, r, pageRenderer, settings, authContext, displayInfo,
				i18n.NewLocalizedError(i18n.ErrCodeChallengeFailed, nil), "", email)
		})
	}
}

// bindTurnstileWidget puts the Turnstile widget on a form's render while the challenge is on: the
// site key its template renders the widget with, and Cloudflare's script admitted to this
// response's script-src (#642 decision 9). With the challenge off it does nothing, and the page is
// sent today's policy.
func bindTurnstileWidget(w http.ResponseWriter, settings *record.Settings, bind map[string]interface{}) {
	if !settings.TurnstileEnabled {
		return
	}
	bind["turnstileSiteKey"] = settings.TurnstileSiteKey
	bind["turnstileScriptURL"] = turnstile.ScriptURL
	httpmw.SetContentSecurityPolicy(w.Header(), turnstile.ScriptOrigin)
}
